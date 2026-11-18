from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from . import __version__
from .adapters import collect
from .backup_proof import create_backup_proof
from .config import Config, load, validate, xdg_config
from .core import (
    Assessment,
    apply_deletions,
    assess,
    assess_category,
    create_verification_plan,
    load_verification_plan,
    new_audit_path,
    verify_saved_plan,
)
from .diagnostics import compatibility_payload
from .legacy_inventory import create_inventory, inventory_status
from .progress import ProgressDisplay
from .reconciliation import ReconciliationItem, reconcile


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="ingest-cleanup", description="Safely remove preserved ingest files only after fresh provenance verification.")
    value.add_argument("--version", action="version", version=f"ingest-cleanup {__version__}")
    value.add_argument("--config-file", type=Path, default=xdg_config())
    value.add_argument("--verbose", action="store_true")
    value.add_argument("--json", action="store_true", help="emit a versioned machine-readable result")
    value.add_argument("command", nargs="?", choices=("status", "verify", "show", "apply", "config", "help", "explain", "reconcile", "provenance-status", "compatibility", "backup-proof", "legacy-inventory"), default="status")
    value.add_argument("target", nargs="?", help="Incoming path, category name, or verification plan ID, depending on command")
    value.add_argument("--publication", type=Path, help="Published destination bound to backup proof")
    value.add_argument("--backup-object", type=Path, help="Exact source-byte object on independent storage")
    value.add_argument("--expected-uuid", help="Expected independent backup filesystem UUID")
    value.add_argument("--report", action="append", type=Path, default=[], help="Explicit legacy report path for legacy-inventory create")
    value.add_argument("--yes", action="store_true", help="Confirm the explicit legacy-inventory create operation")
    return value


def _progress(verbose: bool, expected_bytes: int | None = None, *, json_output: bool = False) -> ProgressDisplay:
    return ProgressDisplay(
        verbose=verbose,
        expected_bytes=expected_bytes,
        stream=sys.stderr if json_output else sys.stdout,
    )


def _assessment_payload(item: Assessment) -> dict[str, object]:
    return {
        "category": item.category,
        "source": str(item.source),
        "destination": str(item.destination) if item.destination else None,
        "state": item.state,
        "reason_code": item.reason_code,
        "reason": item.reason,
        "size": item.size,
        "evidence_identifier": item.evidence.report_id if item.evidence else item.evidence_identifier,
    }


def _results_payload(command: str, results: list[Assessment], rejected: list[object], categories: object) -> dict[str, object]:
    grouped = {category.name: Counter() for category in categories}
    for item in results:
        grouped.setdefault(item.category, Counter())[item.state] += 1
    return {
        "schema": "ingest-cleanup-output-v1",
        "command": command,
        "summary": {
            name: {"incoming": sum(counts.values()), **dict(sorted(counts.items()))}
            for name, counts in grouped.items()
        },
        "items": [_assessment_payload(item) for item in results],
        "rejected_reports": [
            {
                "path": str(item.path),
                "classification": _rejection_kind(item.reason),
                "reason": item.reason,
            }
            for item in rejected
        ],
    }


def _print(
    results: list[Assessment],
    rejected: list[object],
    verbose: bool,
    categories=None,
    *,
    apply_mode: bool = False,
) -> None:
    print("Ingest Cleanup\n\nScanning successful ingestion records...\n")
    grouped: dict[str, list[Assessment]] = defaultdict(list)
    for result in results: grouped[result.category].append(result)
    # Show every configured category: an empty Books root must not look like an
    # unsupported category.
    names = [item.name for item in categories] if categories is not None else list(grouped)
    adapters = {item.name: item.adapter for item in categories or []}
    for category in names:
        values = grouped.get(category, [])
        counts = Counter(value.state for value in values)
        print(category)
        print(f"  Incoming files: {len(values)}")
        print(f"  Candidate:      {counts['CANDIDATE']}")
        print(f"  Safe:           {counts['SAFE']}")
        print(f"  Backup needed:  {counts['BACKUP_REQUIRED']}")
        print(f"  Review:         {counts['REVIEW']}")
        print(f"  Provenance:     {counts['PROVENANCE']}")
        print(f"  Unknown:        {counts['UNKNOWN']}")
        if adapters.get(category) == "kavita":
            reconciliation = sum(
                value.reason_code == "AMBIGUOUS_MAPPING" for value in values
            )
            manual = sum(
                value.state in {"REVIEW", "UNKNOWN"}
                and value.reason_code != "AMBIGUOUS_MAPPING"
                for value in values
            )
            published = (
                counts["CANDIDATE"]
                + counts["SAFE"]
                + counts["BACKUP_REQUIRED"]
                + reconciliation
            )
            print("  Action summary:")
            print(f"    Published evidence:               {published}")
            print(f"    Safe to remove:                   {counts['SAFE']}")
            print(f"    Awaiting independent backup:      {counts['BACKUP_REQUIRED']}")
            print(f"    Awaiting publication reconciliation: {reconciliation}")
            print(f"    Defective/manual action:          {manual}")
            print(f"    Retained repair provenance:       {counts['PROVENANCE']}")
        if verbose:
            for value in values:
                mapping = f" -> {value.destination}" if value.destination else ""
                print(f"  {value.state} [{value.reason_code or 'UNCLASSIFIED'}]: {value.source}{mapping} — {value.reason}")
                if value.evidence_identifier:
                    print(f"    Evidence: {value.evidence_identifier}")
        else:
            reasons = Counter((value.state, value.reason) for value in values if value.state != "SAFE")
            for (state, reason), count in sorted(reasons.items()):
                code = next((value.reason_code for value in values if value.state == state and value.reason == reason), "UNCLASSIFIED")
                print(f"  {state} [{code}]: {count} — {reason}")
        print()
    if rejected:
        print(f"Ignored corrupt/unsafe reports: {len(rejected)}")
        if verbose:
            for item in rejected:
                print(f"  REPORT_REJECTED: {item.path} — {item.reason}")
        else:
            grouped_reports = Counter((_report_origin(item.path), item.reason) for item in rejected)
            for (origin, reason), count in sorted(
                grouped_reports.items(), key=lambda value: (value[0][0], value[0][1])
            ):
                print(f"  {count} [{_rejection_kind(reason)}] from {origin} — {reason}")
            print("  Use --verbose for the full rejected-report list.")
    missing = Counter(value.evidence.adapter if value.evidence else adapters.get(value.category, "unknown") for value in results if value.reason_code == "NO_ACCEPTED_REPORT")
    if missing:
        commands = {"video": "video-ingest", "music": "music-ingest", "kavita": "kavita-ingest", "unknown": "the authoritative producer"}
        print("Missing proof is resolved by replaying the authoritative producer; cleanup does not infer paths:")
        for adapter, count in sorted(missing.items()):
            print(f"  {count}: rerun `{commands[adapter]}`")
    backup_required = sum(value.state == "BACKUP_REQUIRED" for value in results)
    if backup_required:
        print(
            f"{backup_required} verified publication(s) remain in Incoming because no "
            "independent per-file backup proof is available. They are not deletion-ready."
        )
    reconciliation_items = [
        value for value in results if value.reason_code == "AMBIGUOUS_MAPPING"
    ]
    if reconciliation_items:
        print("Publication reconciliation is required before cleanup can select a mapping:")
        for value in reconciliation_items:
            print(f"  ingest-cleanup explain '{value.source}'")
    if not apply_mode:
        print("No files were deleted. Run `ingest-cleanup apply` to verify and review deletion.")


def _report_origin(path: Path) -> str:
    for name in ("video-ingest", "music-ingest", "kavita-ingest"):
        if name in path.parts:
            return name
    return str(path.parent)


def _rejection_kind(reason: str) -> str:
    lowered = reason.casefold()
    if "expecting" in lowered or "json" in lowered or "decode" in lowered:
        return "CORRUPT_REPORT"
    if "unsupported" in lowered or "legacy" in lowered:
        return "UNSUPPORTED_SCHEMA"
    if "not an approved" in lowered or "did not complete" in lowered or "incomplete" in lowered:
        return "INCOMPLETE_RUN"
    if "missing" in lowered or "does not exist" in lowered:
        return "MISSING_ENDPOINT"
    if "duplicate" in lowered:
        return "DUPLICATE_DISCOVERY"
    return "INVALID_PROVENANCE"


def _load(path: Path) -> Config:
    config = load(path); validate(config); return config


def _provenance_status(config: Config, *, emit: bool = True) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    if emit:
        print("Publication provenance adapters\n")
    for category in config.categories:
        if category.adapter == "disabled":
            state = "disabled"
        elif category.adapter == "kavita":
            root = config.kavita_state_root
            state = "ready" if root and root.is_dir() and not root.is_symlink() else "not configured"
        elif category.adapter == "video":
            state = "ready" if config.video_state_roots else "not configured"
        elif category.adapter == "music":
            state = "ready" if config.music_state_root else "not configured"
        else:
            state = "unsupported"
        values.append({"category": category.name, "adapter": category.adapter, "state": state})
        if emit:
            print(f"{category.name:<16} {category.adapter:<8} {state}")
    if emit:
        print("\nThis checks adapter configuration only; it does not assess any source as safe.")
    return values


def _explain(config: Config, path: Path, *, json_output: bool = False) -> int:
    candidate = path.expanduser()
    for category in config.categories:
        try:
            candidate.resolve(strict=False).relative_to(category.ingest_root.resolve(strict=True))
        except (OSError, ValueError):
            continue
        results, rejected = assess_category(config, category, hash_files=False)
        records, _ = collect(config, category)
        item = next((value for value in results if value.source == candidate), None)
        if item is None:
            payload = {"schema": "ingest-cleanup-explain-v1", "state": "UNKNOWN", "reason": "Source is not a regular supported Incoming file."}
            print(json.dumps(payload, indent=2) if json_output else "UNKNOWN\nSource is not a regular supported Incoming file.")
            return 0
        reason = item.reason
        if item.state == "UNKNOWN" and reason == "insufficient proof":
            reason = "No matching accepted publication report exists."
            if rejected:
                reason += f" {len(rejected)} report(s) were rejected as incomplete, malformed, or unsafe."
        mappings = [record for record in records if record.source == item.source]
        if json_output:
            print(json.dumps({
                "schema": "ingest-cleanup-explain-v1",
                **_assessment_payload(item),
                "reason": reason,
                "accepted_mappings": [
                    {"destination": str(record.destination), "report": str(record.report), "record": record.report_id}
                    for record in mappings
                ],
                "rejected_report_count": len(rejected),
            }, indent=2, sort_keys=True))
            return 0
        print(item.state)
        print(f"Category: {item.category}")
        print(f"Reason: {reason}")
        if item.evidence:
            print(f"Adapter: {item.evidence.adapter}")
            print(f"Report: {item.evidence.report}")
            print(f"Record: {item.evidence.report_id}")
            print(f"Destination: {item.evidence.destination}")
        if len(mappings) > 1:
            print("Accepted competing mappings:")
            for record in mappings:
                print(f"  {record.destination}\n    {record.report_id}")
        return 0
    payload = {"schema": "ingest-cleanup-explain-v1", "state": "UNKNOWN", "reason": "Path is outside configured Incoming roots."}
    print(json.dumps(payload, indent=2) if json_output else "UNKNOWN\nPath is outside configured Incoming roots.")
    return 2


def _reconciliation_payload(items: list[ReconciliationItem], rejected: list[object]) -> dict[str, object]:
    return {
        "schema": "ingest-cleanup-reconciliation-v1",
        "safety": "ADVISORY_ONLY",
        "items": [
            {
                "category": item.category,
                "source": str(item.source),
                "current_state": item.current_state,
                "reason_code": item.reason_code,
                "accepted_mappings": [
                    {
                        "classification": "ACCEPTED_PROVENANCE",
                        "destination": str(mapping.destination),
                        "report": str(mapping.report),
                        "record": mapping.report_id,
                    }
                    for mapping in item.accepted_mappings
                ],
                "plausible_matches": [
                    {
                        "classification": match.classification,
                        "destination": str(match.destination),
                        "score": match.score,
                        "name_similarity": match.name_similarity,
                        "size_equal": match.size_equal,
                        "extension_compatible": match.extension_compatible,
                    }
                    for match in item.plausible_matches
                ],
            }
            for item in items
        ],
        "rejected_report_count": len(rejected),
    }


def _print_reconciliation(items: list[ReconciliationItem], rejected: list[object]) -> None:
    ambiguous = sum(bool(item.accepted_mappings) for item in items)
    plausible = sum(bool(item.plausible_matches) for item in items)
    print("Read-only publication reconciliation")
    print(f"  Items needing reconciliation: {len(items)}")
    print(f"  Competing accepted mappings:  {ambiguous}")
    print(f"  Plausible-only suggestions:    {plausible}")
    print(f"  Rejected reports observed:     {len(rejected)}\n")
    for item in items:
        print(f"{item.source} [{item.reason_code}]")
        for mapping in item.accepted_mappings:
            print(f"  ACCEPTED_PROVENANCE: {mapping.destination}\n    {mapping.report_id}")
        for match in item.plausible_matches:
            evidence = "size equal" if match.size_equal else "size differs"
            print(f"  PLAUSIBLE_ONLY {match.score:.3f}: {match.destination} ({evidence})")
    print("\nPlausible matches are not publication evidence and cannot become verification or deletion input.")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = _load(args.config_file)
    except (OSError, ValueError) as exc:
        print(f"ingest-cleanup: configuration error: {exc}", file=sys.stderr); return 2
    if args.command == "help":
        parser().print_help(); return 0
    if args.command == "config":
        if args.json:
            print(json.dumps({
                "schema": "ingest-cleanup-config-v1",
                "config_file": str(args.config_file),
                "categories": [
                    {"name": value.name, "ingest_root": str(value.ingest_root), "production_root": str(value.production_root), "adapter": value.adapter}
                    for value in config.categories
                ],
                "kavita_report_root": str(config.kavita_state_root) if config.kavita_state_root else None,
            }, indent=2, sort_keys=True))
            return 0
        print(f"Config: {args.config_file}")
        for value in config.categories:
            print(f"{value.name}: {value.ingest_root} -> {value.production_root} ({value.adapter})")
        print(f"Kavita report root: {config.kavita_state_root}")
        return 0
    if args.command == "provenance-status":
        values = _provenance_status(config, emit=not args.json)
        if args.json:
            print(json.dumps({"schema": "ingest-cleanup-provenance-status-v1", "adapters": values}, indent=2, sort_keys=True))
        return 0
    if args.command == "compatibility":
        payload = compatibility_payload(config)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            observed = payload["observed"]
            assert isinstance(observed, dict)
            print(f"ingest-cleanup {payload['version']}")
            print(f"Machine instance: {str(payload['machine_instance_id'])[:12]}…")
            print(f"Accepted provenance records: {observed['accepted_records']}")
            print(f"Unpublished partial reports: {observed['unpublished_partial_reports']}")
            print("Observed report schemas:")
            for schema, count in dict(observed["reports_by_schema"]).items():
                print(f"  {count:>4}  {schema}")
            print("Use `ingest-cleanup compatibility --json` for supported schemas and rejection details.")
        return 0
    if args.command == "legacy-inventory":
        action = args.target or "status"
        if action == "status":
            payload = {
                "schema": "ingest-cleanup-legacy-inventory-status-v1",
                "inventory": inventory_status(config),
            }
            if args.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                inventory = payload["inventory"]
                assert isinstance(inventory, dict)
                print(f"Legacy inventory: {inventory.get('state')}")
                print(f"Path: {inventory.get('path')}")
                print(f"Trusted reports: {inventory.get('trusted_reports', 0)}")
                if inventory.get("reason"):
                    print(f"Reason: {inventory['reason']}")
                print("Missing or invalid inventory rejects every legacy report.")
            return 0
        if action != "create":
            print(
                "ingest-cleanup legacy-inventory accepts only status or create",
                file=sys.stderr,
            )
            return 2
        if not args.report:
            print(
                "ingest-cleanup legacy-inventory create requires at least one --report PATH",
                file=sys.stderr,
            )
            return 2
        if not args.yes:
            print(
                "ingest-cleanup legacy-inventory create requires --yes after reviewing every report",
                file=sys.stderr,
            )
            return 2
        try:
            target = create_inventory(config, list(args.report))
        except (OSError, ValueError) as exc:
            print(f"ingest-cleanup: legacy inventory refused: {exc}", file=sys.stderr)
            return 2
        payload = {
            "schema": "ingest-cleanup-legacy-inventory-created-v1",
            "path": str(target),
            "inventory": inventory_status(config),
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"Created trusted legacy inventory: {target}")
            print("No media or producer report was changed.")
        return 0
    if args.command == "backup-proof":
        if not args.target or not args.publication or not args.backup_object or not args.expected_uuid:
            print(
                "ingest-cleanup backup-proof requires SOURCE --publication PATH "
                "--backup-object PATH --expected-uuid UUID",
                file=sys.stderr,
            )
            return 2
        if config.backup_proof_root is None:
            print("ingest-cleanup: backup proof root is not configured", file=sys.stderr)
            return 2
        try:
            proof = create_backup_proof(
                Path(args.target),
                args.publication,
                args.backup_object,
                args.expected_uuid,
                config.backup_proof_root,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            print(f"ingest-cleanup: backup proof refused: {exc}", file=sys.stderr)
            return 2
        print(f"Verified exact-source independent backup proof: {proof}")
        print("No Incoming or publication file was changed.")
        return 0
    if args.command == "explain":
        if args.target is None:
            print("ingest-cleanup explain requires an Incoming source path", file=sys.stderr); return 2
        return _explain(config, Path(args.target), json_output=args.json)
    if args.command == "reconcile":
        selected = config.categories
        if args.target:
            selected = tuple(category for category in config.categories if category.name.casefold() == args.target.casefold())
            if not selected:
                print(f"ingest-cleanup: unknown category: {args.target}", file=sys.stderr)
                return 2
        items, rejected = reconcile(config, selected)
        if args.json:
            print(json.dumps(_reconciliation_payload(items, rejected), indent=2, sort_keys=True))
        else:
            _print_reconciliation(items, rejected)
        return 0
    if args.command == "show":
        if not args.target:
            print("ingest-cleanup show requires a plan ID", file=sys.stderr); return 2
        try:
            payload, plan_path = load_verification_plan(config, args.target)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"ingest-cleanup: plan rejected: {exc}", file=sys.stderr); return 2
        if args.json:
            print(json.dumps({"schema": "ingest-cleanup-show-v1", "plan_path": str(plan_path), "plan": payload}, indent=2, sort_keys=True))
        else:
            print(f"Plan: {plan_path}")
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if args.command == "apply" and args.target:
        try:
            payload, plan_path = load_verification_plan(config, args.target)
            if not args.json:
                print(f"Revalidating saved plan: {plan_path}")
            expected = sum(int(item.get("source_size") or 0) + int(item.get("destination_size") or 0) for item in payload["items"] if isinstance(item, dict))
            progress = _progress(args.verbose, expected, json_output=args.json)
            results = verify_saved_plan(config, payload, progress)
            progress.finish()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"ingest-cleanup: plan rejected: {exc}", file=sys.stderr); return 2
        rejected = []
        return _apply_verified(config, results, rejected, args.verbose, plan_path, json_output=args.json)
    hash_files = args.command != "status"
    if hash_files and not args.json:
        print("Full verification recomputes SHA-256 for source and production copies. Large libraries can take several minutes. No Incoming or library files will be changed.\n")
    elif not hash_files and not args.json:
        print("Status checks provenance, existence, and size only. It never declares sources deletion-ready.\n")
    progress = _progress(args.verbose, json_output=args.json) if hash_files else None
    results, rejected = assess(config, progress, hash_files=hash_files)
    if progress:
        progress.finish()
    if args.command == "verify":
        safe = [item for item in results if item.state == "SAFE"]
        plan_id = None
        plan_path = None
        if safe:
            plan_id, plan_path = create_verification_plan(config, safe)
        if args.json:
            payload = _results_payload("verify", results, rejected, config.categories)
            payload["verification_plan"] = {"id": plan_id, "path": str(plan_path) if plan_path else None, "expires_in_hours": 24 if plan_id else None}
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            _print(results, rejected, args.verbose, config.categories)
            if plan_id:
                print(f"Saved verification plan: {plan_id}\nPlan path: {plan_path}\nExpires in 24 hours.")
            else:
                print("Verification complete. No deletion-ready sources were found; no plan was saved.")
        return 0
    if args.command != "apply":
        if args.json:
            print(json.dumps(_results_payload(args.command, results, rejected, config.categories), indent=2, sort_keys=True))
        else:
            _print(results, rejected, args.verbose, config.categories)
        return 0
    return _apply_verified(config, results, rejected, args.verbose, None, json_output=args.json)


def _human_size(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB": return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def _apply_verified(config: Config, results: list[Assessment], rejected: list[object], verbose: bool, plan_path: Path | None, *, json_output: bool = False) -> int:
    safe = [item for item in results if item.state == "SAFE"]
    total = sum(item.size for item in safe)
    if not json_output:
        _print(results, rejected, verbose, config.categories, apply_mode=True)
    counts = Counter(item.category for item in safe)
    if not json_output:
        print(f"\nProposed deletions: {len(safe)} file(s), {_human_size(total)} ({total} bytes)")
        for category, count in sorted(counts.items()): print(f"  {category}: {count}")
        if plan_path: print(f"Verification plan: {plan_path}")
        print("Warning: byte-identical production content is not independent backup proof.")
    if not safe:
        if json_output:
            payload = _results_payload("apply", results, rejected, config.categories)
            payload["apply"] = {"status": "no-deletion-ready-sources", "deleted": 0}
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("Verification complete. No deletion-ready sources were found.")
        return 0
    audit_path = new_audit_path()
    if not json_output:
        print(f"Audit path: {audit_path}")
    phrase = f"DELETE {len(safe)} VERIFIED SOURCES"
    try:
        if json_output:
            print(f"Type {phrase} to delete these files: ", end="", file=sys.stderr, flush=True)
            answer = input().strip()
        else:
            answer = input(f"Type {phrase} to delete these files: ").strip()
    except (EOFError, KeyboardInterrupt): answer = ""
    if answer != phrase:
        if json_output:
            payload = _results_payload("apply", results, rejected, config.categories)
            payload["apply"] = {"status": "cancelled", "deleted": 0, "audit_path": str(audit_path)}
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("Cancelled. No files were deleted.")
        return 0
    progress = (
        _progress(verbose, stream_expected, json_output=json_output)
        if (stream_expected := sum(item.size for item in safe))
        else None
    )
    payload = apply_deletions(
        safe,
        {category.name: category.ingest_root for category in config.categories},
        audit_path,
        progress,
        config=config,
    )
    if progress:
        progress.finish()
    deleted = sum(1 for item in payload["items"] if item["result"] == "deleted")
    if json_output:
        result = _results_payload("apply", results, rejected, config.categories)
        result["apply"] = {"status": payload.get("status"), "deleted": deleted, "audit_path": str(audit_path)}
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Deleted {deleted} verified source file(s). Audit: {audit_path}")
    return 0 if payload.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
