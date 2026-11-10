from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

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


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="ingest-cleanup", description="Safely remove preserved ingest files only after fresh provenance verification.")
    value.add_argument("--config-file", type=Path, default=xdg_config())
    value.add_argument("--verbose", action="store_true")
    value.add_argument("command", nargs="?", choices=("status", "verify", "show", "apply", "config", "help", "explain", "provenance-status"), default="status")
    value.add_argument("target", nargs="?", help="Incoming path for explain, or verification plan ID for show/apply")
    return value


def _progress(verbose: bool, expected_bytes: int | None = None):
    seen: dict[Path, int] = {}
    started: dict[Path, float] = {}
    tty = sys.stdout.isatty()
    order: list[Path] = []
    last: dict[Path, int] = {}
    aggregate = 0
    aggregate_started = time.monotonic()
    def callback(path: Path, complete: int, total: int) -> None:
        nonlocal aggregate
        if total == 0: return
        percent = complete * 100 // total
        if path not in started:
            started[path] = time.monotonic()
            order.append(path)
            if not tty and verbose:
                print(f"  Verifying {path.name} ({total / 1024 / 1024:.1f} MiB)", flush=True)
        if seen.get(path) != percent and (percent == 100 or percent % 10 == 0):
            seen[path] = percent
            aggregate += max(0, complete - last.get(path, 0)); last[path] = complete
            elapsed = max(time.monotonic() - started[path], 0.001)
            rate = complete / elapsed / 1024 / 1024
            role = "Source" if len(order) % 2 else "Destination"
            suffix = f" | {rate:.1f} MiB/s" if complete >= 32 * 1024 * 1024 and elapsed >= 1 else ""
            if tty and verbose:
                print(f"\r\033[2KVerifying {path.name} | {role} {percent}%{suffix}", end="", flush=True)
                if percent == 100:
                    print()
            elif verbose:
                print(f"  {role.lower()} {path.name}: {percent}%{suffix}", flush=True)
            overall_elapsed = max(time.monotonic() - aggregate_started, 0.001)
            overall_rate = aggregate / overall_elapsed
            eta = ""
            if expected_bytes and overall_rate > 0:
                eta = f" | ETA {max(0, expected_bytes - aggregate) / overall_rate:.0f}s"
            print(f"  Overall: {len(order)} endpoint(s) | {aggregate / 1024 / 1024:.1f} MiB | {overall_rate / 1024 / 1024:.1f} MiB/s{eta}", flush=True)
    return callback


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
        if verbose:
            for value in values:
                mapping = f" -> {value.destination}" if value.destination else ""
                print(f"  {value.state} [{value.reason_code or 'UNCLASSIFIED'}]: {value.source}{mapping} — {value.reason}")
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
                print(f"  {count} from {origin} — {reason}")
            print("  Use --verbose for the full rejected-report list.")
    adapters = {item.name: item.adapter for item in categories or []}
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
    if not apply_mode:
        print("No files were deleted. Run `ingest-cleanup apply` to verify and review deletion.")


def _report_origin(path: Path) -> str:
    for name in ("video-ingest", "music-ingest", "kavita-ingest"):
        if name in path.parts:
            return name
    return str(path.parent)


def _load(path: Path) -> Config:
    config = load(path); validate(config); return config


def _provenance_status(config: Config) -> None:
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
        print(f"{category.name:<16} {category.adapter:<8} {state}")
    print("\nThis checks adapter configuration only; it does not assess any source as safe.")


def _explain(config: Config, path: Path) -> int:
    candidate = path.expanduser()
    for category in config.categories:
        try:
            candidate.resolve(strict=False).relative_to(category.ingest_root.resolve(strict=True))
        except (OSError, ValueError):
            continue
        results, rejected = assess_category(config, category, hash_files=False)
        item = next((value for value in results if value.source == candidate), None)
        if item is None:
            print("UNKNOWN\nSource is not a regular supported Incoming file.")
            return 0
        reason = item.reason
        if item.state == "UNKNOWN" and reason == "insufficient proof":
            reason = "No matching accepted publication report exists."
            if rejected:
                reason += f" {len(rejected)} report(s) were rejected as incomplete, malformed, or unsafe."
        print(item.state)
        print(f"Category: {item.category}")
        print(f"Reason: {reason}")
        if item.evidence:
            print(f"Adapter: {item.evidence.adapter}")
            print(f"Report: {item.evidence.report}")
            print(f"Record: {item.evidence.report_id}")
            print(f"Destination: {item.evidence.destination}")
        return 0
    print("UNKNOWN\nPath is outside configured Incoming roots.")
    return 2


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = _load(args.config_file)
    except (OSError, ValueError) as exc:
        print(f"ingest-cleanup: configuration error: {exc}", file=sys.stderr); return 2
    if args.command == "help":
        parser().print_help(); return 0
    if args.command == "config":
        print(f"Config: {args.config_file}")
        for value in config.categories:
            print(f"{value.name}: {value.ingest_root} -> {value.production_root} ({value.adapter})")
        print(f"Kavita report root: {config.kavita_state_root}")
        return 0
    if args.command == "provenance-status":
        _provenance_status(config); return 0
    if args.command == "explain":
        if args.target is None:
            print("ingest-cleanup explain requires an Incoming source path", file=sys.stderr); return 2
        return _explain(config, Path(args.target))
    if args.command == "show":
        if not args.target:
            print("ingest-cleanup show requires a plan ID", file=sys.stderr); return 2
        try:
            payload, plan_path = load_verification_plan(config, args.target)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"ingest-cleanup: plan rejected: {exc}", file=sys.stderr); return 2
        print(f"Plan: {plan_path}")
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if args.command == "apply" and args.target:
        try:
            payload, plan_path = load_verification_plan(config, args.target)
            print(f"Revalidating saved plan: {plan_path}")
            expected = sum(int(item.get("source_size") or 0) + int(item.get("destination_size") or 0) for item in payload["items"] if isinstance(item, dict))
            results = verify_saved_plan(config, payload, _progress(args.verbose, expected))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"ingest-cleanup: plan rejected: {exc}", file=sys.stderr); return 2
        rejected = []
        return _apply_verified(config, results, rejected, args.verbose, plan_path)
    hash_files = args.command != "status"
    if hash_files:
        print("Full verification recomputes SHA-256 for source and production copies. Large libraries can take several minutes. No Incoming or library files will be changed.\n")
    else:
        print("Status checks provenance, existence, and size only. It never declares sources deletion-ready.\n")
    results, rejected = assess(config, _progress(args.verbose) if hash_files else None, hash_files=hash_files)
    if args.command == "verify":
        _print(results, rejected, args.verbose, config.categories)
        safe = [item for item in results if item.state == "SAFE"]
        if safe:
            plan_id, plan_path = create_verification_plan(config, safe)
            print(f"Saved verification plan: {plan_id}\nPlan path: {plan_path}\nExpires in 24 hours.")
        else:
            print("Verification complete. No deletion-ready sources were found; no plan was saved.")
        return 0
    if args.command != "apply":
        _print(results, rejected, args.verbose, config.categories); return 0
    return _apply_verified(config, results, rejected, args.verbose, None)


def _human_size(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB": return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def _apply_verified(config: Config, results: list[Assessment], rejected: list[object], verbose: bool, plan_path: Path | None) -> int:
    safe = [item for item in results if item.state == "SAFE"]
    total = sum(item.size for item in safe)
    _print(results, rejected, verbose, config.categories, apply_mode=True)
    counts = Counter(item.category for item in safe)
    print(f"\nProposed deletions: {len(safe)} file(s), {_human_size(total)} ({total} bytes)")
    for category, count in sorted(counts.items()): print(f"  {category}: {count}")
    if plan_path: print(f"Verification plan: {plan_path}")
    print("Warning: byte-identical production content is not independent backup proof.")
    if not safe:
        print("Verification complete. No deletion-ready sources were found.")
        return 0
    audit_path = new_audit_path()
    print(f"Audit path: {audit_path}")
    phrase = f"DELETE {len(safe)} VERIFIED SOURCES"
    try: answer = input(f"Type {phrase} to delete these files: ").strip()
    except (EOFError, KeyboardInterrupt): answer = ""
    if answer != phrase:
        print("Cancelled. No files were deleted."); return 0
    payload = apply_deletions(
        safe,
        {category.name: category.ingest_root for category in config.categories},
        audit_path,
        _progress(verbose, sum(item.size + (item.destination_identity.size if item.destination_identity else 0) for item in safe)),
    )
    deleted = sum(1 for item in payload["items"] if item["result"] == "deleted")
    print(f"Deleted {deleted} verified source file(s). Audit: {audit_path}")
    return 0 if payload.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
