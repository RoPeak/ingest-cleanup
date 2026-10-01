from __future__ import annotations

import argparse
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from .config import Config, load, validate, xdg_config
from .core import Assessment, apply_deletions, assess, assess_category, write_audit


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="ingest-cleanup", description="Safely remove preserved ingest files only after fresh provenance verification.")
    value.add_argument("--config-file", type=Path, default=xdg_config())
    value.add_argument("--verbose", action="store_true")
    value.add_argument("command", nargs="?", choices=("status", "verify", "apply", "config", "help", "explain", "provenance-status"), default="status")
    value.add_argument("path", nargs="?", type=Path, help="Incoming source path for explain")
    return value


def _progress(verbose: bool):
    seen: dict[Path, int] = {}
    started: dict[Path, float] = {}
    tty = sys.stdout.isatty()
    order: list[Path] = []
    def callback(path: Path, complete: int, total: int) -> None:
        if total == 0: return
        percent = complete * 100 // total
        if path not in started:
            started[path] = time.monotonic()
            order.append(path)
            if not tty:
                print(f"  Verifying {path.name} ({total / 1024 / 1024:.1f} MiB)", flush=True)
        if seen.get(path) != percent and (percent == 100 or percent % 10 == 0):
            seen[path] = percent
            elapsed = max(time.monotonic() - started[path], 0.001)
            rate = complete / elapsed / 1024 / 1024
            role = "Source" if len(order) % 2 else "Destination"
            suffix = f" | {rate:.1f} MiB/s" if complete >= 32 * 1024 * 1024 and elapsed >= 1 else ""
            if tty:
                print(f"\r\033[2KVerifying {path.name} | {role} {percent}%{suffix}", end="", flush=True)
                if percent == 100:
                    print()
            else:
                print(f"  {role.lower()} {path.name}: {percent}%{suffix}", flush=True)
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
        print(f"  Review:         {counts['REVIEW']}")
        print(f"  Unknown:        {counts['UNKNOWN']}")
        if verbose:
            for value in values:
                print(f"  {value.state}: {value.source} — {value.reason}")
        else:
            reasons = Counter((value.state, value.reason) for value in values if value.state != "SAFE")
            for (state, reason), count in sorted(reasons.items()):
                print(f"  {state}: {count} — {reason}")
        print()
    if rejected and verbose:
        print(f"Ignored corrupt/unsafe reports: {len(rejected)}")
    if not apply_mode:
        print("No files were deleted. Run `ingest-cleanup apply` to verify and review deletion.")


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
        if args.path is None:
            print("ingest-cleanup explain requires an Incoming source path", file=sys.stderr); return 2
        return _explain(config, args.path)
    hash_files = args.command != "status"
    if hash_files:
        print("Full verification recomputes SHA-256 for source and production copies. Large libraries can take several minutes. No files will be changed.\n")
    else:
        print("Status checks provenance, existence, and size only. It never declares sources deletion-ready.\n")
    results, rejected = assess(config, _progress(args.verbose) if hash_files else None, hash_files=hash_files)
    if args.command != "apply":
        _print(results, rejected, args.verbose, config.categories); return 0
    safe = [item for item in results if item.state == "SAFE"]
    total = sum(item.size for item in safe)
    _print(results, rejected, args.verbose, config.categories, apply_mode=True)
    print(f"\nProposed deletions: {len(safe)} file(s), {total} bytes")
    if not safe:
        print("Verification complete. No deletion-ready sources were found.")
        return 0
    try: answer = input("Type DELETE VERIFIED SOURCES to delete these files: ").strip()
    except (EOFError, KeyboardInterrupt): answer = ""
    if answer != "DELETE VERIFIED SOURCES":
        print("Cancelled. No files were deleted."); return 0
    payload = apply_deletions(safe, {category.name: category.ingest_root for category in config.categories})
    payload["skipped_or_review"] = [{"source": str(item.source), "state": item.state, "reason": item.reason} for item in results if item.state != "SAFE"]
    audit = write_audit(payload)
    deleted = sum(1 for item in payload["items"] if item["result"] == "deleted")
    print(f"Deleted {deleted} verified source file(s). Audit: {audit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
