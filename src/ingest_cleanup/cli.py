from __future__ import annotations

import argparse
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from .config import Config, load, validate, xdg_config
from .core import Assessment, apply_deletions, assess, write_audit


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="ingest-cleanup", description="Safely remove preserved ingest files only after fresh provenance verification.")
    value.add_argument("--config-file", type=Path, default=xdg_config())
    value.add_argument("--verbose", action="store_true")
    value.add_argument("command", nargs="?", choices=("status", "verify", "apply", "config", "help"), default="status")
    return value


def _progress(verbose: bool):
    seen: dict[Path, int] = {}
    started: dict[Path, float] = {}
    def callback(path: Path, complete: int, total: int) -> None:
        if total == 0: return
        percent = complete * 100 // total
        if path not in started:
            started[path] = time.monotonic()
            print(f"  Hashing {path.name} ({total / 1024 / 1024:.1f} MiB)", flush=True)
        if seen.get(path) != percent and (percent == 100 or percent % 10 == 0):
            seen[path] = percent; print(f"  hashing {path.name}: {percent}%")
            elapsed = max(time.monotonic() - started[path], 0.001)
            print(f"    {complete / 1024 / 1024:.1f} MiB read | {complete / elapsed / 1024 / 1024:.1f} MiB/s", flush=True)
    return callback


def _print(results: list[Assessment], rejected: list[object], verbose: bool) -> None:
    print("Ingest Cleanup\n\nScanning successful ingestion records...\n")
    grouped: dict[str, list[Assessment]] = defaultdict(list)
    for result in results: grouped[result.category].append(result)
    for category, values in grouped.items():
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
    print("No files were deleted. Run `ingest-cleanup apply` to review deletion.")


def _load(path: Path) -> Config:
    config = load(path); validate(config); return config


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
        print(f"Kavita adapter enabled: {config.kavita_enabled}")
        return 0
    hash_files = args.command != "status"
    if hash_files:
        print("Full verification recomputes SHA-256 for source and production copies. Large libraries can take several minutes. No files will be changed.\n")
    else:
        print("Status checks provenance, existence, and size only. It never declares sources deletion-ready.\n")
    results, rejected = assess(config, _progress(args.verbose) if hash_files else None, hash_files=hash_files)
    if args.command != "apply":
        _print(results, rejected, args.verbose); return 0
    safe = [item for item in results if item.state == "SAFE"]
    total = sum(item.size for item in safe)
    _print(results, rejected, args.verbose)
    print(f"\nProposed deletions: {len(safe)} file(s), {total} bytes")
    if not safe: return 0
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
