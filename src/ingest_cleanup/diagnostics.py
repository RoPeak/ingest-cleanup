from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from . import __version__
from .adapters import collect
from .config import Config
from .provenance import machine_instance_id

SUPPORTED_SCHEMAS = {
    "video": [
        "video JSONL v1",
        "video JSONL v2",
        "video JSONL v3",
        "video-ingest-publication-v4",
    ],
    "music": [
        "music-ingest-publication-v1",
        "music-ingest-publication-v2",
        "music-ingest-publication-v3",
    ],
    "kavita": [
        "kavita-ingest-publication-v1",
        "kavita-ingest-publication-v2",
        "kavita-ingest-publication-v3",
        "kavita-ingest-publication-v4",
    ],
}


def _rejection_classification(reason: str) -> str:
    lowered = reason.casefold()
    if "expecting" in lowered or "json" in lowered or "decode" in lowered:
        return "CORRUPT_REPORT"
    if "unsupported" in lowered or "legacy" in lowered:
        return "UNSUPPORTED_SCHEMA"
    if "not an approved" in lowered or "did not complete" in lowered or "incomplete" in lowered:
        return "INCOMPLETE_RUN"
    if "missing" in lowered or "does not exist" in lowered:
        return "MISSING_ENDPOINT"
    return "INVALID_PROVENANCE"


def _schema(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = json.loads(text.splitlines()[0])
        if isinstance(payload, dict):
            return str(
                payload.get("report_schema")
                or f"video-jsonl-v{payload.get('version', 'unknown')}"
            )
    except OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError:
        pass
    return "malformed"


def compatibility_payload(config: Config) -> dict[str, object]:
    report_paths: set[Path] = set()
    rejected = Counter()
    rejected_classes = Counter()
    seen_rejections: set[tuple[Path, str]] = set()
    accepted_records: set[tuple[str, Path, Path]] = set()
    for category in config.categories:
        records, bad = collect(config, category)
        accepted_records.update(
            (record.report_id, record.source, record.destination) for record in records
        )
        report_paths.update(record.report for record in records)
        for item in bad:
            report_paths.add(item.path)
            key = (item.path, item.reason)
            if key not in seen_rejections:
                rejected[item.reason] += 1
                rejected_classes[_rejection_classification(item.reason)] += 1
                seen_rejections.add(key)
    for root in config.video_state_roots:
        if root.is_dir() and not root.is_symlink():
            report_paths.update(root.glob("*/reports/*.json"))
    if (
        config.music_state_root
        and config.music_state_root.is_dir()
        and not config.music_state_root.is_symlink()
    ):
        report_paths.update(config.music_state_root.glob("reports/*.json"))
    if (
        config.kavita_state_root
        and config.kavita_state_root.is_dir()
        and not config.kavita_state_root.is_symlink()
    ):
        report_paths.update(config.kavita_state_root.glob("kavita-reports/*.json"))
    roots = [*config.video_state_roots]
    if config.music_state_root:
        roots.append(config.music_state_root)
    if config.kavita_state_root:
        roots.append(config.kavita_state_root)
    partials = 0
    for root in roots:
        if root.is_dir() and not root.is_symlink():
            partials += sum(
                1
                for path in root.rglob("*.partial")
                if path.is_file() and not path.is_symlink()
            )
    schemas = Counter(_schema(path) for path in report_paths)
    return {
        "schema": "ingest-cleanup-compatibility-v1",
        "program": "ingest-cleanup",
        "version": __version__,
        "machine_instance_id": machine_instance_id(),
        "supported_report_schemas": SUPPORTED_SCHEMAS,
        "configured_categories": [
            {
                "name": category.name,
                "adapter": category.adapter,
                "ingest_root": str(category.ingest_root),
                "production_root": str(category.production_root),
            }
            for category in config.categories
        ],
        "observed": {
            "accepted_records": len(accepted_records),
            "reports_by_schema": dict(sorted(schemas.items())),
            "rejected_reports_by_classification": dict(sorted(rejected_classes.items())),
            "rejected_reports_by_reason": dict(sorted(rejected.items())),
            "unpublished_partial_reports": partials,
        },
    }
