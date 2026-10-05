from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import Category, Config


@dataclass(frozen=True)
class Evidence:
    source: Path
    destination: Path
    adapter: str
    report: Path
    report_id: str
    source_sha256: str | None = None
    destination_sha256: str | None = None
    transformed: bool = False


@dataclass(frozen=True)
class RejectedReport:
    path: Path
    reason: str


def _safe_report_file(path: Path, root: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False


def _absolute_clean(value: object) -> Path | None:
    if not isinstance(value, str):
        return None
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        return None
    return path


def video_records(config: Config, category: Category) -> tuple[list[Evidence], list[RejectedReport]]:
    records: list[Evidence] = []
    rejected: list[RejectedReport] = []
    for root in config.video_state_roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for report in root.glob("*/reports/*.json"):
            if not _safe_report_file(report, root):
                rejected.append(RejectedReport(report, "unsafe report path")); continue
            try:
                rows = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines() if line.strip()]
                if len(rows) < 2 or not isinstance(rows[0], dict):
                    raise ValueError("not a successful COPY JSON Lines report")
                header = rows[0]
                version = header.get("version")
                if version not in {1, 2} or header.get("type") != "header" or header.get("mode") != "apply" or header.get("copy") is not True:
                    raise ValueError("not a successful COPY JSON Lines report")
                if not isinstance(rows[-1], dict) or rows[-1].get("type") != "final":
                    raise ValueError("missing final record")
                operations = rows[1:-1]
                if rows[-1].get("operations") != len(operations) or any(not isinstance(row, dict) or row.get("type") != "operation" for row in operations):
                    raise ValueError("incomplete or invalid operation sequence")
                for index, row in enumerate(operations, 1):
                    source, destination = _absolute_clean(row.get("source")), _absolute_clean(row.get("destination"))
                    if source is None or destination is None:
                        raise ValueError("operation has an unsafe path")
                    action = "published" if version == 1 else row.get("action")
                    if action not in {"published", "verified-existing-duplicate"}:
                        raise ValueError("operation has unsupported action")
                    records.append(Evidence(source, destination, "video", report, f"{report}:{index}"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                rejected.append(RejectedReport(report, str(exc)))
    return records, rejected


def music_records(config: Config, category: Category) -> tuple[list[Evidence], list[RejectedReport]]:
    records: list[Evidence] = []
    rejected: list[RejectedReport] = []
    root = config.music_state_root
    if root is None or not root.is_dir() or root.is_symlink():
        return records, rejected
    for report in root.glob("reports/*.json"):
        if not _safe_report_file(report, root):
            rejected.append(RejectedReport(report, "unsafe report path")); continue
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(data, dict): raise ValueError("report is not an object")
            if data.get("report_schema") != "music-ingest-publication-v1":
                raise ValueError("unsupported music publication schema")
            if not (data.get("mode") == "apply" and data.get("approved_to_publish") is True
                    and data.get("publication") == "copy" and data.get("source_lifecycle") == "preserved"):
                raise ValueError("not an approved preserved APPLY publication")
            if data.get("publication_completed") is not True:
                raise ValueError("publication did not complete")
            source_root = _absolute_clean(data.get("source_root"))
            library_root = _absolute_clean(data.get("library_root"))
            if source_root is None or library_root is None or source_root != category.ingest_root or library_root != category.production_root:
                raise ValueError("report roots do not match configured roots")
            tracks = [track for album in data.get("albums", []) if isinstance(album, dict) for track in album.get("tracks", []) if isinstance(track, dict)]
            for index, track in enumerate(tracks, 1):
                src, rel = track.get("source"), track.get("destination")
                source_path, final_destination = _absolute_clean(track.get("source_path")), _absolute_clean(track.get("final_destination"))
                if not isinstance(src, str) or not isinstance(rel, str) or Path(src).is_absolute() or Path(rel).is_absolute() or ".." in Path(src).parts or ".." in Path(rel).parts:
                    raise ValueError("unsafe track path")
                if source_path != source_root / src or final_destination != library_root / rel or _absolute_clean(track.get("destination_path")) != final_destination:
                    raise ValueError("track paths are inconsistent")
                if (track.get("readable") is not True or track.get("verified_size_match") is not True
                        or not isinstance(track.get("source_size_bytes"), int)
                        or track.get("source_size_bytes") != track.get("staged_size_bytes")
                        or track.get("publication_status") != "published_or_verified_existing"):
                    raise ValueError("track does not prove successful publication")
                records.append(Evidence(source_path, final_destination, "music", report, f"{report}:{index}"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            rejected.append(RejectedReport(report, str(exc)))
    return records, rejected


def kavita_records(config: Config, category: Category) -> tuple[list[Evidence], list[RejectedReport]]:
    """Read only completed preserve-source records; old reports are never inferred."""
    records: list[Evidence] = []; rejected: list[RejectedReport] = []
    if not config.kavita_enabled:
        return records, rejected
    # The report directory is intentionally explicit/configured through the
    # existing state root convention, not discovered from arbitrary media dirs.
    root = config.kavita_state_root
    if root is None or not root.is_dir() or root.is_symlink():
        return records, rejected
    for report in root.glob("kavita-reports/*.json"):
        try:
            if not _safe_report_file(report, root): raise ValueError("unsafe report path")
            data = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("report_schema") != "kavita-ingest-publication-v1":
                raise ValueError("unsupported Kavita publication schema")
            if not (data.get("status") == "completed" and data.get("approved_apply") is True and data.get("source_lifecycle") == "preserved" and data.get("verification_completed") is True and not data.get("recovery_required")):
                raise ValueError("not a completed verified preserve-source APPLY")
            for index, item in enumerate(data.get("items", []), 1):
                if not isinstance(item, dict): raise ValueError("invalid item")
                source, destination = _absolute_clean(item.get("source")), _absolute_clean(item.get("destination"))
                sh, dh = item.get("source_sha256"), item.get("destination_sha256")
                if source is None or destination is None or not all(isinstance(x, str) and len(x) == 64 for x in (sh, dh)):
                    raise ValueError("item lacks safe paths or hashes")
                if not source.is_relative_to(category.ingest_root) or not destination.is_relative_to(category.production_root):
                    raise ValueError("item paths do not match configured category roots")
                records.append(Evidence(source, destination, "kavita", report, f"{report}:{index}", sh, dh, bool(item.get("transformations"))))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            rejected.append(RejectedReport(report, str(exc)))
    return records, rejected


def collect(config: Config, category: Category) -> tuple[list[Evidence], list[RejectedReport]]:
    if category.adapter == "video": return video_records(config, category)
    if category.adapter == "music": return music_records(config, category)
    if category.adapter == "kavita": return kavita_records(config, category)
    return [], []
