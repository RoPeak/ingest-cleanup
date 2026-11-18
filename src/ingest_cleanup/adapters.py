from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path

from .config import Category, Config
from .provenance import require_local_producer


@dataclass(frozen=True)
class ReportIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    links: int


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
    active: bool = True
    archived_destination: Path | None = None
    archived_sha256: str | None = None
    superseded_by: Path | None = None
    producer: str | None = None
    schema: str | None = None
    machine_identity: str | None = None
    completion_status: str | None = None
    report_sha256: str | None = None
    report_identity: ReportIdentity | None = None
    supersession_report: Path | None = None
    supersession_report_sha256: str | None = None
    supersession_report_identity: ReportIdentity | None = None


@dataclass(frozen=True)
class RejectedReport:
    path: Path
    reason: str


def _safe_report_file(path: Path, root: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False


def _read_report(path: Path, root: Path) -> tuple[str, str, ReportIdentity]:
    """Read a report and bind its content and filesystem identity."""
    if not _safe_report_file(path, root):
        raise ValueError("unsafe report path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("report is not a regular single-link file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read()
            after = os.fstat(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = ReportIdentity(
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    )
    after_identity = ReportIdentity(
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    )
    current = path.lstat()
    current_identity = ReportIdentity(
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
        current.st_nlink,
    )
    if identity != after_identity or identity != current_identity:
        raise ValueError("report changed while being read")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("report is not valid UTF-8") from exc
    return text, hashlib.sha256(payload).hexdigest(), identity


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
            try:
                text, report_hash, report_identity = _read_report(report, root)
                rows = [json.loads(line) for line in text.splitlines() if line.strip()]
                if len(rows) < 2 or not isinstance(rows[0], dict):
                    raise ValueError("not a successful JSON Lines report")
                header = rows[0]
                version = header.get("version")
                if version not in {1, 2, 3, 4} or header.get("type") != "header" or header.get("mode") != "apply":
                    raise ValueError("not a successful APPLY JSON Lines report")
                if version == 4:
                    if header.get("report_schema") != "video-ingest-publication-v4":
                        raise ValueError("unsupported video publication schema")
                    require_local_producer(header, "video-ingest")
                if version < 3 and header.get("copy") is not True:
                    raise ValueError("legacy report is not a successful COPY report")
                if not isinstance(rows[-1], dict) or rows[-1].get("type") != "final" or (version >= 3 and rows[-1].get("status") != "completed"):
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
                    lifecycle = "preserved" if version < 3 else row.get("source_lifecycle")
                    if lifecycle not in {"preserved", "removed"}:
                        raise ValueError("operation has unsupported source lifecycle")
                    if lifecycle == "removed":
                        continue
                    if version >= 3 and action == "verified-existing-duplicate" and row.get("verification") != "sha256":
                        raise ValueError("duplicate evidence lacks SHA-256 verification")
                    source_hash = row.get("source_sha256")
                    destination_hash = row.get("destination_sha256")
                    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
                    source_hash = source_hash or metadata.get("source_sha256")
                    destination_hash = destination_hash or metadata.get("destination_sha256")
                    if source_hash is not None and (not isinstance(source_hash, str) or len(source_hash) != 64):
                        raise ValueError("operation has invalid source hash")
                    if destination_hash is not None and (not isinstance(destination_hash, str) or len(destination_hash) != 64):
                        raise ValueError("operation has invalid destination hash")
                    records.append(
                        Evidence(
                            source=source,
                            destination=destination,
                            adapter="video",
                            report=report,
                            report_id=f"{report}:{index}",
                            source_sha256=source_hash,
                            destination_sha256=destination_hash,
                            producer=header.get("producer")
                            if isinstance(header.get("producer"), str)
                            else None,
                            schema=(
                                str(header.get("report_schema"))
                                if header.get("report_schema") is not None
                                else f"video-jsonl-v{version}"
                            ),
                            machine_identity=header.get("producer_instance_id")
                            if isinstance(header.get("producer_instance_id"), str)
                            else None,
                            completion_status=(
                                str(rows[-1].get("status"))
                                if rows[-1].get("status") is not None
                                else "legacy-completed"
                            ),
                            report_sha256=report_hash,
                            report_identity=report_identity,
                        )
                    )
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
        try:
            text, report_hash, report_identity = _read_report(report, root)
            data = json.loads(text)
            if not isinstance(data, dict): raise ValueError("report is not an object")
            schema = data.get("report_schema")
            if schema not in {"music-ingest-publication-v1", "music-ingest-publication-v2", "music-ingest-publication-v3"}:
                raise ValueError("unsupported music publication schema")
            if schema == "music-ingest-publication-v3":
                require_local_producer(data, "music-ingest")
            if not (data.get("mode") == "apply" and data.get("approved_to_publish") is True
                    and data.get("publication") == "copy" and data.get("source_lifecycle") == "preserved"):
                raise ValueError("not an approved preserved APPLY publication")
            if data.get("publication_completed") is not True:
                raise ValueError("publication did not complete")
            source_root = _absolute_clean(data.get("source_root"))
            library_root = _absolute_clean(data.get("library_root"))
            if source_root is None or library_root is None or source_root != category.ingest_root or library_root != category.production_root:
                raise ValueError("report roots do not match configured roots")
            if schema in {"music-ingest-publication-v2", "music-ingest-publication-v3"}:
                items = data.get("items")
                if not isinstance(items, list):
                    raise ValueError("v2 report lacks per-file outcomes")
                for index, item in enumerate(items, 1):
                    if not isinstance(item, dict): raise ValueError("invalid v2/v3 item")
                    action = item.get("action")
                    lifecycle = item.get("source_lifecycle")
                    kind = item.get("kind")
                    if action in {"failed", "conflicting", "generated-auxiliary"}:
                        continue
                    if action not in {"published", "verified-existing-duplicate"} or lifecycle != "preserved" or kind not in {"audio", "local-artwork"}:
                        raise ValueError("v2/v3 item has unsupported cleanup evidence")
                    source_path = _absolute_clean(item.get("source")); final_destination = _absolute_clean(item.get("destination"))
                    if source_path is None or final_destination is None or not source_path.is_relative_to(source_root) or not final_destination.is_relative_to(library_root):
                        raise ValueError("v2/v3 item paths are unsafe")
                    sh, dh = item.get("source_sha256"), item.get("destination_sha256")
                    for value in (sh, dh):
                        if value is not None and (not isinstance(value, str) or len(value) != 64): raise ValueError("v2/v3 item has invalid hash")
                    records.append(
                        Evidence(
                            source=source_path,
                            destination=final_destination,
                            adapter="music",
                            report=report,
                            report_id=f"{report}:{index}",
                            source_sha256=sh,
                            destination_sha256=dh,
                            producer=data.get("producer")
                            if isinstance(data.get("producer"), str)
                            else None,
                            schema=str(schema),
                            machine_identity=data.get("producer_instance_id")
                            if isinstance(data.get("producer_instance_id"), str)
                            else None,
                            completion_status="completed",
                            report_sha256=report_hash,
                            report_identity=report_identity,
                        )
                    )
                continue
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
                records.append(
                    Evidence(
                        source=source_path,
                        destination=final_destination,
                        adapter="music",
                        report=report,
                        report_id=f"{report}:{index}",
                        producer=data.get("producer")
                        if isinstance(data.get("producer"), str)
                        else None,
                        schema=str(schema),
                        machine_identity=data.get("producer_instance_id")
                        if isinstance(data.get("producer_instance_id"), str)
                        else None,
                        completion_status="completed",
                        report_sha256=report_hash,
                        report_identity=report_identity,
                    )
                )
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
            text, report_hash, report_identity = _read_report(report, root)
            data = json.loads(text)
            if not isinstance(data, dict) or data.get("report_schema") not in {"kavita-ingest-publication-v1", "kavita-ingest-publication-v2", "kavita-ingest-publication-v3", "kavita-ingest-publication-v4"}:
                raise ValueError("unsupported Kavita publication schema")
            schema = data.get("report_schema")
            if schema == "kavita-ingest-publication-v4":
                require_local_producer(data, "kavita-ingest")
            accepted_lifecycle = {"preserved"} if schema == "kavita-ingest-publication-v1" else {"preserved", "mixed"}
            accepted_statuses = {"completed", "partial"} if schema in {"kavita-ingest-publication-v3", "kavita-ingest-publication-v4"} else {"completed"}
            recovery_consistent = (
                schema in {"kavita-ingest-publication-v3", "kavita-ingest-publication-v4"}
                and data.get("status") == "partial"
                and data.get("recovery_required") is True
            ) or (
                data.get("status") == "completed"
                and not data.get("recovery_required")
            )
            if not (data.get("status") in accepted_statuses and recovery_consistent and data.get("approved_apply") is True and data.get("source_lifecycle") in accepted_lifecycle and data.get("verification_completed") is True):
                raise ValueError("not a completed verified preserve-source APPLY")
            for index, item in enumerate(data.get("items", []), 1):
                if not isinstance(item, dict): raise ValueError("invalid item")
                source = _absolute_clean(item.get("source"))
                destination = _absolute_clean(item.get("destination"))
                if source is None or destination is None:
                    raise ValueError("item lacks safe paths")
                routed = _kavita_category(config, source, destination)
                _validate_reported_roots(item, routed)
                if routed != category:
                    continue
                if schema in {"kavita-ingest-publication-v3", "kavita-ingest-publication-v4"}:
                    state = item.get("item_state")
                    eligible = item.get("cleanup_eligible")
                    if state != "complete" or eligible is not True:
                        if eligible is True:
                            raise ValueError("incomplete item is marked cleanup eligible")
                        continue
                if schema in {"kavita-ingest-publication-v2", "kavita-ingest-publication-v3", "kavita-ingest-publication-v4"}:
                    if item.get("source_lifecycle") != "preserved":
                        continue
                    if item.get("action") not in {"published", "verified-existing-duplicate"}:
                        raise ValueError("item has unsupported action")
                sh, dh = item.get("source_sha256"), item.get("destination_sha256")
                if not all(isinstance(x, str) and len(x) == 64 for x in (sh, dh)):
                    raise ValueError("item lacks safe hashes")
                records.append(
                    Evidence(
                        source=source,
                        destination=destination,
                        adapter="kavita",
                        report=report,
                        report_id=f"{report}:{index}",
                        source_sha256=sh,
                        destination_sha256=dh,
                        transformed=bool(item.get("transformations")),
                        producer=data.get("producer")
                        if isinstance(data.get("producer"), str)
                        else None,
                        schema=str(schema),
                        machine_identity=data.get("producer_instance_id")
                        if isinstance(data.get("producer_instance_id"), str)
                        else None,
                        completion_status=str(data.get("status")),
                        report_sha256=report_hash,
                        report_identity=report_identity,
                    )
                )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            rejected.append(RejectedReport(report, str(exc)))
    reconciled, supersession_rejected = _apply_kavita_supersessions(
        config, category, records
    )
    return reconciled, [*rejected, *supersession_rejected]


def _apply_kavita_supersessions(
    config: Config,
    category: Category,
    records: list[Evidence],
) -> tuple[list[Evidence], list[RejectedReport]]:
    root = config.kavita_state_root
    if root is None:
        return records, []
    report_root = root / "supersession-reports"
    if not report_root.is_dir() or report_root.is_symlink():
        return records, []
    output = list(records)
    rejected: list[RejectedReport] = []
    for report in sorted(report_root.glob("*.json")):
        try:
            text, report_hash, report_identity = _read_report(report, root)
            data = json.loads(text)
            if (
                not isinstance(data, dict)
                or data.get("report_schema") != "kavita-ingest-supersession-v1"
                or data.get("state") != "complete"
            ):
                raise ValueError("unsupported or incomplete Kavita supersession report")
            items = data.get("items")
            if not isinstance(items, list) or not items:
                raise ValueError("Kavita supersession report has no items")
            candidate = list(output)
            for item in items:
                if not isinstance(item, dict):
                    raise TypeError("invalid supersession item")
                source = _absolute_clean(item.get("source"))
                old = _absolute_clean(item.get("old_destination"))
                new = _absolute_clean(item.get("canonical_destination"))
                archived = _absolute_clean(item.get("archive"))
                hashes = (
                    item.get("source_sha256"),
                    item.get("old_destination_sha256"),
                    item.get("canonical_destination_sha256"),
                )
                if None in {source, old, new, archived} or not all(
                    isinstance(value, str)
                    and len(value) == 64
                    and all(character in "0123456789abcdef" for character in value.casefold())
                    for value in hashes
                ):
                    raise ValueError("supersession item lacks safe paths or hashes")
                assert source is not None and old is not None and new is not None
                assert archived is not None
                if not source.is_relative_to(category.ingest_root):
                    continue
                if old == new:
                    raise ValueError("supersession old and canonical paths are identical")
                if not old.is_relative_to(category.production_root) or not new.is_relative_to(
                    category.production_root
                ):
                    raise ValueError("supersession paths do not match configured category roots")
                if archived.is_relative_to(category.ingest_root) or archived.is_relative_to(
                    category.production_root
                ):
                    raise ValueError("supersession archive is inside a monitored root")
                _regular_endpoint(archived, "supersession archive")
                _regular_endpoint(new, "canonical supersession destination")
                old_matches = [
                    index
                    for index, value in enumerate(candidate)
                    if value.active
                    and value.source == source
                    and value.destination == old
                    and value.source_sha256 == hashes[0]
                    and value.destination_sha256 == hashes[1]
                ]
                new_matches = [
                    value
                    for value in candidate
                    if value.active
                    and value.source == source
                    and value.destination == new
                    and value.source_sha256 == hashes[0]
                    and value.destination_sha256 == hashes[2]
                ]
                if not old_matches or not new_matches:
                    raise ValueError("supersession does not bind accepted old and new provenance")
                for index in old_matches:
                    candidate[index] = replace(
                        candidate[index],
                        active=False,
                        archived_destination=archived,
                        archived_sha256=str(hashes[1]),
                        superseded_by=new,
                        supersession_report=report,
                        supersession_report_sha256=report_hash,
                        supersession_report_identity=report_identity,
                    )
            output = candidate
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            rejected.append(RejectedReport(report, str(exc)))
    return output, rejected


def _regular_endpoint(path: Path, label: str) -> None:
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode) or value.st_nlink != 1:
        raise ValueError(f"{label} is not a regular single-link file")


def _kavita_category(config: Config, source: Path, destination: Path) -> Category:
    categories = tuple(item for item in config.categories if item.adapter == "kavita")
    source_matches = tuple(item for item in categories if source.is_relative_to(item.ingest_root))
    destination_matches = tuple(
        item for item in categories if destination.is_relative_to(item.production_root)
    )
    matches = tuple(item for item in source_matches if item in destination_matches)
    if len(matches) == 1:
        return matches[0]
    if source_matches or destination_matches:
        raise ValueError("item source and destination cross configured Kavita category roots")
    raise ValueError("item paths do not match any configured Kavita category roots")


def _validate_reported_roots(item: dict[str, object], category: Category) -> None:
    present = {key for key in ("source_root", "library_root") if key in item}
    if not present:
        return
    if present != {"source_root", "library_root"}:
        raise ValueError("item has incomplete reported category roots")
    source_root = _absolute_clean(item.get("source_root"))
    library_root = _absolute_clean(item.get("library_root"))
    if source_root != category.ingest_root or library_root != category.production_root:
        raise ValueError("item reported roots do not match configured category roots")


def collect(config: Config, category: Category) -> tuple[list[Evidence], list[RejectedReport]]:
    if category.adapter == "video": return video_records(config, category)
    if category.adapter == "music": return music_records(config, category)
    if category.adapter == "kavita": return kavita_records(config, category)
    return [], []
