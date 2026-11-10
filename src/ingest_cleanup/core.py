from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

from .adapters import Evidence, RejectedReport, collect
from .config import Category, Config, xdg_state

CHUNK_SIZE = 4 * 1024 * 1024


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    links: int


@dataclass(frozen=True)
class Assessment:
    category: str
    source: Path
    destination: Path | None
    state: str
    reason: str
    evidence: Evidence | None = None
    size: int = 0
    source_identity: Identity | None = None
    sha256: str | None = None
    reason_code: str = ""
    destination_identity: Identity | None = None
    destination_sha256: str | None = None
    evidence_identifier: str | None = None


REASON_CODES = {
    "insufficient proof": "NO_ACCEPTED_REPORT",
    "published destination missing": "DESTINATION_MISSING",
    "ambiguous": "AMBIGUOUS_MAPPING",
    "multiple currently valid": "AMBIGUOUS_MAPPING",
    "size mismatch": "SIZE_MISMATCH",
    "content mismatch": "HASH_MISMATCH",
    "differs from recorded": "HASH_MISMATCH",
    "unsafe": "UNSAFE_PATH",
    "escapes configured": "UNSAFE_PATH",
    "hardlink": "UNSAFE_PATH",
    "symlink": "UNSAFE_PATH",
}


def reason_code(reason: str) -> str:
    lowered = reason.casefold()
    return next((code for fragment, code in REASON_CODES.items() if fragment in lowered), "REPORT_REJECTED")


def _identity(path: Path) -> Identity:
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode):
        raise ValueError("not a regular non-symlink file")
    return Identity(value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=False).is_relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False


def _hash(path: Path, progress: Callable[[Path, int, int], None] | None = None) -> tuple[str, Identity]:
    before = _identity(path)
    digest = hashlib.sha256()
    completed = 0
    with path.open("rb", buffering=CHUNK_SIZE) as handle:
        while block := handle.read(CHUNK_SIZE):
            digest.update(block); completed += len(block)
            if progress: progress(path, completed, before.size)
    after = _identity(path)
    if before != after:
        raise ValueError("file changed while hashing")
    return digest.hexdigest(), before


def _mapping_viability_reason(
    evidence: Evidence,
    *,
    source_id: Identity,
    category: Category,
    by_destination: dict[Path, list[Evidence]],
) -> str | None:
    """Return why evidence cannot currently support a source/destination check.

    This is deliberately only a pre-hash eligibility screen. It is never
    proof that a reused source pathname is safe to delete; SHA-256 comparison
    remains mandatory in ``verify`` and ``apply``.
    """
    destination_records = by_destination.get(evidence.destination, [])
    for other in destination_records:
        if other.source == evidence.source:
            continue
        try:
            if _inside(other.source, category.ingest_root) and _identity(other.source).links == 1:
                return "ambiguous destination provenance with another current source"
        except (OSError, ValueError):
            # Historical reports whose source is absent or unsafe cannot prove
            # anything about this current source-path reuse.
            continue
    if not _inside(evidence.destination, category.production_root):
        return "published destination outside expected production root"
    try:
        destination_id = _identity(evidence.destination)
        if destination_id.links != 1:
            return "published destination unsafe: destination has hardlink count other than one"
    except FileNotFoundError:
        return "published destination missing"
    except ValueError as exc:
        return f"published destination unsafe: {exc}"
    except OSError as exc:
        return f"published destination unavailable: {exc}"
    if not evidence.transformed and source_id.size != destination_id.size:
        return "size mismatch"
    return None


def _files(root: Path):
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        names[:] = [
            name for name in names
            if not (directory_path / name).is_symlink()
            and name.casefold() != "__macosx"
        ]
        for name in files:
            candidate = directory_path / name
            if candidate.is_symlink():
                continue
            lowered = name.casefold()
            if lowered.startswith("._") or lowered in {".ds_store", "thumbs.db", "desktop.ini"}:
                continue
            yield candidate


def _repair_manifest(
    category: Category,
    path: Path,
    identity: Identity,
    progress: Callable[[Path, int, int], None] | None,
    *,
    hash_files: bool,
) -> Assessment | None:
    if category.adapter != "kavita" or not path.name.casefold().endswith(".repair.json"):
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("report_schema") != "kavita-ingest-epub-repair-v1":
            raise ValueError("unsupported repair provenance schema")
        source = Path(str(payload.get("source")))
        output = Path(str(payload.get("output")))
        expected_output = path.with_name(path.name[: -len(".repair.json")])
        if (
            not source.is_absolute()
            or not output.is_absolute()
            or not _inside(source, category.ingest_root)
            or not _inside(output, category.ingest_root)
            or output != expected_output
        ):
            raise ValueError("repair provenance paths are inconsistent or unsafe")
        source_hash = payload.get("source_sha256")
        output_hash = payload.get("output_sha256")
        if not all(
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value.casefold())
            for value in (source_hash, output_hash)
        ):
            raise ValueError("repair provenance hashes are invalid")
        if hash_files:
            actual_source, _ = _hash(source, progress)
            actual_output, _ = _hash(output, progress)
            if actual_source != source_hash or actual_output != output_hash:
                raise ValueError("repair provenance endpoint differs from recorded hash")
        return Assessment(
            category.name,
            path,
            output,
            "PROVENANCE",
            "retained EPUB repair provenance manifest; never deletion-ready",
            size=identity.size,
            source_identity=identity,
            reason_code="REPAIR_PROVENANCE",
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return Assessment(
            category.name,
            path,
            None,
            "UNKNOWN",
            f"invalid repair provenance: {exc}",
            size=identity.size,
            source_identity=identity,
            reason_code="REPAIR_PROVENANCE_INVALID",
        )


def assess_category(config: Config, category: Category, progress: Callable[[Path, int, int], None] | None = None, *, hash_files: bool = True) -> tuple[list[Assessment], list[RejectedReport]]:
    records, rejected = collect(config, category)
    by_source: dict[Path, list[Evidence]] = {}
    by_destination: dict[Path, list[Evidence]] = {}
    for evidence in records:
        by_source.setdefault(evidence.source, []).append(evidence)
        by_destination.setdefault(evidence.destination, []).append(evidence)
    results: list[Assessment] = []
    for source in _files(category.ingest_root):
        try:
            if not _inside(source, category.ingest_root): raise ValueError("source escapes configured ingest root")
            source_id = _identity(source)
            if source_id.links != 1: raise ValueError("source has hardlink count other than one")
        except (OSError, ValueError) as exc:
            text = str(exc); results.append(Assessment(category.name, source, None, "UNKNOWN", text, reason_code=reason_code(text))); continue
        repair = _repair_manifest(
            category,
            source,
            source_id,
            progress,
            hash_files=hash_files,
        )
        if repair is not None:
            results.append(repair)
            continue
        evidence_list = by_source.get(source)
        if not evidence_list:
            results.append(Assessment(category.name, source, None, "UNKNOWN", "insufficient proof", size=source_id.size, source_identity=source_id, reason_code="NO_ACCEPTED_REPORT")); continue
        viable_by_destination: dict[Path, Evidence] = {}
        stale: list[tuple[Evidence, str]] = []
        for evidence in evidence_list:
            reason = _mapping_viability_reason(
                evidence,
                source_id=source_id,
                category=category,
                by_destination=by_destination,
            )
            if reason is None:
                # Repeated reports for the same current source/destination do
                # not create a conflicting mapping; deduplicate only after
                # each record has passed the current-filesystem checks.
                viable_by_destination.setdefault(evidence.destination, evidence)
            else:
                stale.append((evidence, reason))
        if len(viable_by_destination) > 1:
            text = "multiple currently valid source provenance mappings"; results.append(Assessment(category.name, source, None, "UNKNOWN", text, size=source_id.size, source_identity=source_id, reason_code="AMBIGUOUS_MAPPING")); continue
        if not viable_by_destination:
            evidence, reason = stale[0]
            results.append(Assessment(category.name, source, evidence.destination, "REVIEW", reason, evidence, source_id.size, source_id, reason_code=reason_code(reason))); continue
        evidence = next(iter(viable_by_destination.values()))
        destination_id = _identity(evidence.destination)
        if not hash_files:
            suffix = f"; ignored {len(stale)} stale provenance mapping(s)" if stale else ""
            results.append(Assessment(category.name, source, evidence.destination, "CANDIDATE", f"provenance and size checks passed; hash verification required{suffix}", evidence, source_id.size, source_id, reason_code="HASH_REQUIRED", destination_identity=destination_id)); continue
        try:
            source_hash, source_id = _hash(source, progress)
            destination_hash, destination_id = _hash(evidence.destination, progress)
            if evidence.source_sha256 and source_hash != evidence.source_sha256:
                results.append(Assessment(category.name, source, evidence.destination, "REVIEW", "source differs from recorded publication input", evidence, source_id.size, source_id, reason_code="HASH_MISMATCH")); continue
            if evidence.destination_sha256 and destination_hash != evidence.destination_sha256:
                results.append(Assessment(category.name, source, evidence.destination, "REVIEW", "destination differs from recorded publication output", evidence, source_id.size, source_id, reason_code="HASH_MISMATCH")); continue
            if not evidence.transformed and source_hash != destination_hash:
                results.append(Assessment(category.name, source, evidence.destination, "REVIEW", "content mismatch", evidence, source_id.size, source_id, reason_code="HASH_MISMATCH")); continue
            if category.adapter == "kavita":
                results.append(Assessment(
                    category.name,
                    source,
                    evidence.destination,
                    "BACKUP_REQUIRED",
                    "production copy verified; independent per-file backup proof is unavailable",
                    evidence,
                    source_id.size,
                    source_id,
                    source_hash,
                    "INDEPENDENT_BACKUP_REQUIRED",
                    destination_id,
                    destination_hash,
                ))
            else:
                results.append(Assessment(category.name, source, evidence.destination, "SAFE", "production copy verified", evidence, source_id.size, source_id, source_hash, "VERIFIED", destination_id, destination_hash))
        except (OSError, ValueError) as exc:
            text = str(exc); results.append(Assessment(category.name, source, evidence.destination, "REVIEW", text, evidence, source_id.size, source_id, reason_code=reason_code(text)))
    return results, rejected


def assess(config: Config, progress: Callable[[Path, int, int], None] | None = None, *, hash_files: bool = True) -> tuple[list[Assessment], list[RejectedReport]]:
    outcomes: list[Assessment] = []; rejected: list[RejectedReport] = []
    for category in config.categories:
        outcome, bad = assess_category(config, category, progress, hash_files=hash_files)
        outcomes.extend(outcome); rejected.extend(bad)
    unique_rejected = list({(item.path, item.reason): item for item in rejected}.values())
    return outcomes, unique_rejected


def _prune_empty(source: Path, root: Path) -> list[str]:
    pruned: list[str] = []
    current = source.parent
    while current != root:
        try:
            if current.is_symlink() or not _inside(current, root): break
            current.rmdir(); pruned.append(str(current)); current = current.parent
        except OSError: break
    return pruned


def config_fingerprint(config: Config) -> str:
    payload = {
        "categories": [{"name": c.name, "ingest_root": str(c.ingest_root.resolve()), "production_root": str(c.production_root.resolve()), "adapter": c.adapter} for c in config.categories],
        "video_state_roots": [str(p.resolve(strict=False)) for p in config.video_state_roots],
        "music_state_root": str(config.music_state_root.resolve(strict=False)) if config.music_state_root else None,
        "kavita_state_root": str(config.kavita_state_root.resolve(strict=False)) if config.kavita_state_root else None,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def create_verification_plan(config: Config, items: list[Assessment]) -> tuple[str, Path]:
    if not items or any(item.state != "SAFE" for item in items):
        raise ValueError("verification plans require at least one deletion-ready item")
    now = datetime.now(UTC)
    plan_id = now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    folder = xdg_state() / "plans"; folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(folder, 0o700)
    target = folder / f"{plan_id}.json"
    payload = {
        "schema": "verification-plan-v1", "plan_id": plan_id,
        "created_at": now.isoformat(), "expires_at": (now + timedelta(hours=24)).isoformat(),
        "configuration_fingerprint": config_fingerprint(config),
        "items": [{
            "category": item.category, "source": str(item.source), "destination": str(item.destination),
            "source_size": item.size, "destination_size": item.destination_identity.size if item.destination_identity else None,
            "source_identity": asdict(item.source_identity) if item.source_identity else None,
            "destination_identity": asdict(item.destination_identity) if item.destination_identity else None,
            "source_sha256": item.sha256, "destination_sha256": item.destination_sha256,
            "evidence_identifier": item.evidence.report_id if item.evidence else item.evidence_identifier,
        } for item in items],
    }
    payload["integrity_sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data); handle.flush(); os.fsync(handle.fileno())
    os.chmod(target, 0o400)
    return plan_id, target


def load_verification_plan(config: Config, plan_id: str) -> tuple[dict[str, object], Path]:
    if not plan_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in plan_id):
        raise ValueError("invalid plan identifier")
    target = xdg_state() / "plans" / f"{plan_id}.json"
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("plan is not a private regular file")
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != "verification-plan-v1" or payload.get("plan_id") != plan_id:
        raise ValueError("unsupported or tampered verification plan")
    integrity = payload.pop("integrity_sha256", None)
    expected_integrity = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    payload["integrity_sha256"] = integrity
    if not isinstance(integrity, str) or not secrets.compare_digest(integrity, expected_integrity):
        raise ValueError("verification plan integrity check failed")
    if payload.get("configuration_fingerprint") != config_fingerprint(config):
        raise ValueError("verification plan configuration does not match")
    expires = datetime.fromisoformat(str(payload.get("expires_at")))
    if expires.tzinfo is None or datetime.now(UTC) >= expires:
        raise ValueError("verification plan has expired")
    if not isinstance(payload.get("items"), list):
        raise ValueError("verification plan items are invalid")
    return payload, target


def verify_saved_plan(config: Config, payload: dict[str, object], progress: Callable[[Path, int, int], None] | None = None) -> list[Assessment]:
    categories = {c.name: c for c in config.categories}
    verified: list[Assessment] = []
    for raw in payload["items"]:  # type: ignore[index]
        if not isinstance(raw, dict) or raw.get("category") not in categories:
            raise ValueError("plan contains an unknown category")
        category = categories[str(raw["category"])]
        source = Path(str(raw.get("source"))); destination = Path(str(raw.get("destination")))
        if not source.is_absolute() or not destination.is_absolute() or not _inside(source, category.ingest_root) or not _inside(destination, category.production_root):
            raise ValueError("plan contains an unsafe path")
        source_hash, source_id = _hash(source, progress); destination_hash, destination_id = _hash(destination, progress)
        if asdict(source_id) != raw.get("source_identity") or asdict(destination_id) != raw.get("destination_identity"):
            raise ValueError("planned endpoint identity changed")
        if source_hash != raw.get("source_sha256") or destination_hash != raw.get("destination_sha256"):
            raise ValueError("planned endpoint hash changed")
        if category.adapter == "kavita":
            verified.append(Assessment(
                category.name,
                source,
                destination,
                "BACKUP_REQUIRED",
                "saved endpoints reverified; independent per-file backup proof is unavailable",
                None,
                source_id.size,
                source_id,
                source_hash,
                "INDEPENDENT_BACKUP_REQUIRED",
                destination_id,
                destination_hash,
                str(raw.get("evidence_identifier")) if raw.get("evidence_identifier") else None,
            ))
        else:
            verified.append(Assessment(category.name, source, destination, "SAFE", "saved plan reverified", None, source_id.size, source_id, source_hash, "VERIFIED", destination_id, destination_hash, str(raw.get("evidence_identifier")) if raw.get("evidence_identifier") else None))
    return verified


def _atomic_write(target: Path, payload: dict[str, object]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)


def new_audit_path() -> Path:
    folder = xdg_state() / "reports"; folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return folder / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4) + ".json")


def _prevalidate(items: list[Assessment], progress: Callable[[Path, int, int], None] | None = None) -> None:
    for item in items:
        if item.state != "SAFE" or item.source_identity is None or item.destination_identity is None or item.destination is None:
            raise ValueError("batch contains an item that was not freshly verified")
        source_hash, source_id = _hash(item.source, progress); destination_hash, destination_id = _hash(item.destination, progress)
        if source_id != item.source_identity or destination_id != item.destination_identity or source_hash != item.sha256 or destination_hash != item.destination_sha256:
            raise ValueError(f"endpoint changed before deletion: {item.source}")


def apply_deletions(items: list[Assessment], roots: dict[str, Path], audit_path: Path | None = None, progress: Callable[[Path, int, int], None] | None = None) -> dict[str, object]:
    report: dict[str, object] = {"timestamp": datetime.now(UTC).isoformat(), "status": "pending", "items": [], "directories_pruned": []}
    audit_path = audit_path or new_audit_path(); _atomic_write(audit_path, report)
    pruned: list[str] = []
    try:
        _prevalidate(items, progress)
    except KeyboardInterrupt:
        report["status"] = "interrupted"; _atomic_write(audit_path, report); raise
    except (OSError, ValueError) as exc:
        report["status"] = "partial-failure"; report["error"] = str(exc); _atomic_write(audit_path, report); return report
    report["status"] = "running"; _atomic_write(audit_path, report)
    try:
        for item in items:
            entry = {"source": str(item.source), "destination": str(item.destination), "provenance": item.evidence.report_id if item.evidence else item.evidence_identifier, "source_size": item.size, "destination_size": item.destination_identity.size if item.destination_identity else None, "sha256": item.sha256, "result": "skipped"}
            try:
                if item.destination is None or _identity(item.source) != item.source_identity or _identity(item.destination) != item.destination_identity:
                    raise ValueError("source or destination changed after batch verification")
                item.source.unlink()
                entry["result"] = "deleted"
                pruned.extend(_prune_empty(item.source, roots[item.category]))
            except (OSError, ValueError) as exc:
                entry["reason"] = str(exc); report["items"].append(entry); report["status"] = "partial-failure"; report["directories_pruned"] = pruned; _atomic_write(audit_path, report); break
            report["items"].append(entry)
            report["directories_pruned"] = pruned; _atomic_write(audit_path, report)
        else:
            report["status"] = "completed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"; _atomic_write(audit_path, report); raise
    report["directories_pruned"] = pruned
    report["audit_path"] = str(audit_path); _atomic_write(audit_path, report)
    return report


def write_audit(payload: dict[str, object]) -> Path:
    target = new_audit_path()
    _atomic_write(target, payload)
    return target
