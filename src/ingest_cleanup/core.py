from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
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
            results.append(Assessment(category.name, source, None, "UNKNOWN", str(exc))); continue
        evidence_list = by_source.get(source)
        if not evidence_list:
            results.append(Assessment(category.name, source, None, "UNKNOWN", "insufficient proof", size=source_id.size, source_identity=source_id)); continue
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
            results.append(Assessment(category.name, source, None, "UNKNOWN", "multiple currently valid source provenance mappings", size=source_id.size, source_identity=source_id)); continue
        if not viable_by_destination:
            evidence, reason = stale[0]
            results.append(Assessment(category.name, source, evidence.destination, "REVIEW", reason, evidence, source_id.size, source_id)); continue
        evidence = next(iter(viable_by_destination.values()))
        destination_id = _identity(evidence.destination)
        if not hash_files:
            suffix = f"; ignored {len(stale)} stale provenance mapping(s)" if stale else ""
            results.append(Assessment(category.name, source, evidence.destination, "CANDIDATE", f"provenance and size checks passed; hash verification required{suffix}", evidence, source_id.size, source_id)); continue
        try:
            source_hash, source_id = _hash(source, progress)
            destination_hash, _ = _hash(evidence.destination, progress)
            if evidence.source_sha256 and source_hash != evidence.source_sha256:
                results.append(Assessment(category.name, source, evidence.destination, "REVIEW", "source differs from recorded publication input", evidence, source_id.size, source_id)); continue
            if evidence.destination_sha256 and destination_hash != evidence.destination_sha256:
                results.append(Assessment(category.name, source, evidence.destination, "REVIEW", "destination differs from recorded publication output", evidence, source_id.size, source_id)); continue
            if not evidence.transformed and source_hash != destination_hash:
                results.append(Assessment(category.name, source, evidence.destination, "REVIEW", "content mismatch", evidence, source_id.size, source_id)); continue
            results.append(Assessment(category.name, source, evidence.destination, "SAFE", "production copy verified", evidence, source_id.size, source_id, source_hash))
        except (OSError, ValueError) as exc:
            results.append(Assessment(category.name, source, evidence.destination, "REVIEW", str(exc), evidence, source_id.size, source_id))
    return results, rejected


def assess(config: Config, progress: Callable[[Path, int, int], None] | None = None, *, hash_files: bool = True) -> tuple[list[Assessment], list[RejectedReport]]:
    outcomes: list[Assessment] = []; rejected: list[RejectedReport] = []
    for category in config.categories:
        outcome, bad = assess_category(config, category, progress, hash_files=hash_files)
        outcomes.extend(outcome); rejected.extend(bad)
    return outcomes, rejected


def _prune_empty(source: Path, root: Path) -> list[str]:
    pruned: list[str] = []
    current = source.parent
    while current != root:
        try:
            if current.is_symlink() or not _inside(current, root): break
            current.rmdir(); pruned.append(str(current)); current = current.parent
        except OSError: break
    return pruned


def apply_deletions(items: list[Assessment], roots: dict[str, Path]) -> dict[str, object]:
    report: dict[str, object] = {"timestamp": datetime.now(UTC).isoformat(), "items": [], "directories_pruned": []}
    pruned: list[str] = []
    for item in items:
        entry = {"source": str(item.source), "destination": str(item.destination), "provenance": item.evidence.report_id if item.evidence else None, "source_size": item.size, "destination_size": item.size, "sha256": item.sha256, "result": "skipped"}
        try:
            if item.state != "SAFE" or item.source_identity is None: raise ValueError("not freshly verified")
            if _identity(item.source) != item.source_identity: raise ValueError("source changed after verification")
            item.source.unlink()
            entry["result"] = "deleted"
            pruned.extend(_prune_empty(item.source, roots[item.category]))
        except (OSError, ValueError) as exc: entry["reason"] = str(exc)
        report["items"].append(entry)
    report["directories_pruned"] = pruned
    return report


def write_audit(payload: dict[str, object]) -> Path:
    folder = xdg_state() / "reports"; folder.mkdir(parents=True, exist_ok=True)
    target = folder / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".json")
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
