from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = "ingest-cleanup-independent-backup-v1"
MAX_AGE = timedelta(days=14)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(4 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def create_backup_proof(
    source: Path,
    publication: Path,
    backup_object: Path,
    expected_uuid: str,
    proof_root: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    source = _regular(source, "Incoming source")
    publication = _regular(publication, "published destination")
    backup_candidate = backup_object.expanduser().absolute()
    filesystem = _mount_identity(backup_candidate, runner)
    actual_uuid = str(filesystem.get("uuid") or "")
    mount_target = Path(str(filesystem.get("target") or ""))
    if actual_uuid != expected_uuid:
        raise ValueError("backup filesystem UUID does not match the expected independent disk")
    source_filesystem = _mount_identity(source, runner)
    source_uuid = str(source_filesystem.get("uuid") or "")
    if source_uuid and source_uuid == actual_uuid:
        raise ValueError("backup object is on the same filesystem as the Incoming source")
    backup_object = _regular(backup_candidate, "backup object")
    if not mount_target.is_absolute() or not backup_object.is_relative_to(
        mount_target.resolve(strict=True)
    ):
        raise ValueError("backup object is not beneath the verified mount target")
    source_hash = sha256_file(source)
    backup_hash = sha256_file(backup_object)
    if source_hash != backup_hash:
        raise ValueError(
            "backup object is not an exact copy of the Incoming source; "
            "a transformed publication backup is insufficient"
        )
    publication_hash = sha256_file(publication)
    verified_at = datetime.now(UTC)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "verified_at": verified_at.isoformat(),
        "source": str(source),
        "source_identity": _identity(source),
        "source_sha256": source_hash,
        "publication": str(publication),
        "publication_identity": _identity(publication),
        "publication_sha256": publication_hash,
        "publication_byte_relation": (
            "exact-copy" if publication_hash == source_hash else "transformed"
        ),
        "backup_object": str(backup_object),
        "backup_object_identity": _identity(backup_object),
        "backup_object_sha256": backup_hash,
        "storage_uuid": actual_uuid,
        "storage_source": str(filesystem.get("source") or ""),
        "mount_target": str(mount_target),
        "mount_options": str(filesystem.get("options") or ""),
        "evidence_source": "findmnt UUID identity plus SHA-256 endpoint verification",
    }
    payload["integrity_sha256"] = _digest(payload)
    _private_directory(proof_root)
    prefix = hashlib.sha256(f"{source}\0{source_hash}".encode()).hexdigest()
    name = prefix + "-" + verified_at.strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    target = proof_root / name
    _write_private(target, payload)
    return target


def _mount_identity(
    target: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    result = runner(
        [
            "findmnt",
            "--json",
            "--target",
            str(target),
            "--output",
            "TARGET,SOURCE,UUID,OPTIONS",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise ValueError("backup filesystem is not mounted or cannot be identified")
    try:
        filesystems = json.loads(result.stdout).get("filesystems", [])
        filesystem = filesystems[0]
        if not isinstance(filesystem, dict):
            raise TypeError
    except (AttributeError, IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("findmnt returned invalid backup identity data") from exc
    return filesystem


def find_backup_proof(
    proof_root: Path | None,
    *,
    source: Path,
    source_sha256: str,
    publication: Path,
    publication_sha256: str,
    now: datetime | None = None,
) -> tuple[dict[str, Any] | None, str]:
    if proof_root is None or not proof_root.is_dir() or proof_root.is_symlink():
        return None, "independent per-file backup proof is unavailable"
    prefix = hashlib.sha256(f"{source}\0{source_sha256}".encode()).hexdigest()
    candidates = sorted(proof_root.glob(f"{prefix}-*.json"), reverse=True)
    if not candidates:
        return None, "independent per-file backup proof is unavailable"
    target = candidates[0]
    try:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("backup proof is not a private regular file")
        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
            raise ValueError("backup proof schema is unsupported")
        integrity = payload.pop("integrity_sha256", None)
        actual = _digest(payload)
        payload["integrity_sha256"] = integrity
        if not isinstance(integrity, str) or not secrets.compare_digest(integrity, actual):
            raise ValueError("backup proof integrity check failed")
        if (
            payload.get("source") != str(source)
            or payload.get("source_sha256") != source_sha256
            or payload.get("backup_object_sha256") != source_sha256
            or payload.get("publication") != str(publication)
            or payload.get("publication_sha256") != publication_sha256
            or payload.get("source_identity") != _identity(source)
            or payload.get("publication_identity") != _identity(publication)
        ):
            raise ValueError("backup proof does not bind the current source and publication")
        verified_at = datetime.fromisoformat(str(payload.get("verified_at")))
        if verified_at.tzinfo is None:
            raise ValueError("backup proof timestamp has no timezone")
        current_time = now or datetime.now(UTC)
        age = current_time - verified_at.astimezone(UTC)
        if age < -timedelta(minutes=5):
            raise ValueError("backup proof timestamp is in the future")
        if age > MAX_AGE:
            raise ValueError("backup proof is stale")
        payload["proof_file"] = str(target)
        return payload, "exact Incoming bytes have recent independent backup proof"
    except FileNotFoundError:
        return None, "independent per-file backup proof is unavailable"
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return None, str(exc)


def _regular(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    info = path.expanduser().lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"{label} must be a regular non-symlink single-link file")
    return resolved


def _identity(path: Path) -> dict[str, int]:
    value = path.stat()
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "size": value.st_size,
        "links": value.st_nlink,
    }


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("backup proof root must be a real directory")
    os.chmod(path, 0o700)


def _digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write_private(path: Path, payload: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
