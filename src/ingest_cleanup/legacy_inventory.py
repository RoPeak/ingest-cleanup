"""Explicit, machine-bound trust inventory for legacy producer reports."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from datetime import UTC, datetime
from pathlib import Path
from .config import Config
from .provenance import machine_instance_id

SCHEMA = "ingest-cleanup-trusted-legacy-reports-v1"


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _integrity(payload: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _identity(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
        "links": value.st_nlink,
    }


def _read_regular(path: Path) -> tuple[bytes, str, dict[str, int]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("not a regular single-link file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read()
            after = os.fstat(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    before_identity = _identity(before)
    if before_identity != _identity(after) or before_identity != _identity(path.lstat()):
        raise ValueError("file changed while being read")
    return payload, hashlib.sha256(payload).hexdigest(), before_identity


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False


def _legacy_descriptor(config: Config, path: Path) -> dict[str, object]:
    """Describe a report eligible for explicit legacy operator trust.

    This does not accept publication provenance. The normal adapters remain the
    sole parser/validator before a trusted entry can become Evidence.
    """
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("legacy report path must be an absolute non-symlink file")
    payload, digest, identity = _read_regular(path)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("legacy report is not valid UTF-8") from exc
    try:
        music = json.loads(text)
    except json.JSONDecodeError:
        music = None

    for root in config.video_state_roots:
        if not _inside(path, root):
            continue
        try:
            first = next(line for line in text.splitlines() if line.strip())
            header = json.loads(first)
        except (StopIteration, json.JSONDecodeError) as exc:
            raise ValueError("legacy video report has no JSON Lines header") from exc
        version = header.get("version") if isinstance(header, dict) else None
        if version in {1, 2, 3}:
            return {
                "path": str(path.resolve(strict=True)),
                "adapter": "video",
                "schema": f"video-jsonl-v{version}",
                "sha256": digest,
                "identity": identity,
            }
        raise ValueError("report is not a supported legacy video schema")

    if config.music_state_root and _inside(path, config.music_state_root):
        if not isinstance(music, dict):
            raise ValueError("legacy music report is not a JSON object")
        schema = music.get("report_schema")
        if schema in {"music-ingest-publication-v1", "music-ingest-publication-v2"}:
            return {
                "path": str(path.resolve(strict=True)),
                "adapter": "music",
                "schema": schema,
                "sha256": digest,
                "identity": identity,
            }
        raise ValueError("report is not a supported legacy music schema")

    if config.kavita_state_root and _inside(path, config.kavita_state_root):
        if not isinstance(music, dict):
            raise ValueError("legacy Kavita report is not a JSON object")
        schema = music.get("report_schema")
        if schema in {
            "kavita-ingest-publication-v1",
            "kavita-ingest-publication-v2",
            "kavita-ingest-publication-v3",
        }:
            return {
                "path": str(path.resolve(strict=True)),
                "adapter": "kavita",
                "schema": schema,
                "sha256": digest,
                "identity": identity,
            }
        raise ValueError("report is not a supported legacy Kavita schema")
    raise ValueError("legacy report is outside configured producer state roots")


def _load(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("legacy inventory is unreadable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError("legacy inventory is not a private regular file")
    try:
        content, _, identity = _read_regular(path)
        if identity != _identity(info):
            raise ValueError("legacy inventory changed while being read")
        raw = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("legacy inventory is unreadable") from exc
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        raise ValueError("legacy inventory schema is unsupported")
    integrity = raw.pop("integrity_sha256", None)
    expected = _integrity(raw)
    raw["integrity_sha256"] = integrity
    if not isinstance(integrity, str) or not secrets.compare_digest(integrity, expected):
        raise ValueError("legacy inventory integrity check failed")
    if raw.get("machine_instance_id") != machine_instance_id():
        raise ValueError("legacy inventory belongs to a different machine")
    reports = raw.get("reports")
    if not isinstance(reports, list) or not reports:
        raise ValueError("legacy inventory has no trusted reports")
    paths = [entry.get("path") for entry in reports if isinstance(entry, dict)]
    if len(paths) != len(reports) or len(set(paths)) != len(paths):
        raise ValueError("legacy inventory has invalid or duplicate report paths")
    return raw


def inventory_status(config: Config) -> dict[str, object]:
    path = config.legacy_inventory_path
    if path is None:
        return {
            "state": "missing",
            "path": str(path) if path else None,
            "trusted_reports": 0,
        }
    try:
        payload = _load(path)
    except ValueError as exc:
        return {"state": "invalid", "path": str(path), "reason": str(exc)}
    if payload is None:
        return {"state": "missing", "path": str(path), "trusted_reports": 0}
    reports = payload["reports"]
    assert isinstance(reports, list)
    return {
        "state": "valid",
        "path": str(path),
        "trusted_reports": len(reports),
        "created_at": payload.get("created_at"),
    }


def is_trusted(
    config: Config,
    *,
    report: Path,
    adapter: str,
    schema: str,
    sha256: str,
    identity: object,
) -> bool:
    payload = _load(config.legacy_inventory_path)
    if payload is None:
        return False
    expected_identity = _identity_payload(identity)
    for entry in payload["reports"]:  # type: ignore[index]
        if not isinstance(entry, dict):
            raise ValueError("legacy inventory contains an invalid report entry")
        if (
            entry.get("path") == str(report.resolve(strict=True))
            and entry.get("adapter") == adapter
            and entry.get("schema") == schema
            and entry.get("sha256") == sha256
            and entry.get("identity") == expected_identity
        ):
            return True
    return False


def _identity_payload(identity: object) -> dict[str, int]:
    try:
        return {
            "device": int(getattr(identity, "device")),
            "inode": int(getattr(identity, "inode")),
            "size": int(getattr(identity, "size")),
            "mtime_ns": int(getattr(identity, "mtime_ns")),
            "ctime_ns": int(getattr(identity, "ctime_ns")),
            "links": int(getattr(identity, "links")),
        }
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("legacy report identity is invalid") from exc


def create_inventory(
    config: Config,
    reports: list[Path],
    *,
    target: Path | None = None,
) -> Path:
    if not reports:
        raise ValueError("at least one legacy report must be explicitly selected")
    target = target or config.legacy_inventory_path
    if target is None or not target.is_absolute():
        raise ValueError("legacy inventory target must be an absolute path")
    if target.exists() or target.is_symlink():
        raise ValueError("legacy inventory already exists; refusing to overwrite it")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.parent.is_symlink():
        raise ValueError("legacy inventory directory is unsafe")
    entries = [_legacy_descriptor(config, path) for path in reports]
    paths = [entry["path"] for entry in entries]
    if len(set(paths)) != len(paths):
        raise ValueError("legacy report selection contains duplicates")
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "created_at": datetime.now(UTC).isoformat(),
        "machine_instance_id": machine_instance_id(),
        "reports": sorted(entries, key=lambda entry: str(entry["path"])),
    }
    payload["integrity_sha256"] = _integrity(payload)
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(target, 0o400)
    if hasattr(os, "O_DIRECTORY"):
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return target
