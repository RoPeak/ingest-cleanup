from __future__ import annotations

import hashlib
from pathlib import Path


def machine_instance_id() -> str:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return hashlib.sha256(f"ingestion-suite\0{value}".encode()).hexdigest()
    raise ValueError("no stable machine identity is available for publication provenance")


def require_local_producer(payload: dict[str, object], producer: str) -> None:
    if payload.get("producer") != producer:
        raise ValueError("report producer identity is invalid")
    version = payload.get("producer_version")
    if not isinstance(version, str) or not version:
        raise ValueError("report producer version is missing")
    instance = payload.get("producer_instance_id")
    if not isinstance(instance, str) or instance != machine_instance_id():
        raise ValueError("report belongs to a different machine instance")
