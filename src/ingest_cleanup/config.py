from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


def xdg_config() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ingest-cleanup" / "config.toml"


def xdg_state() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "ingest-cleanup"


def kavita_xdg_state() -> Path:
    """The producer's default state root, following its XDG contract.

    A Kavita category is itself the opt-in for this adapter.  The report root
    may still be overridden for a producer configured with a non-default
    database path, but it must never be guessed from a media directory.
    """
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "kavita-ingest"


@dataclass(frozen=True)
class Category:
    name: str
    ingest_root: Path
    production_root: Path
    adapter: str


@dataclass(frozen=True)
class Config:
    categories: tuple[Category, ...]
    video_state_roots: tuple[Path, ...]
    music_state_root: Path | None
    kavita_enabled: bool
    kavita_state_root: Path | None = None


def _path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    return path


def load(path: Path | None = None) -> Config:
    config_path = path or xdg_config()
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    raw_categories = raw.get("categories")
    if not isinstance(raw_categories, dict) or not raw_categories:
        raise ValueError("[categories] is required")
    categories: list[Category] = []
    for name, item in raw_categories.items():
        if not isinstance(name, str) or not isinstance(item, dict):
            raise ValueError("each category must be a TOML table")
        adapter = item.get("adapter", "disabled")
        if adapter not in {"video", "music", "kavita", "disabled"}:
            raise ValueError(f"categories.{name}.adapter is invalid")
        categories.append(Category(name, _path(item.get("ingest_root"), f"categories.{name}.ingest_root"), _path(item.get("production_root"), f"categories.{name}.production_root"), adapter))
    state = raw.get("state", {})
    if not isinstance(state, dict):
        raise ValueError("[state] must be a table")
    video = state.get("video_roots", [])
    if not isinstance(video, list):
        raise ValueError("state.video_roots must be an array")
    music = state.get("music_root")
    kavita_root = state.get("kavita_root")
    legacy_kavita = state.get("kavita_enabled")
    if legacy_kavita is not None and not isinstance(legacy_kavita, bool):
        raise ValueError("state.kavita_enabled must be boolean")
    # `kavita_enabled` was an obsolete second opt-in which caused the consumer
    # to disagree with a configured Kavita producer.  Keep accepting it so old
    # config files load, but category.adapter is now the sole opt-in.
    return Config(
        tuple(categories),
        tuple(_path(v, "state.video_roots item") for v in video),
        _path(music, "state.music_root") if music is not None else None,
        True,
        _path(kavita_root, "state.kavita_root") if kavita_root is not None else kavita_xdg_state(),
    )


def validate(config: Config) -> None:
    seen: list[Path] = []
    for category in config.categories:
        for root in (category.ingest_root, category.production_root):
            if root.is_symlink() or not root.is_dir():
                raise ValueError(f"configured root is unavailable or a symlink: {root}")
            resolved = root.resolve(strict=True)
            for other in seen:
                if resolved == other or resolved.is_relative_to(other) or other.is_relative_to(resolved):
                    raise ValueError(f"configured roots overlap: {root} and {other}")
            seen.append(resolved)
