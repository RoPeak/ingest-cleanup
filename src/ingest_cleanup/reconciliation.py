from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from .adapters import Evidence, collect
from .config import Category, Config
from .core import assess_category


@dataclass(frozen=True)
class PlausibleMatch:
    destination: Path
    score: float
    name_similarity: float
    size_equal: bool
    extension_compatible: bool
    classification: str = "PLAUSIBLE_ONLY"


@dataclass(frozen=True)
class ReconciliationItem:
    category: str
    source: Path
    current_state: str
    reason_code: str
    accepted_mappings: tuple[Evidence, ...]
    plausible_matches: tuple[PlausibleMatch, ...]


def _normalized(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value).casefold()
    return " ".join(
        "".join(
            character if character.isalnum() else " " for character in decomposed
        ).split()
    )


def _tokens(path: Path) -> set[str]:
    return {token for token in _normalized(path.stem).split() if len(token) > 1}


def _extension_compatible(source: Path, destination: Path) -> bool:
    left, right = source.suffix.casefold(), destination.suffix.casefold()
    return left == right or {left, right} <= {".cbr", ".cbz"}


def _production_files(root: Path) -> list[Path]:
    values: list[Path] = []
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        names[:] = [name for name in names if not (base / name).is_symlink()]
        values.extend(
            candidate
            for name in files
            if (candidate := base / name).is_file() and not candidate.is_symlink()
        )
    return values


def _plausible(
    source: Path, candidates: list[Path], *, limit: int = 5
) -> tuple[PlausibleMatch, ...]:
    source_name = _normalized(source.stem)
    source_tokens = _tokens(source)
    try:
        source_size = source.stat().st_size
    except OSError:
        return ()
    ranked: list[PlausibleMatch] = []
    for destination in candidates:
        compatible = _extension_compatible(source, destination)
        destination_tokens = _tokens(destination)
        if not compatible or not (source_tokens & destination_tokens):
            continue
        similarity = SequenceMatcher(
            None, source_name, _normalized(destination.stem)
        ).ratio()
        try:
            size_equal = destination.stat().st_size == source_size
        except OSError:
            continue
        score = (
            similarity * 0.8 + (0.1 if compatible else 0) + (0.1 if size_equal else 0)
        )
        if score >= 0.55:
            ranked.append(
                PlausibleMatch(
                    destination,
                    round(score, 3),
                    round(similarity, 3),
                    size_equal,
                    compatible,
                )
            )
    ranked.sort(
        key=lambda item: (item.score, item.size_equal, str(item.destination)),
        reverse=True,
    )
    return tuple(ranked[:limit])


def reconcile(
    config: Config, categories: tuple[Category, ...] | None = None
) -> tuple[list[ReconciliationItem], list[object]]:
    output: list[ReconciliationItem] = []
    rejected: list[object] = []
    for category in categories or config.categories:
        assessments, bad = assess_category(config, category, hash_files=False)
        records, _ = collect(config, category)
        rejected.extend(bad)
        by_source: dict[Path, list[Evidence]] = {}
        for record in records:
            by_source.setdefault(record.source, []).append(record)
        production = _production_files(category.production_root)
        for assessment in assessments:
            if assessment.reason_code not in {
                "NO_ACCEPTED_REPORT",
                "AMBIGUOUS_MAPPING",
            }:
                continue
            accepted = tuple(by_source.get(assessment.source, ()))
            plausible = () if accepted else _plausible(assessment.source, production)
            output.append(
                ReconciliationItem(
                    category.name,
                    assessment.source,
                    assessment.state,
                    assessment.reason_code,
                    accepted,
                    plausible,
                )
            )
    return output, rejected
