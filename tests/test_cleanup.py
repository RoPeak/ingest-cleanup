from __future__ import annotations

import json
from pathlib import Path

import pytest

from ingest_cleanup.config import Category, Config, validate
from ingest_cleanup.core import apply_deletions, assess_category, write_audit
from ingest_cleanup import cli


def setup(tmp_path: Path):
    ingest = tmp_path / "ingest"; production = tmp_path / "production"; state = tmp_path / "state"
    ingest.mkdir(); production.mkdir(); (state / "run" / "reports").mkdir(parents=True)
    category = Category("TV", ingest, production, "video")
    return ingest, production, state, category, Config((category,), (state,), None, False)


def video(path: Path, source: Path, destination: Path, *, mode="apply", copy=True, final=True):
    rows = [{"type":"header","mode":mode,"copy":copy,"version":1}, {"type":"operation","source":str(source),"destination":str(destination),"media_type":"tv","metadata":{}}]
    if final: rows.append({"type":"final","operations":1})
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")


def test_success_and_conflict_destination(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "episode.mkv"; destination = production / "episode (1).mkv"
    source.write_bytes(b"same bytes"); destination.write_bytes(b"same bytes")
    video(state / "run" / "reports" / "copy.json", source, destination)
    items, bad = assess_category(config, category)
    assert not bad and [(item.state, item.destination) for item in items] == [("SAFE", destination)]


@pytest.mark.parametrize("mode,copy,final", [("dry-run", True, True), ("apply", False, True), ("apply", True, False)])
def test_unsuccessful_video_report_is_not_proof(tmp_path: Path, mode: str, copy: bool, final: bool):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination, mode=mode, copy=copy, final=final)
    items, bad = assess_category(config, category)
    assert items[0].state == "UNKNOWN" and bad


@pytest.mark.parametrize("destination_bytes,reason", [(None, "published destination missing or unsafe"), (b"xx", "size mismatch"), (b"y", "content mismatch")])
def test_current_destination_failures(tmp_path: Path, destination_bytes: bytes | None, reason: str):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x")
    if destination_bytes is not None: destination.write_bytes(destination_bytes)
    video(state / "run" / "reports" / "report.json", source, destination)
    items, _ = assess_category(config, category)
    assert items[0].state == "REVIEW" and items[0].reason == reason


def test_ambiguity_and_outside_path_fail_closed(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; source.write_bytes(b"x"); one = production / "one"; two = production / "two"; one.write_bytes(b"x"); two.write_bytes(b"x")
    report = state / "run" / "reports" / "report.json"
    rows = [{"type":"header","mode":"apply","copy":True,"version":1}, *({"type":"operation","source":str(source),"destination":str(dest),"media_type":"tv","metadata":{}} for dest in (one,two)), {"type":"final","operations":2}]
    report.write_text("\n".join(json.dumps(row) for row in rows))
    items, _ = assess_category(config, category)
    assert items[0].state == "UNKNOWN"


def test_symlink_hardlink_and_root_overlap_are_rejected(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    target = tmp_path / "target"; target.write_bytes(b"x")
    (ingest / "link").symlink_to(target)
    items, _ = assess_category(config, category); assert not items
    source = ingest / "hard"; source.write_bytes(b"x"); destination = production / "hard"; destination.write_bytes(b"x"); (ingest / "other").hardlink_to(source)
    video(state / "run" / "reports" / "report.json", source, destination)
    items, _ = assess_category(config, category); assert next(item for item in items if item.source == source).state == "UNKNOWN"
    with pytest.raises(ValueError): validate(Config((Category("bad", ingest, ingest / "nested", "disabled"),), (), None, False))


def test_apply_rechecks_identity_and_prunes(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    nested = ingest / "nested"; nested.mkdir(); source = nested / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination)
    items, _ = assess_category(config, category); payload = apply_deletions(items, {"TV": ingest})
    assert payload["items"][0]["result"] == "deleted" and not source.exists() and ingest.exists() and not nested.exists()


def test_changed_source_during_hash_is_review(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x" * 100); destination.write_bytes(b"x" * 100)
    video(state / "run" / "reports" / "report.json", source, destination)
    changed = False
    def mutate(path: Path, complete: int, total: int):
        nonlocal changed
        if path == source and not changed:
            changed = True; source.write_bytes(b"y" * 100)
    items, _ = assess_category(config, category, mutate)
    assert items[0].state == "REVIEW" and "changed while hashing" in items[0].reason


def test_music_apply_chain_and_dry_run(tmp_path: Path):
    ingest = tmp_path / "ingest"; production = tmp_path / "production"; state = tmp_path / "state"; ingest.mkdir(); production.mkdir(); (state / "reports").mkdir(parents=True)
    source = ingest / "album" / "track.mp3"; source.parent.mkdir(); source.write_bytes(b"music")
    destination = production / "artist" / "track.mp3"; destination.parent.mkdir(); destination.write_bytes(b"music")
    data = music_report(ingest, production, "album/track.mp3", "artist/track.mp3")
    (state / "reports" / "music.json").write_text(json.dumps(data))
    category = Category("Music", ingest, production, "music"); config = Config((category,), (), state, False)
    items, bad = assess_category(config, category); assert not bad and items[0].state == "SAFE"
    data["mode"] = "dry-run"; (state / "reports" / "music.json").write_text(json.dumps(data))
    items, bad = assess_category(config, category); assert items[0].state == "UNKNOWN" and bad


def music_report(ingest: Path, production: Path, source: str, destination: str) -> dict[str, object]:
    return {"report_schema":"music-ingest-publication-v1", "mode":"apply", "approved_to_publish":True, "publication":"copy", "source_lifecycle":"preserved", "publication_completed":True, "source_root":str(ingest), "library_root":str(production), "copied_tracks":1, "published_file_count":2, "albums":[{"tracks":[{"source":source, "source_path":str(ingest / source), "destination":destination, "destination_path":str(production / destination), "final_destination":str(production / destination), "readable":True, "source_size_bytes":5, "staged_size_bytes":5, "verified_size_match":True, "publication_status":"published_or_verified_existing"}]}]}


@pytest.mark.parametrize("field,value", [("report_schema", "wrong"), ("publication_completed", False), ("approved_to_publish", False), ("mode", "dry-run")])
def test_music_partial_or_cancelled_is_not_proof(tmp_path: Path, field: str, value: object):
    ingest = tmp_path / "ingest"; production = tmp_path / "production"; state = tmp_path / "state"; ingest.mkdir(); production.mkdir(); (state / "reports").mkdir(parents=True)
    source = ingest / "s"; destination = production / "d"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    data = music_report(ingest, production, "s", "d"); data[field] = value
    (state / "reports" / "music.json").write_text(json.dumps(data))
    category = Category("Music", ingest, production, "music"); items, bad = assess_category(Config((category,), (), state, False), category)
    assert items[0].state == "UNKNOWN" and bad


def test_music_auxiliary_files_do_not_poison_audio_provenance(tmp_path: Path):
    ingest = tmp_path / "ingest"; production = tmp_path / "production"; state = tmp_path / "state"; ingest.mkdir(); production.mkdir(); (state / "reports").mkdir(parents=True)
    for index in range(92):
        source = ingest / f"source-{index}.mp3"; destination = production / f"track-{index}.mp3"; source.write_bytes(b"music"); destination.write_bytes(b"music")
        data = music_report(ingest, production, source.name, destination.name) if index == 0 else data
        if index:
            data["albums"][0]["tracks"].append({"source":source.name, "source_path":str(source), "destination":destination.name, "destination_path":str(destination), "final_destination":str(destination), "readable":True, "source_size_bytes":5, "staged_size_bytes":5, "verified_size_match":True, "publication_status":"published_or_verified_existing"})
    data["published_file_count"] = 96
    (state / "reports" / "music.json").write_text(json.dumps(data))
    category = Category("Music", ingest, production, "music")
    items, bad = assess_category(Config((category,), (), state, False), category)
    assert not bad and len(items) == 92 and {item.state for item in items} == {"SAFE"}
def test_audit_report_is_written_under_xdg_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    audit = write_audit({"items": [], "directories_pruned": []})
    assert audit.parent == tmp_path / "ingest-cleanup" / "reports"
    assert json.loads(audit.read_text())["items"] == []


def test_apply_requires_exact_typed_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination)
    monkeypatch.setattr(cli, "_load", lambda path: config)
    monkeypatch.setattr("builtins.input", lambda prompt: "delete verified sources")
    assert cli.main(["apply"]) == 0 and source.exists()
