from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ingest_cleanup import cli
from ingest_cleanup import core as core_module
from ingest_cleanup.backup_proof import create_backup_proof, find_backup_proof
from ingest_cleanup.config import Category, Config, kavita_xdg_state, validate
from ingest_cleanup.core import (
    apply_deletions,
    assess,
    assess_category,
    create_verification_plan,
    load_verification_plan,
    verify_saved_plan,
    write_audit,
)


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


def test_v2_verified_existing_duplicate_requires_fresh_hash_verification(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "O'Brien S01E01.mkv"; destination = production / "O'Brien S01E01.mkv"
    source.write_bytes(b"same bytes"); destination.write_bytes(b"same bytes")
    report = state / "run" / "reports" / "copy.json"
    rows = [
        {"type": "header", "mode": "apply", "copy": True, "version": 2},
        {"type": "operation", "source": str(source), "destination": str(destination), "media_type": "tv", "metadata": {}, "action": "verified-existing-duplicate"},
        {"type": "final", "operations": 1},
    ]
    report.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    candidates, bad = assess_category(config, category, hash_files=False)
    assert not bad and candidates[0].state == "CANDIDATE"
    verified, bad = assess_category(config, category)
    assert not bad and verified[0].state == "SAFE"
    destination.write_bytes(b"changed")
    assert assess_category(config, category)[0][0].state == "REVIEW"


def test_v2_user_skip_is_not_accepted_provenance(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source.mkv"; destination = production / "destination.mkv"
    source.write_bytes(b"incoming"); destination.write_bytes(b"different")
    report = state / "run" / "reports" / "copy.json"
    rows = [
        {"type": "header", "mode": "apply", "copy": True, "version": 2},
        {"type": "operation", "source": str(source), "destination": str(destination), "media_type": "tv", "metadata": {}, "action": "user-skipped"},
        {"type": "final", "operations": 1},
    ]
    report.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    items, rejected = assess_category(config, category)
    assert not items or items[0].state == "UNKNOWN"
    assert rejected


@pytest.mark.parametrize("mode,copy,final", [("dry-run", True, True), ("apply", False, True), ("apply", True, False)])
def test_unsuccessful_video_report_is_not_proof(tmp_path: Path, mode: str, copy: bool, final: bool):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination, mode=mode, copy=copy, final=final)
    items, bad = assess_category(config, category)
    assert items[0].state == "UNKNOWN" and bad


@pytest.mark.parametrize("destination_bytes,reason", [(None, "published destination missing"), (b"xx", "size mismatch"), (b"y", "content mismatch")])
def test_current_destination_failures(tmp_path: Path, destination_bytes: bytes | None, reason: str):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x")
    if destination_bytes is not None: destination.write_bytes(destination_bytes)
    video(state / "run" / "reports" / "report.json", source, destination)
    items, _ = assess_category(config, category)
    assert items[0].state == "REVIEW" and items[0].reason == reason


def test_destination_outside_production_or_symlink_is_review(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; source.write_bytes(b"x")
    outside = tmp_path / "outside"; outside.write_bytes(b"x")
    video(state / "run" / "reports" / "outside.json", source, outside)
    items, _ = assess_category(config, category)
    assert items[0].state == "REVIEW"
    assert items[0].reason == "published destination outside expected production root"

    (state / "run" / "reports" / "outside.json").unlink()
    target = production / "target"; target.write_bytes(b"x")
    link = production / "link"; link.symlink_to(target)
    video(state / "run" / "reports" / "symlink.json", source, link)
    items, _ = assess_category(config, category)
    assert items[0].state == "REVIEW"
    assert items[0].reason == "published destination unsafe: not a regular non-symlink file"


def test_ambiguity_and_outside_path_fail_closed(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; source.write_bytes(b"x"); one = production / "one"; two = production / "two"; one.write_bytes(b"x"); two.write_bytes(b"x")
    report = state / "run" / "reports" / "report.json"
    rows = [{"type":"header","mode":"apply","copy":True,"version":1}, *({"type":"operation","source":str(source),"destination":str(dest),"media_type":"tv","metadata":{}} for dest in (one,two)), {"type":"final","operations":2}]
    report.write_text("\n".join(json.dumps(row) for row in rows))
    items, _ = assess_category(config, category)
    assert items[0].state == "UNKNOWN"


def test_stale_v1_mapping_does_not_mask_unique_v2_existing_duplicate(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "Banshee (2013) - s02e01 - Little Fish.mkv"
    canonical = production / "Banshee (2013) - s02e01 - Little Fish.mkv"
    stale = production / "Banshee (2013) - s02e01 - Little Fish (2).mkv"
    source.write_bytes(b"same bytes"); canonical.write_bytes(b"same bytes")
    video(state / "run" / "reports" / "old.json", source, stale)
    report = state / "run" / "reports" / "current.json"
    report.write_text("\n".join(json.dumps(row) for row in [
        {"type": "header", "mode": "apply", "copy": True, "version": 2},
        {"type": "operation", "source": str(source), "destination": str(canonical), "media_type": "tv", "metadata": {}, "action": "verified-existing-duplicate"},
        {"type": "final", "operations": 1},
    ]) + "\n")

    candidates, rejected = assess_category(config, category, hash_files=False)
    assert not rejected and candidates[0].state == "CANDIDATE"
    assert candidates[0].destination == canonical
    assert "ignored 1 stale provenance mapping" in candidates[0].reason
    verified, rejected = assess_category(config, category)
    assert not rejected and verified[0].state == "SAFE"


def test_reused_source_path_requires_current_size_and_hash_match(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "reused.mkv"; destination = production / "published.mkv"
    source.write_bytes(b"new source"); destination.write_bytes(b"old")
    video(state / "run" / "reports" / "old.json", source, destination)
    items, _ = assess_category(config, category, hash_files=False)
    assert items[0].state == "REVIEW" and items[0].reason == "size mismatch"

    destination.write_bytes(b"old bytes!")
    assert len(destination.read_bytes()) == len(source.read_bytes())
    candidates, _ = assess_category(config, category, hash_files=False)
    assert candidates[0].state == "CANDIDATE"
    verified, _ = assess_category(config, category)
    assert verified[0].state == "REVIEW" and verified[0].reason == "content mismatch"


def test_two_current_sources_for_one_destination_remain_ambiguous(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    first = ingest / "first.mkv"; second = ingest / "second.mkv"; destination = production / "episode.mkv"
    first.write_bytes(b"same"); second.write_bytes(b"same"); destination.write_bytes(b"same")
    video(state / "run" / "reports" / "first.json", first, destination)
    video(state / "run" / "reports" / "second.json", second, destination)
    items, _ = assess_category(config, category, hash_files=False)
    assert {item.state for item in items} == {"REVIEW"}
    assert {item.reason for item in items} == {"ambiguous destination provenance with another current source"}


def test_repeated_same_source_destination_records_are_deduplicated_after_validation(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source.mkv"; destination = production / "episode.mkv"
    source.write_bytes(b"same"); destination.write_bytes(b"same")
    video(state / "run" / "reports" / "one.json", source, destination)
    video(state / "run" / "reports" / "two.json", source, destination)
    items, _ = assess_category(config, category, hash_files=False)
    assert len(items) == 1 and items[0].state == "CANDIDATE"


def test_symlink_hardlink_and_root_overlap_are_rejected(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    target = tmp_path / "target"; target.write_bytes(b"x")
    (ingest / "link").symlink_to(target)
    items, _ = assess_category(config, category); assert not items
    source = ingest / "hard"; source.write_bytes(b"x"); destination = production / "hard"; destination.write_bytes(b"x"); (ingest / "other").hardlink_to(source)
    video(state / "run" / "reports" / "report.json", source, destination)
    items, _ = assess_category(config, category); assert next(item for item in items if item.source == source).state == "UNKNOWN"
    with pytest.raises(ValueError): validate(Config((Category("bad", ingest, ingest / "nested", "disabled"),), (), None, False))


def test_apply_rechecks_identity_and_prunes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest, production, state, category, config = setup(tmp_path)
    nested = ingest / "nested"; nested.mkdir(); source = nested / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination)
    items, _ = assess_category(config, category); payload = apply_deletions(items, {"TV": ingest})
    assert payload["items"][0]["result"] == "deleted" and not source.exists() and ingest.exists() and not nested.exists()


def test_v3_mixed_move_accepts_only_preserved_duplicate(tmp_path: Path):
    ingest, production, state, category, config = setup(tmp_path)
    moved = ingest / "moved.mkv"; duplicate = ingest / "duplicate.mkv"
    moved_dest = production / "moved.mkv"; duplicate_dest = production / "duplicate.mkv"
    for path in (moved, moved_dest, duplicate, duplicate_dest): path.write_bytes(path.name.encode())
    duplicate_dest.write_bytes(duplicate.read_bytes())
    report = state / "run" / "reports" / "mixed.json"
    digest = hashlib.sha256(duplicate.read_bytes()).hexdigest()
    rows = [
        {"type":"header", "mode":"apply", "copy":False, "version":3},
        {"type":"operation", "source":str(moved), "destination":str(moved_dest), "action":"published", "source_lifecycle":"removed", "verification":"destination-created"},
        {"type":"operation", "source":str(duplicate), "destination":str(duplicate_dest), "action":"verified-existing-duplicate", "source_lifecycle":"preserved", "verification":"sha256", "source_sha256":digest, "destination_sha256":digest},
        {"type":"final", "operations":2, "status":"completed"},
    ]
    report.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    items, rejected = assess_category(config, category)
    assert not rejected
    assert next(item for item in items if item.source == duplicate).state == "SAFE"
    assert next(item for item in items if item.source == moved).reason_code == "NO_ACCEPTED_REPORT"


def test_kavita_v3_partial_report_accepts_only_complete_items(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    ingest.mkdir(); production.mkdir(); (state / "kavita-reports").mkdir(parents=True)
    complete = ingest / "complete.epub"; failed = ingest / "failed.epub"
    destination = production / "complete.epub"
    complete.write_bytes(b"published"); destination.write_bytes(b"published")
    failed.write_bytes(b"not published")
    digest = hashlib.sha256(b"published").hexdigest()
    payload = {
        "report_schema": "kavita-ingest-publication-v3",
        "approved_apply": True,
        "status": "partial",
        "source_lifecycle": "preserved",
        "verification_completed": True,
        "recovery_required": True,
        "items": [
            {
                "item_id": "complete",
                "item_state": "complete",
                "cleanup_eligible": True,
                "source_lifecycle": "preserved",
                "action": "published",
                "source": str(complete),
                "destination": str(destination),
                "source_sha256": digest,
                "destination_sha256": digest,
                "transformations": [],
            },
            {
                "item_id": "failed",
                "item_state": "failed",
                "cleanup_eligible": False,
                "source_lifecycle": "preserved",
                "source": str(failed),
                "destination": str(production / "failed.epub"),
            },
        ],
    }
    (state / "kavita-reports" / "partial.json").write_text(json.dumps(payload))
    category = Category("Books", ingest, production, "kavita")
    config = Config((category,), (), None, True, state)

    items, rejected = assess_category(config, category)

    assert not rejected
    complete_item = next(item for item in items if item.source == complete)
    assert complete_item.state == "BACKUP_REQUIRED"
    assert complete_item.reason_code == "INDEPENDENT_BACKUP_REQUIRED"
    assert next(item for item in items if item.source == failed).reason_code == "NO_ACCEPTED_REPORT"
    with pytest.raises(ValueError, match="deletion-ready"):
        create_verification_plan(config, [complete_item])


def test_legacy_saved_plan_cannot_bypass_kavita_backup_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest = tmp_path / "incoming"; production = tmp_path / "books"
    ingest.mkdir(); production.mkdir()
    source = ingest / "published.epub"; destination = production / "published.epub"
    source.write_bytes(b"same"); destination.write_bytes(b"same")
    source_id = core_module._identity(source)
    destination_id = core_module._identity(destination)
    digest = hashlib.sha256(b"same").hexdigest()
    category = Category("Books", ingest, production, "kavita")
    config = Config((category,), (), None, True, tmp_path / "producer-state")
    legacy_safe = core_module.Assessment(
        "Books", source, destination, "SAFE", "legacy verification",
        size=source_id.size, source_identity=source_id, sha256=digest,
        reason_code="VERIFIED", destination_identity=destination_id,
        destination_sha256=digest,
    )

    plan_id, _ = create_verification_plan(config, [legacy_safe])
    payload, _ = load_verification_plan(config, plan_id)
    reverified = verify_saved_plan(config, payload)

    assert reverified[0].state == "BACKUP_REQUIRED"
    assert reverified[0].reason_code == "INDEPENDENT_BACKUP_REQUIRED"


def test_kavita_v3_never_accepts_incomplete_item_marked_eligible(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    ingest.mkdir(); production.mkdir(); (state / "kavita-reports").mkdir(parents=True)
    source = ingest / "failed.epub"; destination = production / "failed.epub"
    source.write_bytes(b"same"); destination.write_bytes(b"same")
    digest = hashlib.sha256(b"same").hexdigest()
    payload = {
        "report_schema": "kavita-ingest-publication-v3", "approved_apply": True,
        "status": "partial", "source_lifecycle": "preserved",
        "verification_completed": True, "recovery_required": True,
        "items": [{"item_state": "failed", "cleanup_eligible": True,
                   "source_lifecycle": "preserved", "action": "published",
                   "source": str(source), "destination": str(destination),
                   "source_sha256": digest, "destination_sha256": digest}],
    }
    report = state / "kavita-reports" / "unsafe.json"
    report.write_text(json.dumps(payload))
    category = Category("Books", ingest, production, "kavita")
    config = Config((category,), (), None, True, state)

    items, rejected = assess_category(config, category)

    assert rejected and rejected[0].path == report
    assert next(item for item in items if item.source == source).reason_code == "NO_ACCEPTED_REPORT"


def test_saved_plan_expiry_config_drift_and_endpoint_replacement_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"
    source.write_bytes(b"same"); destination.write_bytes(b"same")
    video(state / "run" / "reports" / "report.json", source, destination)
    safe, _ = assess_category(config, category)
    plan_id, path = create_verification_plan(config, safe)
    assert path.stat().st_mode & 0o777 == 0o400
    payload, _ = load_verification_plan(config, plan_id)
    assert verify_saved_plan(config, payload)[0].state == "SAFE"

    replacement = production / "replacement"; replacement.mkdir()
    drifted = Config((Category("TV", ingest, replacement, "video"),), (state,), None, False)
    with pytest.raises(ValueError, match="configuration"):
        load_verification_plan(drifted, plan_id)

    destination.unlink(); destination.write_bytes(b"same")
    with pytest.raises(ValueError, match="identity"):
        verify_saved_plan(config, payload)

    path.chmod(0o600)
    expired = json.loads(path.read_text()); expired["expires_at"] = "2000-01-01T00:00:00+00:00"
    path.write_text(json.dumps(expired)); path.chmod(0o400)
    with pytest.raises(ValueError, match="integrity"):
        load_verification_plan(config, plan_id)
    path.chmod(0o600)
    expired.pop("integrity_sha256")
    expired["integrity_sha256"] = hashlib.sha256(json.dumps(expired, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path.write_text(json.dumps(expired)); path.chmod(0o400)
    with pytest.raises(ValueError, match="expired"):
        load_verification_plan(config, plan_id)


def test_batch_destination_change_aborts_before_any_deletion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest, production, state, category, config = setup(tmp_path)
    sources = [ingest / "one", ingest / "two"]; destinations = [production / "one", production / "two"]
    for index, (source, destination) in enumerate(zip(sources, destinations)):
        source.write_bytes(str(index).encode()); destination.write_bytes(str(index).encode())
        video(state / "run" / "reports" / f"{index}.json", source, destination)
    safe, _ = assess_category(config, category)
    destinations[1].write_bytes(b"changed")
    payload = apply_deletions(safe, {"TV": ingest})
    assert payload["status"] == "partial-failure"
    assert all(source.exists() for source in sources)


def test_prevalidation_cancellation_records_interrupted_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "destination"
    source.write_bytes(b"same"); destination.write_bytes(b"same")
    video(state / "run" / "reports" / "report.json", source, destination)
    safe, _ = assess_category(config, category)
    audit = tmp_path / "audit.json"

    def cancel(_path: Path, _complete: int, _total: int) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        apply_deletions(safe, {"TV": ingest}, audit, cancel)
    assert source.exists()
    assert json.loads(audit.read_text())["status"] == "interrupted"


def test_deletion_interruption_retains_crash_safe_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "destination"
    source.write_bytes(b"same"); destination.write_bytes(b"same")
    video(state / "run" / "reports" / "report.json", source, destination)
    safe, _ = assess_category(config, category)
    audit = tmp_path / "audit.json"

    original_unlink = Path.unlink

    def interrupt(path: Path, *args, **kwargs) -> None:
        if path == source:
            raise KeyboardInterrupt
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", interrupt)
    with pytest.raises(KeyboardInterrupt):
        apply_deletions(safe, {"TV": ingest}, audit)
    assert source.exists()
    assert json.loads(audit.read_text())["status"] == "interrupted"


def test_first_deletion_race_stops_batch_and_retains_partial_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    ingest, production, state, category, config = setup(tmp_path)
    sources = [ingest / "one", ingest / "two"]
    destinations = [production / "one", production / "two"]
    for index, (source, destination) in enumerate(zip(sources, destinations)):
        source.write_bytes(str(index).encode()); destination.write_bytes(str(index).encode())
        video(state / "run" / "reports" / f"{index}.json", source, destination)
    safe, _ = assess_category(config, category)
    safe.sort(key=lambda item: item.source.name)
    audit = tmp_path / "audit.json"
    original_identity = core_module._identity
    raced = False
    first_destination_checks = 0

    def race(path: Path):
        nonlocal raced, first_destination_checks
        if path == destinations[0]:
            first_destination_checks += 1
        # Prevalidation hashes the destination and checks its identity twice.
        # Change the second source only at the first item's immediate-delete
        # destination recheck, after the whole batch has passed prevalidation.
        if path == destinations[0] and first_destination_checks == 3 and not raced:
            raced = True
            sources[1].write_bytes(b"changed after batch verification")
        return original_identity(path)

    monkeypatch.setattr(core_module, "_identity", race)
    payload = apply_deletions(safe, {"TV": ingest}, audit)
    persisted = json.loads(audit.read_text())
    assert payload["status"] == persisted["status"] == "partial-failure"
    assert [item["result"] for item in persisted["items"]] == ["deleted", "skipped"]
    assert not sources[0].exists() and sources[1].exists()


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


def test_explain_and_provenance_status_are_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "unknown.mkv"; source.write_bytes(b"x")
    monkeypatch.setattr(cli, "_load", lambda path: config)
    assert cli.main(["explain", str(source)]) == 0
    output = capsys.readouterr().out
    assert "UNKNOWN" in output and "No matching accepted publication report exists." in output
    assert cli.main(["provenance-status"]) == 0
    assert "TV" in capsys.readouterr().out
    assert source.exists() and not list(production.iterdir())


def _kavita_report(source: Path, destination: Path, *, transformed: bool = False) -> dict[str, object]:
    return {
        "report_schema": "kavita-ingest-publication-v1",
        "operation_id": "synthetic-preserve-run",
        "approved_apply": True,
        "status": "completed",
        "source_lifecycle": "preserved",
        "verification_completed": True,
        "recovery_required": False,
        "items": [{
            "source": str(source),
            "destination": str(destination),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "destination_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "transformations": ["cbr-to-cbz"] if transformed else [],
        }],
    }


@pytest.mark.parametrize(
    "suffix,transformed", [(".cbz", False), (".cbr", True), (".epub", False), (".pdf", False)]
)
def test_kavita_publication_reports_are_discovered_and_fail_closed(
    tmp_path: Path, suffix: str, transformed: bool, capsys: pytest.CaptureFixture[str]
):
    ingest = tmp_path / "incoming"
    production = tmp_path / "library"
    state = tmp_path / "kavita-state"
    ingest.mkdir()
    production.mkdir()
    (state / "kavita-reports").mkdir(parents=True)
    source = ingest / f"source{suffix}"
    destination = production / f"published{'.cbz' if transformed else suffix}"
    source.write_bytes(b"original")
    destination.write_bytes(b"published" if transformed else b"original")
    (state / "kavita-reports" / "run.json").write_text(
        json.dumps(_kavita_report(source, destination, transformed=transformed))
    )
    category = Category("Books" if suffix in {".epub", ".pdf"} else "Comics", ingest, production, "kavita")
    config = Config((category,), (), None, True, state)
    cli._provenance_status(config)
    assert "kavita   ready" in capsys.readouterr().out
    candidate, rejected = assess_category(config, category, hash_files=False)
    assert not rejected and candidate[0].state == "CANDIDATE"
    verified, rejected = assess_category(config, category, hash_files=True)
    assert not rejected and verified[0].state == "BACKUP_REQUIRED"
    assert verified[0].reason_code == "INDEPENDENT_BACKUP_REQUIRED"
    source.write_bytes(b"changed source")
    assert assess_category(config, category)[0][0].state == "REVIEW"
    source.write_bytes(b"original")
    destination.write_bytes(b"changed destination")
    assert assess_category(config, category)[0][0].state == "REVIEW"


def test_kavita_default_state_root_uses_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert kavita_xdg_state() == tmp_path / "kavita-ingest"


def test_kavita_v2_mixed_lifecycle_accepts_only_preserved_item(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "library"; state = tmp_path / "state"
    ingest.mkdir(); production.mkdir(); (state / "kavita-reports").mkdir(parents=True)
    preserved = ingest / "preserved.cbz"; removed = ingest / "removed.cbz"
    preserved_dest = production / "preserved.cbz"; removed_dest = production / "removed.cbz"
    for source, destination in ((preserved, preserved_dest), (removed, removed_dest)):
        source.write_bytes(source.name.encode()); destination.write_bytes(source.read_bytes())
    def item(source: Path, destination: Path, lifecycle: str) -> dict[str, object]:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        return {"source":str(source), "destination":str(destination), "source_sha256":digest, "destination_sha256":digest, "source_lifecycle":lifecycle, "action":"verified-existing-duplicate", "transformations":[]}
    report = {"report_schema":"kavita-ingest-publication-v2", "approved_apply":True, "status":"completed", "source_lifecycle":"mixed", "verification_completed":True, "recovery_required":False, "items":[item(preserved, preserved_dest, "preserved"), item(removed, removed_dest, "removed")]}
    (state / "kavita-reports" / "run.json").write_text(json.dumps(report))
    category = Category("Comics", ingest, production, "kavita")
    results, rejected = assess_category(Config((category,), (), None, True, state), category)
    assert not rejected
    assert next(value for value in results if value.source == preserved).state == "BACKUP_REQUIRED"
    assert next(value for value in results if value.source == removed).state == "UNKNOWN"


def test_kavita_report_is_routed_to_one_configured_category_without_false_rejection(
    tmp_path: Path,
):
    books_in = tmp_path / "incoming-books"; books_out = tmp_path / "books"
    comics_in = tmp_path / "incoming-comics"; comics_out = tmp_path / "comics"
    state = tmp_path / "state"
    for path in (books_in, books_out, comics_in, comics_out, state / "kavita-reports"):
        path.mkdir(parents=True)
    source = books_in / "book.epub"; destination = books_out / "book.epub"
    source.write_bytes(b"book"); destination.write_bytes(b"book")
    report = _kavita_report(source, destination)
    report["report_schema"] = "kavita-ingest-publication-v3"
    report["items"][0].update({
        "item_state": "complete", "cleanup_eligible": True,
        "source_lifecycle": "preserved", "action": "published",
        "source_root": str(books_in), "library_root": str(books_out),
    })
    (state / "kavita-reports" / "books.json").write_text(json.dumps(report))
    config = Config(
        (
            Category("Books", books_in, books_out, "kavita"),
            Category("Comics", comics_in, comics_out, "kavita"),
        ),
        (), None, True, state,
    )

    results, rejected = assess(config)

    assert not rejected
    assert [(item.category, item.state) for item in results] == [
        ("Books", "BACKUP_REQUIRED")
    ]


def test_kavita_cross_category_report_is_rejected_once(tmp_path: Path):
    books_in = tmp_path / "incoming-books"; books_out = tmp_path / "books"
    comics_in = tmp_path / "incoming-comics"; comics_out = tmp_path / "comics"
    state = tmp_path / "state"
    for path in (books_in, books_out, comics_in, comics_out, state / "kavita-reports"):
        path.mkdir(parents=True)
    source = books_in / "book.epub"; destination = comics_out / "book.epub"
    source.write_bytes(b"book"); destination.write_bytes(b"book")
    (state / "kavita-reports" / "crossed.json").write_text(
        json.dumps(_kavita_report(source, destination))
    )
    config = Config(
        (
            Category("Books", books_in, books_out, "kavita"),
            Category("Comics", comics_in, comics_out, "kavita"),
        ),
        (), None, True, state,
    )

    results, rejected = assess(config)

    assert len(rejected) == 1
    assert "cross configured Kavita category roots" in rejected[0].reason
    assert next(item for item in results if item.source == source).state == "UNKNOWN"


def test_unsupported_historical_kavita_report_is_deduplicated_and_summarized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    books_in = tmp_path / "incoming-books"; books_out = tmp_path / "books"
    comics_in = tmp_path / "incoming-comics"; comics_out = tmp_path / "comics"
    state = tmp_path / "state"
    for path in (books_in, books_out, comics_in, comics_out, state / "kavita-reports"):
        path.mkdir(parents=True)
    (state / "kavita-reports" / "legacy.json").write_text(
        json.dumps({"report_schema": "unsupported-historical-v0"})
    )
    config = Config(
        (
            Category("Books", books_in, books_out, "kavita"),
            Category("Comics", comics_in, comics_out, "kavita"),
        ),
        (), None, True, state,
    )
    results, rejected = assess(config)

    assert len(rejected) == 1
    cli._print(results, rejected, False, config.categories)
    output = capsys.readouterr().out
    assert "Ignored corrupt/unsafe reports: 1" in output
    assert "unsupported Kavita publication schema" in output
    assert "Use --verbose for the full rejected-report list." in output
    assert "legacy.json" not in output


def test_epub_repair_manifest_is_known_retained_provenance(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    ingest.mkdir(); production.mkdir(); (state / "kavita-reports").mkdir(parents=True)
    source = ingest / "original.epub"; output = ingest / "repaired.epub"
    source.write_bytes(b"original"); output.write_bytes(b"repaired")
    sidecar = ingest / "repaired.epub.repair.json"
    sidecar.write_text(json.dumps({
        "report_schema": "kavita-ingest-epub-repair-v1",
        "source": str(source),
        "output": str(output),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "package_path": "OEBPS/content.opf",
        "report": "synthetic repair",
        "source_findings": ["mimetype_not_first"],
        "member_hashes": {},
    }))
    category = Category("Books", ingest, production, "kavita")

    results, rejected = assess_category(
        Config((category,), (), None, True, state), category, hash_files=True
    )

    assert not rejected
    manifest = next(item for item in results if item.source == sidecar)
    assert manifest.state == "PROVENANCE"
    assert manifest.reason_code == "REPAIR_PROVENANCE"
    assert manifest.destination == output
    assert source.exists() and output.exists() and sidecar.exists()


def test_malformed_repair_manifest_remains_unknown(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    ingest.mkdir(); production.mkdir(); state.mkdir()
    sidecar = ingest / "repaired.epub.repair.json"
    sidecar.write_text(json.dumps({"report_schema": "wrong"}))
    category = Category("Books", ingest, production, "kavita")

    results, _ = assess_category(Config((category,), (), None, True, state), category)

    manifest = next(item for item in results if item.source == sidecar)
    assert manifest.state == "UNKNOWN"
    assert manifest.reason_code == "REPAIR_PROVENANCE_INVALID"
    assert sidecar.exists()


def test_explicit_supersession_resolves_mapping_but_never_proves_backup(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    archive = tmp_path / "archive"
    for path in (ingest, production, archive, state / "kavita-reports", state / "supersession-reports"):
        path.mkdir(parents=True)
    source = ingest / "book.epub"; old = production / "old.epub"; new = production / "new.epub"
    source.write_bytes(b"source"); old.write_bytes(b"old-metadata"); new.write_bytes(b"new-metadata")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    old_hash = hashlib.sha256(old.read_bytes()).hexdigest()
    new_hash = hashlib.sha256(new.read_bytes()).hexdigest()
    report = _kavita_report(source, old, transformed=True)
    report["items"].append({**report["items"][0], "destination": str(new), "destination_sha256": new_hash})
    report["items"][0]["source_sha256"] = source_hash
    report["items"][0]["destination_sha256"] = old_hash
    (state / "kavita-reports" / "publications.json").write_text(json.dumps(report))
    category = Category("Books", ingest, production, "kavita")
    config = Config((category,), (), None, True, state)

    before, _ = assess_category(config, category, hash_files=False)
    assert before[0].reason_code == "AMBIGUOUS_MAPPING"

    archived = archive / "old.epub"
    old.rename(archived)
    supersession = {
        "report_schema": "kavita-ingest-supersession-v1",
        "state": "complete",
        "items": [{
            "source": str(source), "source_sha256": source_hash,
            "old_destination": str(old), "old_destination_sha256": old_hash,
            "archive": str(archived),
            "canonical_destination": str(new), "canonical_destination_sha256": new_hash,
        }],
    }
    (state / "supersession-reports" / "dcc.json").write_text(json.dumps(supersession))

    status, rejected = assess_category(config, category, hash_files=False)
    verified, _ = assess_category(config, category, hash_files=True)

    assert not rejected
    assert status[0].state == "CANDIDATE"
    assert "ignored 1 stale provenance mapping" in status[0].reason
    assert verified[0].state == "BACKUP_REQUIRED"
    assert archived.is_file() and new.is_file() and source.is_file()


def test_changed_supersession_archive_fails_closed(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    archive = tmp_path / "archive"
    for path in (ingest, production, archive, state / "kavita-reports", state / "supersession-reports"):
        path.mkdir(parents=True)
    source = ingest / "book.epub"; old = production / "old.epub"; new = production / "new.epub"
    source.write_bytes(b"source"); old.write_bytes(b"old"); new.write_bytes(b"new")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    old_hash = hashlib.sha256(old.read_bytes()).hexdigest()
    new_hash = hashlib.sha256(new.read_bytes()).hexdigest()
    report = _kavita_report(source, old, transformed=True)
    report["items"].append({**report["items"][0], "destination": str(new), "destination_sha256": new_hash})
    report["items"][0].update({"source_sha256": source_hash, "destination_sha256": old_hash})
    (state / "kavita-reports" / "publications.json").write_text(json.dumps(report))
    archived = archive / "old.epub"; old.rename(archived)
    (state / "supersession-reports" / "dcc.json").write_text(json.dumps({
        "report_schema": "kavita-ingest-supersession-v1", "state": "complete",
        "items": [{
            "source": str(source), "source_sha256": source_hash,
            "old_destination": str(old), "old_destination_sha256": old_hash,
            "archive": str(archived), "canonical_destination": str(new),
            "canonical_destination_sha256": new_hash,
        }],
    }))
    archived.write_bytes(b"tampered")
    category = Category("Books", ingest, production, "kavita")

    results, _ = assess_category(Config((category,), (), None, True, state), category)

    assert results[0].state == "REVIEW"
    assert results[0].reason_code == "SUPERSESSION_INVALID"


def test_interrupted_archive_without_complete_supersession_remains_ambiguous(
    tmp_path: Path,
):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    archive = tmp_path / "archive"
    for path in (ingest, production, archive, state / "kavita-reports"):
        path.mkdir(parents=True)
    source = ingest / "book.epub"; old = production / "old.epub"; new = production / "new.epub"
    source.write_bytes(b"source"); old.write_bytes(b"old"); new.write_bytes(b"new")
    report = _kavita_report(source, old, transformed=True)
    report["items"].append(
        {
            **report["items"][0],
            "destination": str(new),
            "destination_sha256": hashlib.sha256(new.read_bytes()).hexdigest(),
        }
    )
    (state / "kavita-reports" / "publications.json").write_text(json.dumps(report))
    old.rename(archive / "old.epub")
    category = Category("Books", ingest, production, "kavita")

    results, _ = assess_category(
        Config((category,), (), None, True, state), category, hash_files=True
    )

    assert results[0].state == "UNKNOWN"
    assert results[0].reason_code == "AMBIGUOUS_MAPPING"
    assert "explicit supersession" in results[0].reason


def test_invalid_multi_item_supersession_is_applied_transactionally(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    archive = tmp_path / "archive"
    for path in (ingest, production, archive, state / "kavita-reports", state / "supersession-reports"):
        path.mkdir(parents=True)
    source = ingest / "book.epub"; old = production / "old.epub"; new = production / "new.epub"
    source.write_bytes(b"source"); old.write_bytes(b"old"); new.write_bytes(b"new")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    old_hash = hashlib.sha256(old.read_bytes()).hexdigest()
    new_hash = hashlib.sha256(new.read_bytes()).hexdigest()
    report = _kavita_report(source, old, transformed=True)
    report["items"].append(
        {
            **report["items"][0],
            "destination": str(new),
            "destination_sha256": new_hash,
        }
    )
    report["items"][0].update(
        {"source_sha256": source_hash, "destination_sha256": old_hash}
    )
    (state / "kavita-reports" / "publications.json").write_text(json.dumps(report))
    archived = archive / "old.epub"; old.rename(archived)
    valid_item = {
        "source": str(source), "source_sha256": source_hash,
        "old_destination": str(old), "old_destination_sha256": old_hash,
        "archive": str(archived), "canonical_destination": str(new),
        "canonical_destination_sha256": new_hash,
    }
    (state / "supersession-reports" / "partial.json").write_text(
        json.dumps(
            {
                "report_schema": "kavita-ingest-supersession-v1",
                "state": "complete",
                "items": [valid_item, {"invalid": True}],
            }
        )
    )
    category = Category("Books", ingest, production, "kavita")

    results, rejected = assess_category(
        Config((category,), (), None, True, state), category, hash_files=False
    )

    assert rejected
    assert results[0].reason_code == "AMBIGUOUS_MAPPING"


def test_exact_source_backup_proof_can_authorize_transformed_publication(tmp_path: Path):
    ingest = tmp_path / "incoming"; production = tmp_path / "books"; state = tmp_path / "state"
    backup_mount = tmp_path / "backup"; proof_root = tmp_path / "proofs"
    for path in (ingest, production, backup_mount, state / "kavita-reports"):
        path.mkdir(parents=True)
    source = ingest / "book.epub"; destination = production / "book.epub"
    backup = backup_mount / "Incoming" / "book.epub"; backup.parent.mkdir()
    source.write_bytes(b"original-source"); destination.write_bytes(b"rewritten-publication")
    backup.write_bytes(source.read_bytes())
    (state / "kavita-reports" / "publication.json").write_text(
        json.dumps(_kavita_report(source, destination, transformed=True))
    )

    def runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        target = Path(args[0][args[0].index("--target") + 1])
        is_backup = target.is_relative_to(backup_mount)
        return subprocess.CompletedProcess(
            args[0], 0, json.dumps({"filesystems": [{
                "target": str(backup_mount if is_backup else tmp_path),
                "source": "/dev/sdz1" if is_backup else "/dev/sda1",
                "uuid": "MEDIA-UUID" if is_backup else "SOURCE-UUID",
                "options": "rw",
            }]}), ""
        )

    create_backup_proof(
        source, destination, backup, "MEDIA-UUID", proof_root, runner=runner
    )
    category = Category("Books", ingest, production, "kavita")
    config = Config((category,), (), None, True, state, proof_root)

    results, _ = assess_category(config, category, hash_files=True)

    assert results[0].state == "SAFE"
    assert results[0].reason_code == "INDEPENDENT_BACKUP_VERIFIED"
    assert results[0].evidence_identifier and results[0].evidence_identifier.endswith(".json")


def test_transformed_publication_backup_is_not_source_backup_proof(tmp_path: Path):
    source = tmp_path / "source.epub"; publication = tmp_path / "published.epub"
    mount = tmp_path / "backup"; mount.mkdir()
    backup = mount / "published.epub"
    source.write_bytes(b"original"); publication.write_bytes(b"transformed")
    backup.write_bytes(publication.read_bytes())

    def runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        target = Path(args[0][args[0].index("--target") + 1])
        is_backup = target.is_relative_to(mount)
        return subprocess.CompletedProcess(
            args[0], 0,
            json.dumps({"filesystems": [{
                "target": str(mount if is_backup else tmp_path),
                "uuid": "EXPECTED" if is_backup else "SOURCE",
            }]}),
            "",
        )

    with pytest.raises(ValueError, match="transformed publication backup is insufficient"):
        create_backup_proof(source, publication, backup, "EXPECTED", tmp_path / "proofs", runner=runner)


@pytest.mark.parametrize("returncode,uuid", [(1, "EXPECTED"), (0, "WRONG")])
def test_missing_or_wrong_backup_filesystem_identity_is_refused(
    tmp_path: Path, returncode: int, uuid: str
):
    source = tmp_path / "source"; publication = tmp_path / "publication"
    mount = tmp_path / "mount"; mount.mkdir(); backup = mount / "source"
    source.write_bytes(b"same"); publication.write_bytes(b"same"); backup.write_bytes(b"same")

    def runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        target = Path(args[0][args[0].index("--target") + 1])
        is_backup = target.is_relative_to(mount)
        output = json.dumps({"filesystems": [{"target": str(mount), "uuid": uuid}]})
        if not is_backup:
            output = json.dumps(
                {"filesystems": [{"target": str(tmp_path), "uuid": "SOURCE"}]}
            )
        return subprocess.CompletedProcess(args[0], returncode, output, "")

    with pytest.raises(ValueError, match="not mounted|UUID"):
        create_backup_proof(source, publication, backup, "EXPECTED", tmp_path / "proofs", runner=runner)


def test_stale_backup_proof_is_not_accepted_offline(tmp_path: Path):
    source = tmp_path / "source"; publication = tmp_path / "publication"
    mount = tmp_path / "mount"; mount.mkdir(); backup = mount / "source"
    source.write_bytes(b"same"); publication.write_bytes(b"same"); backup.write_bytes(b"same")
    proof_root = tmp_path / "proofs"

    def runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        target = Path(args[0][args[0].index("--target") + 1])
        is_backup = target.is_relative_to(mount)
        output = json.dumps({"filesystems": [{
            "target": str(mount if is_backup else tmp_path),
            "uuid": "EXPECTED" if is_backup else "SOURCE",
        }]})
        return subprocess.CompletedProcess(args[0], 0, output, "")

    create_backup_proof(source, publication, backup, "EXPECTED", proof_root, runner=runner)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    publication_hash = hashlib.sha256(publication.read_bytes()).hexdigest()
    future = datetime.now(UTC) + timedelta(days=15)

    proof, reason = find_backup_proof(
        proof_root,
        source=source.resolve(), source_sha256=source_hash,
        publication=publication.resolve(), publication_sha256=publication_hash,
        now=future,
    )

    assert proof is None
    assert reason == "backup proof is stale"


def test_backup_proof_refuses_same_filesystem_and_changed_endpoint_identity(
    tmp_path: Path,
):
    source = tmp_path / "source"; publication = tmp_path / "publication"
    mount = tmp_path / "mount"; mount.mkdir(); backup = mount / "source"
    source.write_bytes(b"same"); publication.write_bytes(b"same"); backup.write_bytes(b"same")

    def same_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        output = json.dumps(
            {"filesystems": [{"target": str(tmp_path), "uuid": "SAME"}]}
        )
        return subprocess.CompletedProcess(args[0], 0, output, "")

    with pytest.raises(ValueError, match="same filesystem"):
        create_backup_proof(
            source, publication, backup, "SAME", tmp_path / "proofs", runner=same_runner
        )

    def independent_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        target = Path(args[0][args[0].index("--target") + 1])
        is_backup = target.is_relative_to(mount)
        output = json.dumps(
            {"filesystems": [{
                "target": str(mount if is_backup else tmp_path),
                "uuid": "BACKUP" if is_backup else "SOURCE",
            }]}
        )
        return subprocess.CompletedProcess(args[0], 0, output, "")

    proof_root = tmp_path / "proofs"
    create_backup_proof(
        source, publication, backup, "BACKUP", proof_root, runner=independent_runner
    )
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    publication_hash = hashlib.sha256(publication.read_bytes()).hexdigest()
    replacement = tmp_path / "replacement"
    replacement.write_bytes(source.read_bytes())
    source.unlink()
    replacement.rename(source)

    proof, reason = find_backup_proof(
        proof_root,
        source=source.resolve(),
        source_sha256=source_hash,
        publication=publication.resolve(),
        publication_sha256=publication_hash,
    )

    assert proof is None
    assert "does not bind" in reason


def test_apply_empty_result_uses_mode_aware_completion_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    ingest, production, state, category, config = setup(tmp_path)
    (ingest / "unknown.mkv").write_bytes(b"x")
    monkeypatch.setattr(cli, "_load", lambda path: config)
    assert cli.main(["apply"]) == 0
    output = capsys.readouterr().out
    assert "Verification complete. No deletion-ready sources were found." in output
    assert "Run `ingest-cleanup apply`" not in output


def test_apply_requires_exact_typed_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination)
    monkeypatch.setattr(cli, "_load", lambda path: config)
    monkeypatch.setattr("builtins.input", lambda prompt: "delete verified sources")
    assert cli.main(["apply"]) == 0 and source.exists()


def test_apply_accepts_counted_confirmation_and_writes_completed_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "source"; destination = production / "dest"; source.write_bytes(b"x"); destination.write_bytes(b"x")
    video(state / "run" / "reports" / "report.json", source, destination)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "_load", lambda path: config)
    monkeypatch.setattr("builtins.input", lambda prompt: "DELETE 1 VERIFIED SOURCES")
    assert cli.main(["apply"]) == 0 and not source.exists()
    audit = next((tmp_path / "xdg" / "ingest-cleanup" / "reports").glob("*.json"))
    assert json.loads(audit.read_text())["status"] == "completed"


def test_saved_plan_cli_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    """Exercise producer evidence through saved review, apply, and audit."""
    ingest, production, state, category, config = setup(tmp_path)
    source = ingest / "synthetic-source.mkv"
    destination = production / "synthetic-destination.mkv"
    source.write_bytes(b"synthetic media bytes")
    destination.write_bytes(source.read_bytes())
    video(state / "run" / "reports" / "report.json", source, destination)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "_load", lambda path: config)

    assert cli.main(["verify"]) == 0
    assert "Saved verification plan:" in capsys.readouterr().out
    plan_file = next((tmp_path / "xdg" / "ingest-cleanup" / "plans").glob("*.json"))
    plan_id = plan_file.stem

    assert cli.main(["show", plan_id]) == 0
    shown = capsys.readouterr().out
    assert '"schema": "verification-plan-v1"' in shown
    assert str(source) in shown and str(destination) in shown

    monkeypatch.setattr("builtins.input", lambda prompt: "DELETE 1 VERIFIED SOURCES")
    assert cli.main(["apply", plan_id]) == 0
    assert not source.exists()
    assert destination.read_bytes() == b"synthetic media bytes"
    audit = next((tmp_path / "xdg" / "ingest-cleanup" / "reports").glob("*.json"))
    payload = json.loads(audit.read_text())
    assert payload["status"] == "completed"
    assert payload["items"][0]["result"] == "deleted"
