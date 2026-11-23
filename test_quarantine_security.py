import os
from pathlib import Path

import pytest
from core import database, quarantine


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.db")
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "vault")
    database.initialize_database()
    return tmp_path


def test_quarantine_rejects_symlink_source(isolated):
    real = isolated / "real.txt"
    real.write_text("safe")
    link = isolated / "link.txt"
    link.symlink_to(real)

    result = quarantine.quarantine_file(str(link))

    assert "error" in result
    assert real.read_text() == "safe"
    assert link.is_symlink()


def test_quarantine_rolls_back_when_database_insert_fails(isolated, monkeypatch):
    source = isolated / "rollback.txt"
    source.write_text("recover me")

    def fail_insert(**kwargs):
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(quarantine, "save_quarantine_record", fail_insert)
    result = quarantine.quarantine_file(str(source))

    assert "error" in result
    assert source.read_text() == "recover me"
    assert list((isolated / "vault").glob("*.quarantine")) == []


def test_restore_rejects_quarantine_symlink(isolated):
    source = isolated / "source.txt"
    source.write_text("safe")
    result = quarantine.quarantine_file(str(source))
    record = database.get_quarantine_record(result["quarantine_id"])

    payload = Path(record["quarantine_path"])
    backup = isolated / "backup.txt"
    backup.write_text("do not follow")
    payload.unlink()
    payload.symlink_to(backup)

    restored = quarantine.restore_quarantined_file(result["quarantine_id"])

    assert "error" in restored
    assert backup.read_text() == "do not follow"
    assert database.get_quarantine_record(result["quarantine_id"])["quarantine_status"] == "quarantined"


def test_restore_rejects_destination_symlink(isolated):
    source = isolated / "source.txt"
    source.write_text("safe")
    result = quarantine.quarantine_file(str(source))

    target = isolated / "target.txt"
    target.write_text("keep me")
    link = isolated / "restore.txt"
    link.symlink_to(target)

    restored = quarantine.restore_quarantined_file(
        result["quarantine_id"], str(link)
    )

    assert "error" in restored
    assert target.read_text() == "keep me"


def test_restore_database_failure_keeps_quarantine_payload(isolated, monkeypatch):
    source = isolated / "source.txt"
    source.write_text("safe")
    result = quarantine.quarantine_file(str(source))
    record = database.get_quarantine_record(result["quarantine_id"])
    payload = Path(record["quarantine_path"])

    def fail_update(*args, **kwargs):
        raise RuntimeError("simulated database outage")

    monkeypatch.setattr(quarantine, "update_quarantine_status", fail_update)
    restored = quarantine.restore_quarantined_file(result["quarantine_id"])

    assert "error" in restored
    assert payload.exists()
    assert not source.exists()
    assert database.get_quarantine_record(result["quarantine_id"])["quarantine_status"] == "quarantined"


def test_delete_database_finalization_can_be_retried(isolated, monkeypatch):
    source = isolated / "source.txt"
    source.write_text("delete me")
    result = quarantine.quarantine_file(str(source))
    qid = result["quarantine_id"]

    original_update = quarantine.update_quarantine_status
    calls = {"count": 0}

    def fail_final_deleted(*args, **kwargs):
        if args and len(args) > 1 and args[1] == "deleted":
            calls["count"] += 1
            raise RuntimeError("simulated final commit failure")
        if kwargs.get("status") == "deleted":
            calls["count"] += 1
            raise RuntimeError("simulated final commit failure")
        return original_update(*args, **kwargs)

    monkeypatch.setattr(quarantine, "update_quarantine_status", fail_final_deleted)
    first = quarantine.delete_quarantined_file(qid)
    assert "error" in first
    assert database.get_quarantine_record(qid)["quarantine_status"] == "delete_pending"

    monkeypatch.setattr(quarantine, "update_quarantine_status", original_update)
    second = quarantine.delete_quarantined_file(qid)
    assert second["success"] is True
    assert database.get_quarantine_record(qid)["quarantine_status"] == "deleted"


def test_database_status_update_checks_expected_state(isolated):
    source = isolated / "source.txt"
    source.write_text("payload")
    result = quarantine.quarantine_file(str(source))
    qid = result["quarantine_id"]

    changed = database.update_quarantine_status(
        qid, "restored", expected_status="deleted"
    )
    assert changed is False
    assert database.get_quarantine_record(qid)["quarantine_status"] == "quarantined"
