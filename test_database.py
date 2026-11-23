import sqlite3

from core import database

def test_initialize_database(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    assert test_db.exists()

    connection = sqlite3.connect(test_db)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='scan_history'
    """)

    result = cursor.fetchone()

    connection.close()

    assert result is not None

def test_save_scan(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    report = {
        "sha256": "abc123",
        "status": "NO DETECTION"
    }

    scan_id = database.save_scan(
        filename="test.txt",
        sha256="abc123",
        status="NO DETECTION",
        report=report
    )

    assert scan_id == 1

def test_get_scan_history(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    report = {"sha256": "abc123"}

    database.save_scan("test.txt", "abc123", "NO DETECTION", report)

    history = database.get_scan_history()

    assert len(history) == 1
    assert history[0]["filename"] == "test.txt"
    assert history[0]["sha256"] == "abc123"
    assert history[0]["status"] == "NO DETECTION"
    assert history[0]["report"] == report

def test_empty_scan_history(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    history = database.get_scan_history()

    assert history == []

def test_scan_history_ascending_order(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    database.save_scan(
        "first.txt", "hash1", "NO DETECTION", {"id": 1}
    )

    database.save_scan(
        "second.txt", "hash2", "DETECTED", {"id": 2}
    )

    database.save_scan(
        "third.txt", "hash3", "NO DETECTION", {"id": 3}
    )

    history = database.get_scan_history()

    filenames = [scan["filename"] for scan in history]

    assert filenames == ["first.txt", "second.txt", "third.txt"]


def test_quarantine_records_lifecycle(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    record_id = database.save_quarantine_record(
        quarantine_id="q-1234",
        original_path="/tmp/malware.exe",
        original_filename="malware.exe",
        quarantine_path="/tmp/quarantine/q-1234.quarantine",
        file_size=1024,
        file_type="EXE",
        sha256="abc123hash",
        threat_name="EICAR-Test-Signature",
        reason="Detected known threat",
        original_permissions=0o755
    )

    assert record_id == 1

    record = database.get_quarantine_record("q-1234")
    assert record is not None
    assert record["quarantine_id"] == "q-1234"
    assert record["original_filename"] == "malware.exe"
    assert record["file_size"] == 1024
    assert record["file_type"] == "EXE"
    assert record["sha256"] == "abc123hash"
    assert record["threat_name"] == "EICAR-Test-Signature"
    assert record["original_permissions"] == 0o755
    assert record["quarantine_status"] == "quarantined"

    # List active quarantine
    active_list = database.list_quarantine_records(include_inactive=False)
    assert len(active_list) == 1

    # Update status to restored
    updated = database.update_quarantine_status(
        "q-1234", "restored", restored_at="2026-11-23 12:00:00"
    )
    assert updated is True

    # Check active list again (should now be empty)
    active_list = database.list_quarantine_records(include_inactive=False)
    assert len(active_list) == 0

    # Inactive list includes restored
    all_list = database.list_quarantine_records(include_inactive=True)
    assert len(all_list) == 1
    assert all_list[0]["quarantine_status"] == "restored"
    assert all_list[0]["restored_at"] == "2026-11-23 12:00:00"
