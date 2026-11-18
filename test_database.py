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
