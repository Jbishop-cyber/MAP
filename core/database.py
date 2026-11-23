import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATABASE_DIR / "sentrix.db"


def get_connection():
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = None
    return connection


def initialize_database():
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT,
                status TEXT NOT NULL,
                report TEXT NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_id TEXT UNIQUE NOT NULL,
                original_path TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_type TEXT,
                sha256 TEXT NOT NULL,
                threat_name TEXT,
                reason TEXT,
                original_permissions INTEGER,
                quarantine_status TEXT NOT NULL DEFAULT 'quarantined',
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restored_at TIMESTAMP,
                deleted_at TIMESTAMP
            )
        """)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def save_scan(filename, sha256, status, report):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO scan_history (filename, sha256, status, report)
            VALUES (?, ?, ?, ?)
        """, (filename, sha256, status, json.dumps(report)))
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_scan_history():
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM scan_history ORDER BY scanned_at ASC")
        rows = cursor.fetchall()
    finally:
        connection.close()

    history = []
    for row in rows:
        local_time = datetime.strptime(
            row[5], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Africa/Lagos"))
        history.append({
            "id": row[0], "filename": row[1], "sha256": row[2],
            "status": row[3], "report": json.loads(row[4]),
            "scanned_at(UTC)": local_time.strftime("%Y-%m-%d %H:%M:%S")
        })
    return history


def _row_to_quarantine_record(row):
    if not row:
        return None
    return {
        "id": row[0], "quarantine_id": row[1], "original_path": row[2],
        "original_filename": row[3], "quarantine_path": row[4],
        "file_size": row[5], "file_type": row[6], "sha256": row[7],
        "threat_name": row[8], "reason": row[9],
        "original_permissions": row[10], "quarantine_status": row[11],
        "quarantined_at": row[12], "restored_at": row[13],
        "deleted_at": row[14]
    }


def save_quarantine_record(
    quarantine_id, original_path, original_filename, quarantine_path,
    file_size, file_type, sha256, threat_name=None, reason=None,
    original_permissions=None, quarantine_status="quarantined"
):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO quarantine_records (
                quarantine_id, original_path, original_filename,
                quarantine_path, file_size, file_type, sha256,
                threat_name, reason, original_permissions, quarantine_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            quarantine_id, str(original_path), original_filename,
            str(quarantine_path), file_size, file_type, sha256,
            threat_name, reason, original_permissions, quarantine_status
        ))
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_quarantine_record(quarantine_id):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT * FROM quarantine_records WHERE quarantine_id = ?",
            (quarantine_id,)
        )
        return _row_to_quarantine_record(cursor.fetchone())
    finally:
        connection.close()


def list_quarantine_records(include_inactive=False):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if include_inactive:
            cursor.execute("""
                SELECT * FROM quarantine_records ORDER BY quarantined_at DESC
            """)
        else:
            cursor.execute("""
                SELECT * FROM quarantine_records
                WHERE quarantine_status = 'quarantined'
                ORDER BY quarantined_at DESC
            """)
        rows = cursor.fetchall()
        return [_row_to_quarantine_record(row) for row in rows]
    finally:
        connection.close()


def update_quarantine_status(
    quarantine_id, status, restored_at=None, deleted_at=None,
    expected_status=None
):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        query = """
            UPDATE quarantine_records
            SET quarantine_status = ?,
                restored_at = COALESCE(?, restored_at),
                deleted_at = COALESCE(?, deleted_at)
            WHERE quarantine_id = ?
        """
        params = [status, restored_at, deleted_at, quarantine_id]
        if expected_status is not None:
            query += " AND quarantine_status = ?"
            params.append(expected_status)
        cursor.execute(query, params)
        connection.commit()
        return cursor.rowcount > 0
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
