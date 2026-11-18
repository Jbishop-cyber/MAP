import sqlite3
from pathlib import Path

import json

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATABASE_DIR / "sentrix.db"

def get_connection():
    DATABASE_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    return connection

def initialize_database():
    connection = get_connection()

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

    connection.commit()
    connection.close()

def save_scan(filename, sha256, status, report):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scan_history (filename, sha256, status, report)
        VALUES (?, ?, ?, ?)
    """, (
        filename,
        sha256,
        status,
        json.dumps(report)
    ))

    connection.commit()
    scan_id = cursor.lastrowid
    connection.close()

    return scan_id

def get_scan_history():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM scan_history
        ORDER BY scanned_at ASC
    """)

    rows = cursor.fetchall()
    connection.close()

    history = []

    for row in rows:
        local_time = datetime.strptime(
            row[5], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc).astimezone(
            ZoneInfo("Africa/Lagos")
        )
        
        history.append({
            "id": row[0],
            "filename": row[1],
            "sha256": row[2],
            "status": row[3],
            "report": json.loads(row[4]),
            "scanned_at(UTC)": local_time.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return history

