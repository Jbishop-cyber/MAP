import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from core import database, quarantine

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_isolated_env(tmp_path, monkeypatch):
    test_db = tmp_path / "test_sentrix.db"
    test_vault = tmp_path / "quarantine_vault"

    monkeypatch.setattr(database, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", test_db)
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", test_vault)

    database.initialize_database()
    yield tmp_path


def test_quarantine_vault_creation(tmp_path):
    vault = quarantine.ensure_quarantine_vault()
    assert vault.exists()
    assert vault.is_dir()

    vault_stat = os.stat(vault)
    # Check directory permissions are 0o700 (owner rwx only)
    assert vault_stat.st_mode & 0o777 == 0o700


def test_quarantine_file_success(tmp_path):
    sample = tmp_path / "threat_sample.exe"
    content = b"SUSPICIOUS_PAYLOAD_DATA_123"
    sample.write_bytes(content)
    os.chmod(sample, 0o755)

    result = quarantine.quarantine_file(
        file_path=str(sample),
        threat_name="Trojan.Generic",
        reason="Detected matching heuristics",
        original_filename="threat_sample.exe"
    )

    assert result["success"] is True
    quarantine_id = result["quarantine_id"]
    assert quarantine_id is not None
    assert result["file_size"] == len(content)
    assert result["original_filename"] == "threat_sample.exe"
    assert result["threat_name"] == "Trojan.Generic"
    assert result["quarantine_status"] == "quarantined"

    # Original file must no longer exist at original location
    assert not sample.exists()

    # Quarantined file must exist in vault
    quarantined_file = Path(result["quarantine_path"])
    assert quarantined_file.exists()
    assert quarantined_file.name == f"{quarantine_id}.quarantine"

    # Neutralized permissions must be 0o000
    file_stat = os.stat(quarantined_file)
    assert file_stat.st_mode & 0o777 == 0o000

    # Record in database
    db_record = database.get_quarantine_record(quarantine_id)
    assert db_record is not None
    assert db_record["quarantine_id"] == quarantine_id
    assert db_record["original_permissions"] == 0o100755
    assert db_record["quarantine_status"] == "quarantined"


def test_quarantine_nonexistent_file():
    result = quarantine.quarantine_file("/nonexistent/file/path.xyz")
    assert "error" in result
    assert "does not exist" in result["error"].lower()


def test_quarantine_directory(tmp_path):
    test_dir = tmp_path / "some_dir"
    test_dir.mkdir()
    result = quarantine.quarantine_file(str(test_dir))
    assert "error" in result
    assert "not a regular file" in result["error"].lower()


def test_restore_quarantined_file_with_verified_sha256(tmp_path):
    sample = tmp_path / "important_file.txt"
    original_content = b"Important system configuration."
    sample.write_bytes(original_content)
    os.chmod(sample, 0o644)

    # 1. Quarantine
    q_result = quarantine.quarantine_file(
        file_path=str(sample),
        threat_name="FalsePositive.Test",
        reason="Extension anomaly",
        original_filename="important_file.txt"
    )
    assert q_result["success"] is True
    quarantine_id = q_result["quarantine_id"]

    assert not sample.exists()

    # 2. Restore to original path
    r_result = quarantine.restore_quarantined_file(quarantine_id)
    assert r_result["success"] is True
    assert r_result["quarantine_status"] == "restored"

    # File should be back at original path with exact content
    assert sample.exists()
    assert sample.read_bytes() == original_content

    # Permissions should be restored
    file_stat = os.stat(sample)
    assert file_stat.st_mode & 0o777 == 0o644

    # DB record updated
    record = database.get_quarantine_record(quarantine_id)
    assert record["quarantine_status"] == "restored"
    assert record["restored_at"] is not None


def test_restore_fails_on_sha256_integrity_mismatch(tmp_path):
    sample = tmp_path / "tamper_target.txt"
    sample.write_bytes(b"Original content before quarantine")

    # Quarantine file
    q_result = quarantine.quarantine_file(str(sample))
    quarantine_id = q_result["quarantine_id"]
    q_path = Path(q_result["quarantine_path"])

    # Simulate tampering or corruption in the vault
    os.chmod(q_path, stat.S_IWUSR | stat.S_IRUSR)
    q_path.write_bytes(b"Tampered corrupted content!!")
    os.chmod(q_path, 0)

    # Attempt restoration
    r_result = quarantine.restore_quarantined_file(quarantine_id)
    assert "error" in r_result
    assert "integrity check failed" in r_result["error"].lower()
    assert "sha-256 mismatch" in r_result["error"].lower()

    # Quarantined file must remain neutralized (0o000)
    assert os.stat(q_path).st_mode & 0o777 == 0o000

    # DB status must remain 'quarantined'
    record = database.get_quarantine_record(quarantine_id)
    assert record["quarantine_status"] == "quarantined"


def test_restore_conflict_handling(tmp_path):
    sample = tmp_path / "conflict.txt"
    sample.write_bytes(b"Version 1")

    q_result = quarantine.quarantine_file(str(sample))
    quarantine_id = q_result["quarantine_id"]

    # Recreate file at original path
    sample.write_bytes(b"Version 2 already exists")

    # Attempt restore without overwrite
    r_result = quarantine.restore_quarantined_file(quarantine_id)
    assert "error" in r_result
    assert "already exists" in r_result["error"]

    # Original file must remain untouched
    assert sample.read_bytes() == b"Version 2 already exists"

    # Quarantined file must remain available
    record = database.get_quarantine_record(quarantine_id)
    q_path = Path(record["quarantine_path"])
    assert q_path.exists()

    # Database status must remain quarantined
    assert record["quarantine_status"] == "quarantined"

def test_delete_quarantined_file_permanently(tmp_path):
    sample = tmp_path / "delete_target.bin"
    sample.write_bytes(b"Nasty malware to be permanently deleted")

    q_result = quarantine.quarantine_file(str(sample))
    quarantine_id = q_result["quarantine_id"]
    q_path = Path(q_result["quarantine_path"])
    assert q_path.exists()

    # Permanently delete
    d_result = quarantine.delete_quarantined_file(quarantine_id)
    assert d_result["success"] is True
    assert d_result["quarantine_status"] == "deleted"

    # File should be removed from disk
    assert not q_path.exists()

    # DB record updated
    record = database.get_quarantine_record(quarantine_id)
    assert record["quarantine_status"] == "deleted"
    assert record["deleted_at"] is not None

    # Attempting to delete again returns error
    second_delete = quarantine.delete_quarantined_file(quarantine_id)
    assert "error" in second_delete


def test_quarantine_api_endpoints(tmp_path):
    # 1. Create a sample file
    sample = tmp_path / "api_threat.exe"
    sample.write_bytes(b"API threat sample payload")

    # 2. Isolate via API
    iso_res = client.post(
        "/quarantine/isolate",
        json={
            "file_path": str(sample),
            "threat_name": "API.Trojan",
            "reason": "Test API isolation"
        }
    )
    assert iso_res.status_code == 200
    data = iso_res.json()
    assert data["success"] is True
    quarantine_id = data["quarantine_id"]

    # 3. List via API
    list_res = client.get("/quarantine")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] == 1
    assert list_data["quarantined_files"][0]["quarantine_id"] == quarantine_id

    # 4. Get item details via API
    item_res = client.get(f"/quarantine/{quarantine_id}")
    assert item_res.status_code == 200
    assert item_res.json()["threat_name"] == "API.Trojan"

    # 5. Restore via API
    custom_dest = tmp_path / "restored_api_threat.exe"
    restore_res = client.post(
        f"/quarantine/{quarantine_id}/restore",
        json={"destination_path": str(custom_dest)}
    )
    assert restore_res.status_code == 200
    assert custom_dest.exists()
    assert custom_dest.read_bytes() == b"API threat sample payload"

    # 6. Verify listing now shows 0 active
    list_res_after = client.get("/quarantine")
    assert list_res_after.json()["total"] == 0

    # 7. List including inactive
    list_all = client.get("/quarantine?include_inactive=true")
    assert list_all.json()["total"] == 1
    assert list_all.json()["quarantined_files"][0]["quarantine_status"] == "restored"

    # 8. Re-quarantine and test delete via API
    sample2 = tmp_path / "api_threat_delete.exe"
    sample2.write_bytes(b"Payload to delete via API")

    iso2 = client.post(
        "/quarantine/isolate",
        json={"file_path": str(sample2)}
    ).json()
    qid2 = iso2["quarantine_id"]

    del_res = client.delete(f"/quarantine/{qid2}")
    assert del_res.status_code == 200
    assert del_res.json()["quarantine_status"] == "deleted"

    # 9. Nonexistent ID 404
    not_found = client.get("/quarantine/nonexistent-id-999")
    assert not_found.status_code == 404

def test_restore_rejects_quarantine_symlink(tmp_path):
    original_file = tmp_path / "original.txt"
    original_file.write_text("safe content")

    result = quarantine.quarantine_file(str(original_file))
    record = database.get_quarantine_record(result["quarantine_id"])

    quarantine_path = Path(record["quarantine_path"])
    backup_file = tmp_path / "backup.txt"
    backup_file.write_text("safe content")

    quarantine_path.unlink()
    quarantine_path.symlink_to(backup_file)

    restore_result = quarantine.restore_quarantined_file(
        result["quarantine_id"]
    )

    assert "error" in restore_result
    assert backup_file.read_text() == "safe content"
    assert database.get_quarantine_record(
        result["quarantine_id"]
    )["quarantine_status"] == "quarantined"


def test_restore_rejects_destination_symlink(tmp_path):
    original_file = tmp_path / "original.txt"
    original_file.write_text("safe content")

    result = quarantine.quarantine_file(str(original_file))

    target_file = tmp_path / "target.txt"
    target_file.write_text("do not overwrite")

    destination_link = tmp_path / "restore.txt"
    destination_link.symlink_to(target_file)

    restore_result = quarantine.restore_quarantined_file(
        result["quarantine_id"],
        str(destination_link)
    )

    assert "error" in restore_result
    assert target_file.read_text() == "do not overwrite"
    assert database.get_quarantine_record(
        result["quarantine_id"]
    )["quarantine_status"] == "quarantined"
