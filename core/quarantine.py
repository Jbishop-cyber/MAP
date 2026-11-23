import os
import stat
import shutil
import uuid
import threading
from pathlib import Path
from datetime import datetime, timezone

from core.hash_analyzer import calculate_sha256
from core.file_identifier import identify_file
from core.database import (
    initialize_database,
    save_quarantine_record,
    get_quarantine_record,
    list_quarantine_records,
    update_quarantine_status,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
QUARANTINE_DIR = PROJECT_ROOT / "data" / "quarantine"
_OPERATION_LOCK = threading.RLock()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def ensure_quarantine_vault():
    """Create/validate a private, non-symlink quarantine directory."""
    vault = Path(QUARANTINE_DIR)
    if vault.is_symlink():
        raise OSError("Quarantine vault must not be a symbolic link")
    vault.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = vault.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise OSError("Quarantine vault is not a directory")
    os.chmod(vault, 0o700)
    return vault


def _vault_file(record):
    vault = ensure_quarantine_vault().resolve(strict=True)
    path = Path(record["quarantine_path"])
    if path.is_symlink():
        raise OSError("Quarantined file cannot be a symbolic link")
    resolved = path.resolve(strict=True)
    if resolved.parent != vault:
        raise OSError("Invalid quarantine file location")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise OSError("Quarantined payload is not a regular file")
    return path


def _restore_vault_permissions(path):
    try:
        os.chmod(path, 0)
    except OSError:
        pass


def quarantine_file(file_path, threat_name=None, reason=None,
                    original_filename=None):
    source = Path(file_path)
    try:
        if source.is_symlink():
            return {"error": "Symbolic links cannot be quarantined"}
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode):
            return {"error": "Path is not a regular file"}
        source = source.resolve(strict=True)
    except FileNotFoundError:
        return {"error": "File does not exist"}
    except OSError as error:
        return {"error": f"Cannot access source file: {error}"}

    try:
        file_hash = calculate_sha256(str(source))
        if isinstance(file_hash, dict) or not isinstance(file_hash, str):
            return {"error": "Could not calculate file SHA-256"}
        file_info = identify_file(str(source))
        file_type = (
            file_info.get("detected_type", "Unknown")
            if isinstance(file_info, dict) and "error" not in file_info
            else "Unknown"
        )
        vault = ensure_quarantine_vault()
    except Exception as error:
        return {"error": f"Quarantine preparation failed: {error}"}

    original_mode = stat.S_IMODE(info.st_mode)
    qid = str(uuid.uuid4())
    target = vault / f"{qid}.quarantine"
    moved = False

    with _OPERATION_LOCK:
        try:
            # Destination name is unique; os.replace cannot overwrite a known item
            # because UUID names are generated for each operation.
            if target.exists() or target.is_symlink():
                return {"error": "Generated quarantine destination already exists"}
            shutil.move(str(source), str(target))
            moved = True
            os.chmod(target, 0)

            initialize_database()
            save_quarantine_record(
                quarantine_id=qid,
                original_path=str(source),
                original_filename=original_filename or source.name,
                quarantine_path=str(target),
                file_size=info.st_size,
                file_type=file_type,
                sha256=file_hash,
                threat_name=threat_name,
                reason=reason,
                original_permissions=info.st_mode,
                quarantine_status="quarantined",
            )
        except Exception as error:
            if moved:
                try:
                    os.chmod(target, original_mode)
                    if not source.exists():
                        shutil.move(str(target), str(source))
                except OSError as rollback_error:
                    return {
                        "error": (
                            f"Quarantine failed: {error}. Rollback also failed: "
                            f"{rollback_error}. File remains at {target}"
                        )
                    }
            return {"error": f"Quarantine failed and was rolled back: {error}"}

    return {
        "success": True,
        "quarantine_id": qid,
        "original_filename": original_filename or source.name,
        "original_path": str(source),
        "quarantine_path": str(target),
        "file_size": info.st_size,
        "file_type": file_type,
        "sha256": file_hash,
        "threat_name": threat_name,
        "reason": reason,
        "quarantine_status": "quarantined",
    }


def restore_quarantined_file(quarantine_id, destination_path=None):
    with _OPERATION_LOCK:
        record = get_quarantine_record(quarantine_id)
        if not record:
            return {"error": f"Quarantine record {quarantine_id} not found"}
        if record["quarantine_status"] != "quarantined":
            return {"error": f"File cannot be restored because its status is '{record['quarantine_status']}'"}

        try:
            source = _vault_file(record)
            os.chmod(source, stat.S_IRUSR)
            digest = calculate_sha256(str(source))
            if not isinstance(digest, str) or digest != record["sha256"]:
                return {"error": "Integrity check failed: SHA-256 mismatch"}
        except Exception as error:
            return {"error": f"Cannot verify quarantined file: {error}"}
        finally:
            # The file is returned to no-access mode after verification/copy.
            if "source" in locals() and source.exists():
                _restore_vault_permissions(source)

        destination = Path(destination_path or record["original_path"])
        try:
            parent = destination.parent.resolve(strict=True)
            destination = parent / destination.name
            if destination.is_symlink():
                return {"error": "Destination cannot be a symbolic link"}
            mode = stat.S_IMODE(record.get("original_permissions") or 0o600)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(destination, flags, mode)
        except FileExistsError:
            return {"error": f"Destination path already exists: {destination}"}
        except OSError as error:
            return {"error": f"Cannot create restoration destination: {error}"}

        try:
            os.chmod(source, stat.S_IRUSR)
            with os.fdopen(fd, "wb") as output, open(source, "rb") as input_file:
                shutil.copyfileobj(input_file, output)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(destination, mode)
        except Exception as error:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            _restore_vault_permissions(source)
            return {"error": f"Restoration failed: {error}"}
        finally:
            _restore_vault_permissions(source)

        timestamp = _now()
        try:
            changed = update_quarantine_status(
                quarantine_id, "restored", restored_at=timestamp,
                expected_status="quarantined"
            )
            if not changed:
                raise RuntimeError("Quarantine record changed during restoration")
        except Exception as error:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            return {"error": f"Database update failed; quarantined copy retained: {error}"}

        try:
            os.chmod(source, stat.S_IWUSR)
            source.unlink()
        except OSError as error:
            # Database says restored; retained vault payload is a safe duplicate
            # and is reported for manual cleanup rather than risking data loss.
            return {
                "error": (
                    f"File restored to {destination}, but vault cleanup failed: "
                    f"{error}. Retained payload: {source}"
                )
            }

        return {
            "success": True,
            "quarantine_id": quarantine_id,
            "restored_path": str(destination),
            "quarantine_status": "restored",
            "restored_at": timestamp,
        }


def delete_quarantined_file(quarantine_id):
    with _OPERATION_LOCK:
        record = get_quarantine_record(quarantine_id)
        if not record:
            return {"error": f"Quarantine record {quarantine_id} not found"}
        status = record["quarantine_status"]
        if status == "deleted":
            return {"error": "File has already been permanently deleted"}
        if status not in ("quarantined", "delete_pending"):
            return {"error": f"File cannot be deleted from status '{status}'"}

        try:
            source = _vault_file(record)
        except OSError as error:
            # A pending delete with a missing payload can be finalized safely.
            if status == "delete_pending" and "No such file" in str(error):
                source = None
            else:
                return {"error": f"Cannot validate quarantine payload: {error}"}

        if status == "quarantined":
            try:
                if not update_quarantine_status(
                    quarantine_id, "delete_pending",
                    expected_status="quarantined"
                ):
                    return {"error": "Quarantine record changed before deletion"}
            except Exception as error:
                return {"error": f"Could not prepare deletion: {error}"}

        if source is not None:
            try:
                os.chmod(source, stat.S_IWUSR)
                source.unlink()
            except OSError as error:
                try:
                    update_quarantine_status(
                        quarantine_id, "quarantined",
                        expected_status="delete_pending"
                    )
                except Exception:
                    pass
                return {"error": f"Failed to delete quarantined file: {error}"}

        timestamp = _now()
        try:
            if not update_quarantine_status(
                quarantine_id, "deleted", deleted_at=timestamp,
                expected_status="delete_pending"
            ):
                return {"error": "Payload deleted, but database finalization is pending"}
        except Exception as error:
            return {"error": f"Payload deleted; database finalization is pending: {error}"}

        return {
            "success": True,
            "quarantine_id": quarantine_id,
            "quarantine_status": "deleted",
            "deleted_at": timestamp,
        }


def list_quarantined_files(include_inactive=False):
    initialize_database()
    return list_quarantine_records(include_inactive=include_inactive)


def get_quarantined_file(quarantine_id):
    initialize_database()
    return get_quarantine_record(quarantine_id)
