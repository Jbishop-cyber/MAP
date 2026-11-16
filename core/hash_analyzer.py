import os
import hashlib


def calculate_sha256(file_path):
    if not os.path.isfile(file_path):
        return {"error": "File does not exist"}

    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(65536):
                sha256_hash.update(chunk)

    except PermissionError:
        return {"error": "Permission denied: Cannot access file"}

    except OSError as error:
        return {"error": f"Hash calculation failed: {error}"}

    return sha256_hash.hexdigest()
