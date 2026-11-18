import os
import mimetypes
import json

FILE_SIGNATURES = {
    "PNG": bytes.fromhex("89504E470D0A1A0A"),
    "JPEG": bytes.fromhex("FFD8FF"),
    "PDF": bytes.fromhex("25504446"),
    "ZIP": bytes.fromhex("504B0304"),
    "EXE": bytes.fromhex("4D5A")
}

EXTENSION_TYPES = {
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".pdf": "PDF",
    ".zip": "ZIP",
    ".exe": "EXE",
    ".html": "HTML",
    ".htm": "HTML",
    ".xml": "XML",
    ".json": "JSON"
}

def detect_file_signature(file_path):
    try:
        with open(file_path, "rb") as file:
            file_header = file.read(8)
    except OSError as error:
        return {"error": str(error)}
    
    for file_type, signature in FILE_SIGNATURES.items():
        if file_header.startswith(signature):
            return file_type
    
    return "Unknown"

def identify_file(file_path):
    if not os.path.exists(file_path):
        return {"error": "File does not exist"}
    
    if not os.path.isfile(file_path):
        return {"error": "Path is not a file"}
    
    filename = os.path.basename(file_path)
    extension = os.path.splitext(filename)[1]
    try:
        file_size = os.path.getsize(file_path)

    except PermissionError:
        return {"error": "Permission denied: Cannot access file"}

    except OSError as error:
        return {"error": f"File identification failed: {error}"}

    mime_type, encoding = mimetypes.guess_type(file_path)

    detected_type = detect_file_signature(file_path)

    if isinstance(detected_type, dict):
        return detected_type

    if detected_type == "Unknown":
        detected_type = detect_text_file_type(file_path)
    
    extension_mismatch = check_extension_mismatch(
        extension,
        detected_type
    )

    return {
        "filename": filename,
        "extension": extension,
        "file_size": file_size,
        "mime_type": mime_type or "Unknown",
        "detected_type": detected_type,
        "extension_mismatch": extension_mismatch
    }

def detect_text_file_type(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read(4096).lstrip()
    except (OSError, UnicodeDecodeError):
        return "Unknown"
    
    if not content:
        return "Unknown"
    
    lowered_content = content.lower()

    # HTML detection
    if any(marker in lowered_content[:500] for marker in [
        "<!doctype html",
        "<html",
        "<head",
        "<body"
    ]):
        return "HTML"
    
    # XML detection
    if lowered_content.startswith("<?xml"):
        return "XML"
    
    # JSON detection
    try:
        json.loads(content)
        return "JSON"
    except json.JSONDecodeError:
        pass

    return "Unknown"

def check_extension_mismatch(extension, detected_type):
    expected_type = EXTENSION_TYPES.get(extension.lower())

    if expected_type is None or detected_type == "Unknown":
        return False

    return expected_type != detected_type

