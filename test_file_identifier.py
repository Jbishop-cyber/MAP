import pytest
import os
import json

from core.file_identifier import (
    identify_file,
    detect_file_signature,
    detect_text_file_type,
    check_extension_mismatch,
    validate_json_file
)

def test_identify_file_permission_error(monkeypatch):
    def mock_getsize(file_path):
        raise PermissionError

    monkeypatch.setattr(os.path, "getsize", mock_getsize)

    result = identify_file("samples/clean_test.txt")

    assert "error" in result
    assert "Permission denied" in result["error"]

def test_identify_file_missing_file():
    result = identify_file("samples/nonexistent.txt")

    assert "error" in result
    assert result["error"] == "File does not exist"

def test_identify_file_directory():
    result = identify_file("samples")

    assert "error" in result
    assert result["error"] == "Path is not a file"

def test_identify_file_success():
    result = identify_file("samples/clean_test.txt")

    assert result["filename"] == "clean_test.txt"
    assert result["extension"] == ".txt"
    assert result["file_size"] > 0
    assert result["mime_type"] == "text/plain"

def test_detect_png_signature(tmp_path):
    test_file = tmp_path / "test.png"
    test_file.write_bytes(bytes.fromhex("89504E470D0A1A0A"))

    result = detect_file_signature(test_file)

    assert result == "PNG"

def test_detect_pdf_signature(tmp_path):
    test_file = tmp_path / "test.pdf"
    test_file.write_bytes(bytes.fromhex("25504446"))

    result = detect_file_signature(test_file)

    assert result == "PDF"

def test_detect_unknown_signature(tmp_path):
    test_file = tmp_path / "unknown.bin"
    test_file.write_bytes(b"Hello Sentrix")

    result = detect_file_signature(test_file)

    assert result == "Unknown"

def test_detect_extension_signature(tmp_path):
    test_file = tmp_path / "fake.pdf"
    test_file.write_bytes(bytes.fromhex("89504E470D0A1A0A"))

    result = identify_file(str(test_file))

    assert result["extension"] == ".pdf"
    assert result["detected_type"] == "PNG"

def test_detect_html_content(tmp_path):
    test_file = tmp_path / "fake.pdf"
    test_file.write_text(
        "<!DOCTYPE html><html><body>Hello</body></html>"
    )

    result = detect_text_file_type(test_file)

    assert result == "HTML"

def test_detect_xml_content(tmp_path):
    test_file = tmp_path / "fake.pdf"
    test_file.write_text(
        '<?xml version="1.0"?><root><name>Sentrix</name></root>'
    )

    result = detect_text_file_type(test_file)

    assert result == "XML"

def test_detect_json_content(tmp_path):
    test_file = tmp_path / "fake.pdf"
    test_file.write_text(
        '{"name": "Sentrix", "type": "security"}'
    )

    result = detect_text_file_type(test_file)

    assert result == "JSON"

def test_identify_file_signature_error(monkeypatch):
    def mock_detect_file_signature(file_path):
        return {"error": "Permission denied"}

    monkeypatch.setattr(
        "core.file_identifier.detect_file_signature",
        mock_detect_file_signature
    )

    result = identify_file("samples/clean_test.txt")

    assert "error" in result
    assert result["error"] == "Permission denied"

def test_extension_matches_content():
    result = check_extension_mismatch(".pdf", "PDF")
    assert result is False


def test_extension_mismatch():
    result = check_extension_mismatch(".pdf", "HTML")
    assert result is True


def test_unknown_extension():
    result = check_extension_mismatch(".xyz", "HTML")
    assert result is False

def test_validate_json_file_valid(tmp_path):
    test_file = tmp_path / "valid.json"
    test_file.write_text('{"name": "Sentrix", "version": "0.2"}')

    result = validate_json_file(test_file)

    assert result is True

def test_validate_json_file_invalid(tmp_path):
    test_file = tmp_path / "invalid.json"
    test_file.write_text('{"name": "Sentrix"')

    result = validate_json_file(test_file)

    assert result is False

def test_validate_json_file_empty(tmp_path):
    test_file = tmp_path / "empty.json"
    test_file.write_text("")

    result = validate_json_file(test_file)

    assert result is False

def test_validate_large_json_file(tmp_path):
    test_file = tmp_path / "large.json"

    large_data = {
        "name": "Sentrix",
        "records": ["security analysis"] * 1000
    }

    test_file.write_text(json.dumps(large_data))

    assert test_file.stat().st_size > 4096
    assert validate_json_file(test_file) is True
