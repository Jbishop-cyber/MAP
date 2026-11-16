import pytest
import os

from core.file_identifier import identify_file

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
