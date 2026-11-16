import hashlib
import builtins
import pytest

from core.hash_analyzer import calculate_sha256

def test_sha256_permission_error(monkeypatch):
    original_open = builtins.open

    def mock_open(file_path, mode="r", *args, **kwargs):
        if mode == "rb":
            raise PermissionError

        return original_open(file_path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", mock_open)

    result = calculate_sha256("samples/clean_test.txt")

    assert "error" in result
    assert "Permission denied" in result["error"]

def test_sha256_calculation():
    file_path = "samples/clean_test.txt"

    result = calculate_sha256(file_path)

    with open(file_path, "rb") as file:
        expected_hash = hashlib.sha256(file.read()).hexdigest()

    assert result == expected_hash


def test_sha256_missing_file():
    result = calculate_sha256("samples/nonexistent.txt")

    assert "error" in result
    assert result["error"] == "File does not exist"


def test_sha256_empty_file(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    result = calculate_sha256(str(empty_file))

    assert result == hashlib.sha256(b"").hexdigest()
