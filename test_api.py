from fastapi.testclient import TestClient
from app.main import app

from unittest.mock import patch
import os

client = TestClient(app)

def test_successful_file_upload():
    file_path = "samples/clean_test.txt"

    with open(file_path, "rb") as file:
        response = client.post(
            "/scan",
            files={"file": ("clean_test.txt", file, "text/plain")}
        )

    assert response.status_code == 200

    data = response.json()

    assert data["uploaded_filename"] == "clean_test.txt"
    assert "file information" in data["analysis"]
    assert "sha256" in data["analysis"]
    assert "yara_analysis" in data["analysis"]
    assert "clamav_analysis" in data["analysis"]

def test_oversized_file_upload():
    large_content = b"A" * (20 * 1024 * 1024 + 1)

    response = client.post(
        "/scan",
        files={"file": ("large.txt", large_content, "text/plain")}
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "File exceeds the 20 MB upload limit."

def test_analysis_failure():
    with patch(
        "app.main.analyze_file",
        return_value={"error": "Simulated scanner failure"}
    ):
        response = client.post(
            "/scan",
            files={"file": ("test.txt", b"sample content", "text/plain")}
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "Simulated scanner failure"

def test_temporary_file_cleanup(monkeypatch):
    captured_path = {}

    def mock_analyze(file_path, rule_path, original_filename=None):
        captured_path["path"] = file_path
        return {"error": "Simulated failure"}

    monkeypatch.setattr("app.main.analyze_file", mock_analyze)

    response = client.post(
        "/scan",
        files={"file": ("test.txt", b"sample content", "text/plain")}
    )

    assert response.status_code == 500
    assert not os.path.exists(captured_path["path"])

def test_empty_file_upload():
    response = client.post(
        "/scan",
        files={"file": ("empty.txt", b"", "text/plain")}
    )

    assert response.status_code == 200
    assert response.json()["analysis"]["file information"]["file_size"] == 0

def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_missing_upload():
    response = client.post("/scan")

    assert response.status_code == 422

def test_filename_sanitization():
    response = client.post(
        "/scan",
        files={
            "file": (
                "../../malicious.pdf",
                b"sample content",
                "application/pdf"
            )
        }
    )

    assert response.status_code == 200
    assert response.json()["uploaded_filename"] == "malicious.pdf"


def test_windows_absolute_path_sanitization():
    response = client.post(
        "/scan",
        files={
            "file": (
                "C:\\Users\\evil\\payload.exe",
                b"sample content",
                "application/octet-stream"
            )
        }
    )

    assert response.status_code == 200
    assert response.json()["uploaded_filename"] == "payload.exe"


def test_windows_relative_path_sanitization():
    response = client.post(
        "/scan",
        files={
            "file": (
                "..\\..\\malware.txt",
                b"sample content",
                "text/plain"
            )
        }
    )

    assert response.status_code == 200
    assert response.json()["uploaded_filename"] == "malware.txt"


def test_null_byte_sanitization():
    response = client.post(
        "/scan",
        files={
            "file": (
                "innocent.txt\x00.exe",
                b"sample content",
                "text/plain"
            )
        }
    )

    assert response.status_code == 200
    assert "\x00" not in response.json()["uploaded_filename"]


def test_temp_file_permissions(monkeypatch):
    captured = {}

    def mock_analyze(file_path, rule_path, original_filename=None):
        file_stat = os.stat(file_path)
        captured["mode"] = file_stat.st_mode
        captured["path"] = file_path
        return {"error": "Simulated failure"}

    monkeypatch.setattr("app.main.analyze_file", mock_analyze)

    response = client.post(
        "/scan",
        files={"file": ("test.txt", b"sample content", "text/plain")}
    )

    assert response.status_code == 500
    assert captured["mode"] & 0o777 == 0o600
    assert not os.path.exists(captured["path"])


def test_oversized_file_cleanup(monkeypatch):
    removed = []
    original_remove = os.remove

    def track_remove(path):
        removed.append(path)
        original_remove(path)

    monkeypatch.setattr(os, "remove", track_remove)

    large_content = b"A" * (20 * 1024 * 1024 + 1)

    response = client.post(
        "/scan",
        files={"file": ("large.txt", large_content, "text/plain")}
    )

    assert response.status_code == 413
    assert len(removed) >= 1
    assert not os.path.exists(removed[0])
