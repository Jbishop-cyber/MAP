import subprocess

from core.clamav_analyzer import scan_with_clamav

def test_clamav_scans_clean_file():
    result = scan_with_clamav("samples/test.txt")

    assert result["scan_status"] == "no_detection"

def test_missing_file_returns_error():
    result = scan_with_clamav("samples/nonexistent.txt")

    assert "error" in result
    assert result["error"] == "File does not exist"

def test_missing_clamav_returns_error(monkeypatch):
    def mock_run(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(
        "core.clamav_analyzer.subprocess.run",
        mock_run
    )

    result = scan_with_clamav("samples/test.txt")

    assert "error" in result
    assert "ClamAV is not installed" in result["error"]

def test_clamav_timeout_returns_error(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired("clamscan", 60)

    monkeypatch.setattr(
        "core.clamav_analyzer.subprocess.run",
        mock_run
    )

    result = scan_with_clamav("samples/test.txt")

    assert "error" in result
    assert result["error"] == "ClamAV scan timed out"
