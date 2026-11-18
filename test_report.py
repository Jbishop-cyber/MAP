from pathlib import Path
from core.report_builder import analyze_file
from core.report_formatter import format_report, get_overall_status


def test_report_generation():
    report = analyze_file(
        "samples/yara_test.txt",
        "rules/test_rule.yar"
    )

    assert "file information" in report
    assert "sha256" in report
    assert "yara_analysis" in report
    assert "clamav_analysis" in report


def test_report_formatting():
    report = analyze_file(
        "samples/yara_test.txt",
        "rules/test_rule.yar"
    )

    formatted_report = format_report(report)

    assert isinstance(formatted_report, str)
    assert "FILE INFORMATION" in formatted_report
    assert "YARA-X ANALYSIS" in formatted_report
    assert "CLAMAV ANALYSIS" in formatted_report
    assert "OVERALL ASSESSMENT" in formatted_report

def test_yara_error_produces_scan_error():
    report = {
        "file information": {
            "filename": "test.txt",
            "extension": ".txt",
            "file_size": 100,
            "mime_type": "text/plain"
        },
        "sha256": "test_hash",
        "yara_analysis": {
            "error": "YARA rule error: invalid syntax"
        },
        "clamav_analysis": {
            "scan_status": "no_detection",
            "return_code": 0
        }
    }

    formatted_report = format_report(report)

    assert "SCAN ERROR" in formatted_report
    assert "YARA rule error" in formatted_report

def test_clamav_error_produces_scan_error():
    report = {
        "file information": {
            "filename": "test.txt",
            "extension": ".txt",
            "file_size": 100,
            "mime_type": "text/plain"
        },
        "sha256": "test_hash",
        "yara_analysis": {
            "matches_found": 0,
            "detections": []
        },
        "clamav_analysis": {
            "error": "ClamAV scan timed out"
        }
    }

    formatted_report = format_report(report)

    assert "SCAN ERROR" in formatted_report
    assert "ClamAV scan timed out" in formatted_report

def test_successful_scan_produces_assessment():
    report = {
        "file information": {
            "filename": "test.txt",
            "extension": ".txt",
            "file_size": 100,
            "mime_type": "text/plain"
        },
        "sha256": "test_hash",
        "yara_analysis": {
            "matches_found": 0,
            "detections": []
        },
        "clamav_analysis": {
            "scan_status": "no_detection",
            "return_code": 0
        }
    }

    formatted_report = format_report(report)

    assert "OVERALL ASSESSMENT" in formatted_report
    assert "NO DETECTION" in formatted_report
    assert "YARA-X" in formatted_report

def test_clamav_detection_produces_detected():
    report = {
        "file information": {
            "filename": "test.txt",
            "extension": ".txt",
            "file_size": 100,
            "mime_type": "text/plain"
        },
        "sha256": "test_hash",
        "yara_analysis": {
            "matches_found": 0,
            "detections": []
        },
        "clamav_analysis": {
            "scan_status": "infected",
            "detections": ["EICAR_Test_File"],
            "return_code": 1
        }
    }

    formatted_report = format_report(report)

    assert "OVERALL ASSESSMENT" in formatted_report
    assert "DETECTED" in formatted_report
    assert "ClamAV identified" in formatted_report

def test_yara_rule_path_works_from_different_directory(monkeypatch, tmp_path):
    project_root = Path(__file__).resolve().parent

    sample_path = project_root / "samples" / "yara_test.txt"

    # Change the working directory to a temporary directory
    monkeypatch.chdir(tmp_path)

    report = analyze_file(
        str(sample_path),
        "rules/test_rule.yar"
    )

    assert "error" not in report["yara_analysis"]
    assert report["yara_analysis"]["matches_found"] > 0

def test_hash_error_stops_report_generation(monkeypatch):
    def mock_hash(file_path):
        return {"error": "Permission denied: Cannot access file"}

    monkeypatch.setattr("core.report_builder.calculate_sha256", mock_hash)

    report = analyze_file("samples/clean_test.txt", "rules/test_rule.yar")

    assert "error" in report
    assert report["error"] == "Permission denied: Cannot access file"

def test_extension_mismatch_flagged_for_review():
    report = {
        "file information": {
            "extension_mismatch": True
        },
        "yara_analysis": {
            "matches_found": 0
        },
        "clamav_analysis": {
            "scan_status": "no_detection"
        }
    }

    status, reason = get_overall_status(report)

    assert status == "FLAGGED FOR REVIEW"
    assert "extension" in reason.lower()

