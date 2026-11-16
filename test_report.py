from core.report_builder import analyze_file
from core.report_formatter import format_report


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