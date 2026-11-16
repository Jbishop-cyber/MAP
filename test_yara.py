from core.yara_analyzer import scan_with_yara


def test_clean_file_has_no_yara_matches():
    result = scan_with_yara(
        "samples/clean_test.txt",
        "rules/test_rule.yar"
    )

    assert result["matches_found"] == 0

def test_missing_file_returns_error():
    result = scan_with_yara(
        "samples/nonexistent.txt",
        "rules/test_rule.yar"
    )

    assert "error" in result
    assert result["error"] == "File does not exist"

def test_invalid_yara_rule_returns_error():
    result = scan_with_yara(
        "samples/clean_test.txt",
        "samples/clean_test.txt"
    )

    assert "error" in result
    assert "YARA rule error" in result["error"]
