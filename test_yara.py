from core.yara_analyzer import scan_with_yara


def test_clean_file_has_no_yara_matches():
    result = scan_with_yara(
        "samples/clean_test.txt",
        "rules/test_rule.yar"
    )

    assert result["matches_found"] == 0
    