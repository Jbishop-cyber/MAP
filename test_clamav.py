from core.clamav_analyzer import scan_with_clamav


def test_clamav_scans_clean_file():
    result = scan_with_clamav("samples/test.txt")

    assert result["scan_status"] == "no_detection"
