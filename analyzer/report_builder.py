from analyzer.file_identifier import identify_file
from analyzer.hash_analyzer import calculate_sha256
from analyzer.yara_analyzer import scan_with_yara
from analyzer.clamav_analyzer import scan_with_clamav

def analyze_file(file_path, rule_path, original_filename=None):
    file_info = identify_file(file_path)

    if "error" in file_info:
        return file_info
    
    file_hash = calculate_sha256(file_path)

    yara_result = scan_with_yara(file_path, rule_path)

    clamav_result = scan_with_clamav(file_path)

    display_filename = original_filename or file_info["filename"]

    file_info["filename"] = display_filename
    yara_result["filename"] = display_filename
    clamav_result["filename"] = display_filename

    return {
        "file information": file_info,
        "sha256": file_hash,
        "yara_analysis": yara_result,
        "clamav_analysis": clamav_result
    }