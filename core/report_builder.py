from pathlib import Path

from core.file_identifier import identify_file
from core.hash_analyzer import calculate_sha256
from core.yara_analyzer import scan_with_yara
from core.clamav_analyzer import scan_with_clamav

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def analyze_file(file_path, rule_path, original_filename=None):
    file_info = identify_file(file_path)

    if "error" in file_info:
        return file_info
    
    file_hash = calculate_sha256(file_path)
    if isinstance(file_hash, dict) and "error" in file_hash:
        return {"error": file_hash["error"]}

    rule_path = Path(rule_path)

    if not rule_path.is_absolute():
        rule_path = PROJECT_ROOT / rule_path

    yara_result = scan_with_yara(file_path, str(rule_path))

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
