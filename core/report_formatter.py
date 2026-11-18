def get_overall_status(report):
    yara_result = report["yara_analysis"]

    clamav_result = report["clamav_analysis"]
    clamav_status = clamav_result.get("scan_status", "error")

    file_info = report["file information"]
    extension_mismatch = file_info.get("extension_mismatch", False)

    if "error" in yara_result or clamav_status == "error":
        return (
            "SCAN ERROR",
            "One or more security scans could not be completed."
        )
    elif clamav_status == "infected":
        return (
            "DETECTED",
            "ClamAV identified a known threat signature."
        )
    elif yara_result.get("matches_found", 0) > 0:
        return (
            "FLAGGED FOR REVIEW",
            "YARA-X identified matching rules requiring investigation."
        )
    elif extension_mismatch:
        return (
            "FLAGGED FOR REVIEW",
            "File extension does not match detected file content."
        )
    else:
        return (
            "NO DETECTION",
            "No threats were detected by the cofigured scanners."
        )

def format_report(report):
    file_info = report["file information"]
    file_hash = report["sha256"]
    yara_result = report["yara_analysis"]
    clamav_result = report["clamav_analysis"]
    detected_type = file_info.get("detected_type", "Unknown")
    extension_mismatch = file_info.get("extension_mismatch", False)

    if extension_mismatch:
        extension_warning = "WARNING: File extension does not match detected content!"
    else:
        extension_warning = "No extension mismatch detected."

    # Determine YARA status
    if "error" in yara_result:
        yara_status = "SCAN ERROR"
        yara_detections = yara_result["error"]

    elif yara_result.get("matches_found", 0) > 0:
        yara_status = "MATCHES FOUND"
        yara_detections = ", ".join(yara_result["detections"])

    else:
        yara_status = "NO MATCHING RULES"
        yara_detections = "None"

    # Determine ClamAV status
    clamav_status = clamav_result.get("scan_status", "error")

    if clamav_status == "infected":
        clamav_display = "THREAT DETECTED"
    elif clamav_status == "no_detection":
        clamav_display = "NO DETECTION"
    else:
        clamav_display = "SCAN ERROR"

    clamav_error = clamav_result.get("error", "None")

    overall_status, reason = get_overall_status(report)

    # Build report
    output = f"""
==================================================
          MALWARE ANALYSIS PLATFORM
                  SCAN REPORT
==================================================

FILE INFORMATION
--------------------------------------------------
Filename:       {file_info['filename']}
Extension:      {file_info['extension']}
File Size:      {file_info['file_size']} bytes
MIME Type:      {file_info['mime_type']}
Detected Type: {detected_type}
Extension Check: {extension_warning}

FILE FINGERPRINT
--------------------------------------------------
SHA-256:
{file_hash}

YARA-X ANALYSIS
--------------------------------------------------
Status:         {yara_status}
Matches Found:  {yara_result.get('matches_found', 0)}
Detections:     {yara_detections}

CLAMAV ANALYSIS
--------------------------------------------------
Status:         {clamav_display}
Return Code:    {clamav_result.get('return_code', 'N/A')}
Error Details:  {clamav_error}

OVERALL ASSESSMENT
--------------------------------------------------
Result:         {overall_status}
Reason:         {reason}

==================================================
"""

    return output

