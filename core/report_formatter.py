def format_report(report):
    file_info = report["file information"]
    file_hash = report["sha256"]
    yara_result = report["yara_analysis"]
    clamav_result = report["clamav_analysis"]

    # Determine YARA status
    if yara_result.get("matches_found", 0) > 0:
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

    # Determine overall assessment
    if clamav_status == "infected":
        overall_status = "DETECTED"
        reason = "ClamAV identified a known threat signature."

    elif yara_result.get("matches_found", 0) > 0:
        overall_status = "FLAGGED FOR REVIEW"
        reason = "YARA-X identified matching rules requiring investigation."

    elif clamav_status == "error" or "error" in yara_result:
        overall_status = "SCAN ERROR"
        reason = "One or more security scans could not be completed."

    else:
        overall_status = "NO DETECTION"
        reason = "No threats were detected by the configured scanners."

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

OVERALL ASSESSMENT
--------------------------------------------------
Result:         {overall_status}
Reason:         {reason}

==================================================
"""

    return output

