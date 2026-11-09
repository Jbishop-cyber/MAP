import os
import subprocess

def scan_with_clamav(file_path):
    if not os.path.isfile(file_path):
        return {"error": "File does not exist"}
    
    result = subprocess.run(
        ["clamscan", file_path],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        status = "no_detection"
    elif result.returncode == 1:
        status = "infected"
    else:
        status = "error"

    return {
        "filename": os.path.basename(file_path),
        "scan_status": status,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }

