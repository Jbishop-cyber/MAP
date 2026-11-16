import os
import subprocess

def scan_with_clamav(file_path):
    if not os.path.isfile(file_path):
        return {"error": "File does not exist"}
    
    try:
        result = subprocess.run(
            ["clamscan", file_path],
            capture_output=True,
            text=True,
            timeout=60
        )

    except FileNotFoundError:
        return {
            "error": "ClamAV is not installed or clamscan is unavailable"
        }

    except subprocess.TimeoutExpired:
        return {
            "error": "ClamAV scan timed out"
        }
    except Exception as error:
        return {
            "error": f"ClamAV scanning failed: {error}"
        }

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

