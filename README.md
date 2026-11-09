# Malware Analysis Platform (MAP)

A local-first hybrid Malware Analysis Platform built with Python. It combines static file analysis, signature-based malware detection, and a web interface to help users inspect suspicious files and identify potential threats.

## Project Overview

The Malware Analysis Platform (MAP) is designed to provide a simple environment for analysing files using multiple security tools.

The current prototype integrates:

- File identification
- SHA-256 file hashing
- YARA-X rule-based scanning
- ClamAV antivirus scanning
- Automated analysis report generation
- FastAPI backend
- Browser-based file upload and analysis interface

The platform is designed to analyse files without executing them.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| FastAPI | Backend API |
| YARA-X | Rule-based threat detection |
| ClamAV | Antivirus scanning |
| hashlib | SHA-256 hashing |
| HTML | Dashboard structure |
| JavaScript | Dashboard interaction |
| Uvicorn | ASGI server |

## Project Structure

```text
MAP/
│
├── analyzer/
│   ├── __init__.py
│   ├── file_identifier.py
│   ├── hash_analyzer.py
│   ├── yara_analyzer.py
│   ├── clamav_analyzer.py
│   ├── report_builder.py
│   └── report_formatter.py
│
├── app/
│   ├── __init__.py
│   └── main.py
│
├── rules/
│   └── test_rule.yar
│
├── samples/
│   ├── test.txt
│   ├── yara_test.txt
│   └── clean_test.txt
│
├── requirements.txt
├── README.md
└── .gitignore
```

## Features

### 1. File Identification
Extracts basic file information, including:
- Filename
- File extension
- File size
- MIME type

### 2. SHA-256 Hashing
Generates a SHA-256 cryptographic hash to provide a unique fingerprint of the analysed file.

### 3. YARA-X Scanning
Uses YARA-X rules to identify files containing predefined suspicious patterns.

### 4. ClamAV Scanning
Integrates ClamAV to scan uploaded files against its antivirus signature database.

### 5. Automated Analysis Reports
Combines the results from the analysis components into a structured report containing file information, hash values, scanner results, and an overall assessment.

### 6. FastAPI Web Interface
Provides a browser-based interface for uploading files and viewing their analysis results.

## Installation

### Prerequisites

- Python 3.12 or later
- pip
- ClamAV
- Ubuntu/Linux environment recommended

### 1. Clone the repository

```bash
git clone <repository-url>
cd MAP
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install ClamAV

On Ubuntu:

```bash
sudo apt update
sudo apt install clamav clamav-daemon -y
```

Update antivirus signatures:

```bash
sudo freshclam
```

If the automatic FreshClam service is already updating the database, allow it to finish rather than starting another update process.

### 5. Start the application

From the project root:

```bash
python -m uvicorn app.main:app --reload
```

Open the dashboard:

```text
http://127.0.0.1:8000/
```

FastAPI interactive documentation:

```text
http://127.0.0.1:8000/docs
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Opens the web dashboard |
| GET | `/health` | Checks application health |
| POST | `/scan` | Uploads and analyses a file |

The upload endpoint currently enforces a 20 MB file-size limit.

## Analysis Workflow

1. A user uploads a file through the dashboard.
2. FastAPI receives the uploaded file.
3. The file is temporarily stored for analysis.
4. The analysis engine identifies the file.
5. SHA-256 hashing is performed.
6. YARA-X scans the file using the configured rules.
7. ClamAV performs antivirus scanning.
8. The results are combined into an analysis report.
9. The API returns the report.
10. The temporary uploaded file is deleted.

Uploaded files are not executed by the platform.

## Threat Assessment

The platform uses the scanner results to determine an overall assessment.

| Assessment | Meaning |
|---|---|
| DETECTED | ClamAV identified a known threat signature. |
| FLAGGED FOR REVIEW | YARA-X identified a matching rule requiring investigation. |
| NO DETECTION | No threats were detected by the configured scanners. |
| SCAN ERROR | One or more security scans could not be completed. |

**Important:** A result of NO DETECTION does not guarantee that a file is safe. It only means that the configured scanners did not identify a threat.

## Testing

The project uses harmless test files to verify its analysis components.

- `yara_test.txt` tests YARA-X rule matching.
- `clean_test.txt` tests scanning without a matching YARA rule.
- ClamAV integration can be tested with the official EICAR antivirus test file.

The EICAR test file is a harmless antivirus test signature, not actual malware. It should never be executed.

## Current Development Status

| Component | Status |
|---|---|
| File identification | Completed |
| SHA-256 hashing | Completed |
| YARA-X integration | Completed |
| ClamAV integration | Completed |
| Combined analysis engine | Completed |
| Human-readable terminal report | Completed |
| FastAPI backend | Completed |
| File upload endpoint | Completed |
| Browser-based analysis interface | Functional |
| Dashboard visual improvements | Planned |

## Future Development

Planned improvements include:

- Improved cybersecurity-themed dashboard.
- More comprehensive analysis reports.
- Better file identification using file signatures.
- Expanded YARA-X detection rules.
- Improved error handling and logging.
- Evidence preservation and quarantine management.
- URL analysis.
- Desktop protection application.

## Security Considerations

- Uploaded files are analysed without execution.
- Uploaded files are temporarily stored and removed after analysis.
- File uploads are currently limited to 20 MB.
- The current implementation is a local-first prototype, not a production malware analysis service.
- A clean scan should never be interpreted as proof that a file is completely safe.

## Project Goal

The long-term goal is to develop a hybrid Malware Analysis Platform that combines web-based malware analysis with desktop-level protection capabilities.

---

**Project:** Malware Analysis Platform (MAP)  
**Version:** 0.1.0  
**Status:** Prototype in development