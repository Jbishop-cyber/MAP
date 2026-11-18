# SENTRIX
### Intelligent File Security & Threat Analysis
**See Beyond the File.**

Sentrix is a local-first file security and malware analysis platform designed to help users identify potentially harmful files through multiple layers of security analysis.

It combines file identification, SHA-256 fingerprinting, YARA-X rule-based detection, and ClamAV antivirus scanning to provide a structured security assessment.

The current version is a functional prototype focused on file analysis, threat detection, and security reporting.

---

## Features

### 1. File Identification
- Identifies supported file types using binary signatures.
- Detects common file formats, including PNG, JPEG, PDF, ZIP, and EXE.
- Identifies text-based formats such as HTML, XML, and JSON.
- Detects mismatches between file extensions and detected content.
- Helps identify files disguised using misleading extensions.

### 2. SHA-256 File Fingerprinting
- Generates SHA-256 hashes for uploaded files.
- Uses chunk-based file reading to process files efficiently.
- Provides unique file fingerprints for identification and verification.

### 3. YARA-X Analysis
- Scans files against configured YARA-X detection rules.
- Identifies files containing patterns that match configured rules.
- Reports matching rules for further investigation.

### 4. ClamAV Antivirus Integration
- Uses ClamAV to scan uploaded files.
- Identifies known malware signatures.
- Distinguishes between clean scan results, detected threats, and scanning errors.

### 5. Security Assessment and Reporting
Combines analysis results to produce an overall assessment:

- **NO DETECTION:** No threats detected by the configured scanners.
- **THREAT DETECTED:** ClamAV identified a known threat.
- **FLAGGED FOR REVIEW:** A YARA-X rule matched or a file extension mismatch was detected.
- **SCAN ERROR:** One or more security scans could not be completed.

Reports include file information, SHA-256 fingerprints, YARA-X results, ClamAV results, and security assessments.

### 6. Web Dashboard
- Browser-based file upload and scanning.
- Visual presentation of analysis results.
- Security status indicators.
- File information and extension mismatch warnings.
- Analysis summaries.

### 7. Scan History
- Records completed scan results in an SQLite database.
- Provides access to previous scans.
- Displays scan history through the dashboard.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| FastAPI | Backend API |
| SQLite | Scan history storage |
| YARA-X | Rule-based file analysis |
| ClamAV | Antivirus scanning |
| SHA-256 | File fingerprinting |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Frontend interactions |
| Pytest | Automated testing |

---

## Project Structure

```text
MAP/
│
├── app/
│   ├── main.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
│
├── core/
│   ├── file_identifier.py
│   ├── hash_analyzer.py
│   ├── yara_analyzer.py
│   ├── clamav_analyzer.py
│   ├── report_builder.py
│   ├── report_formatter.py
│   └── database.py
│
├── rules/
│   └── test_rule.yar
│
├── samples/
│
├── data/
│
├── test_api.py
├── test_file_identifier.py
├── test_hash_analyzer.py
├── test_yara.py
├── test_clamav.py
├── test_report.py
│
├── requirements.txt
└── README.md
```

---

## Installation and Setup

### Prerequisites

- Python 3.12 or later.
- ClamAV installed and available through the `clamscan` command.
- YARA-X and the project's Python dependencies installed.

### 1. Clone the repository

```bash
git clone https://github.com/Jbishop-cyber/MAP.git
cd MAP
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate the environment

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

Ensure ClamAV and YARA-X are installed and configured for the application.

### 5. Start the application

```bash
uvicorn app.main:app --reload
```

Open the dashboard in your browser:

```text
http://127.0.0.1:8000
```

---

## Running Tests

Sentrix uses Pytest for automated testing.

Run the complete test suite:

```bash
pytest -v
```

### Current Test Status

**47 tests passing.**

The tests cover major application components, including:

- File identification.
- File signature detection.
- File extension mismatch detection.
- SHA-256 hashing.
- YARA-X analysis.
- ClamAV integration.
- Report generation.
- API functionality.

---

## Security and Privacy

Sentrix is designed around a local-first security approach.

Important design principles:

- Uploaded files are processed locally by the application.
- Files are not intentionally submitted to external malware analysis services.
- File analysis errors must not be reported as clean results.
- Testing should use harmless files and the EICAR antivirus test file.
- Real malware must never be executed as part of testing.

The current prototype is not a replacement for a fully deployed endpoint protection solution.

---

## Development Roadmap

Future development will focus on expanding Sentrix beyond manual file scanning.

Planned capabilities include:

- Automatic file monitoring.
- Website and URL threat analysis.
- Suspicious download detection.
- Threat intelligence integrations.
- File quarantine and restoration.
- Desktop security agent.
- Browser security integration.
- Expanded cross-platform support.

These capabilities are planned extensions and are not all implemented in the current version.

---

## Project Status

**Current Stage:** Functional Prototype / MVP Development

Sentrix currently provides a working file analysis pipeline with multiple detection mechanisms, security reporting, a browser-based dashboard, scan history, and automated tests.

Development is ongoing, with a focus on reliability, security, and expanding detection capabilities.

---

## Author

**Justice Bishop**

GitHub: [Jbishop-cyber](https://github.com/Jbishop-cyber)
