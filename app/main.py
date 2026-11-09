import os
import tempfile

from pathlib import Path

from fastapi import FastAPI
from fastapi import UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse

from analyzer.report_builder import analyze_file


app = FastAPI(
    title="Malware Analysis Platform",
    description="A local-first platform for file analysis and threat detection.",
    version="0.1.0"
)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Malware Analysis Platform</title>
    </head>

    <body>
        <h1>Malware Analysis Platform</h1>

        <p>Status: <strong>Online</strong></p>

        <h2>File Analysis</h2>

        <form id="scanForm">
            <input type="file" id="fileInput" required>
            <button type="submit">Scan File</button>
        </form>

        <h2>Analysis Results</h2>

        <div id="results">
            <p>No file scanned yet.</p>
        </div>

        <script>
            const form = document.getElementById("scanForm");

            form.addEventListener("submit", async function(event) {
                event.preventDefault();

                const file = document.getElementById("fileInput").files[0];

                if (!file) {
                    return;
                }

                const formData = new FormData();
                formData.append("file", file);

                const results = document.getElementById("results");
                results.textContent = "Scanning file...";

                try {
                    const response = await fetch("/scan", {
                        method: "POST",
                        body: formData
                    });

                    const data = await response.json();

                    if (!response.ok) {
                        results.textContent = "Error: " + data.detail;
                        return;
                    }

                    const report = data.analysis;

                    const fileInfo = report["file information"];
                    const yara = report.yara_analysis;
                    const clamav = report.clamav_analysis;

                    let overallStatus = "NO DETECTION";

                    if (clamav.scan_status === "infected") {
                        overallStatus = "THREAT DETECTED";
                    } else if (yara.matches_found > 0) {
                        overallStatus = "FLAGGED FOR REVIEW";
                    } else if (clamav.scan_status === "error" || yara.error) {
                        overallStatus = "SCAN ERROR";
                    }

                    results.innerHTML = `
                        <h3>Overall Assessment: ${overallStatus}</h3>

                        <h4>File Information</h4>
                        <p><strong>Filename:</strong> ${fileInfo.filename}</p>
                        <p><strong>Extension:</strong> ${fileInfo.extension}</p>
                        <p><strong>File Size:</strong> ${fileInfo.file_size} bytes</p>
                        <p><strong>MIME Type:</strong> ${fileInfo.mime_type}</p>

                        <h4>File Fingerprint</h4>
                        <p><strong>SHA-256:</strong> ${report.sha256}</p>

                        <h4>YARA-X Analysis</h4>
                        <p><strong>Matches Found:</strong> ${yara.matches_found}</p>
                        <p><strong>Detections:</strong> ${yara.detections.join(", ") || "None"}</p>

                        <h4>ClamAV Analysis</h4>
                        <p><strong>Status:</strong> ${clamav.scan_status}</p>
                        <p><strong>Return Code:</strong> ${clamav.return_code}</p>
                    `;

                } catch (error) {
                    results.textContent = "Error: " + error.message;
                }
            });
        </script>
    </body>
    </html>
    """


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):

    filename = file.filename or "uploaded_file"
    suffix = Path(filename).suffix

    temp_path = None
    max_size = 20 * 1024 * 1024  # 20 MB
    uploaded_size = 0

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as temp_file:

            temp_path = temp_file.name

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                uploaded_size += len(chunk)

                if uploaded_size > max_size:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 20 MB upload limit."
                    )

                temp_file.write(chunk)

        # Analyse the uploaded file
        report = analyze_file(
            temp_path,
            "rules/test_rule.yar",
            original_filename=filename
        )

        return {
            "uploaded_filename": filename,
            "analysis": report
        }

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        await file.close()