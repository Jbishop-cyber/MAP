import os
import tempfile

from pathlib import Path

from fastapi import FastAPI
from fastapi import UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from core.report_builder import analyze_file

from core.database import save_scan, get_scan_history
from core.report_formatter import get_overall_status

from fastapi import Request
from fastapi.templating import Jinja2Templates


app = FastAPI(
    title="Sentrix",
    description="See threats, Understand risks, Stay protected.",
    version="0.1.0"
)

templates = Jinja2Templates(
    directory=Path(__file__).parent / "templates"
)

app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static"
)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )
#       """
#     <!DOCTYPE html>
#     <html>
#     <head>
#     <title>Sentrix | System Security</title>

#     <style>
#         * {
#             margin: 0;
#             padding: 0;
#             box-sizing: border-box;
#         }

#         body {
#             font-family: Arial, sans-serif;
#             background: #f5f7fb;
#             color: #1e293b;
#             line-height: 1.6;
#         }

#         .container {
#             max-width: 1100px;
#             margin: 0 auto;
#             padding: 40px 25px;
#         }

#         header {
#             margin-bottom: 40px;
#         }

#         header h1 {
#             font-size: 32px;
#             color: #172554;
#             letter-spacing: 2px;
#         }

#         header p {
#             color: #64748b;
#             margin-top: 5px;
#         }

#         .panel {
#             background: #ffffff;
#             padding: 30px;
#             margin-bottom: 25px;
#             border: 1px solid #e2e8f0;
#             border-radius: 12px;
#             box-shadow: 0 4px 15px rgba(0, 0, 0, 0.03);
#         }

#         .panel h2 {
#             font-size: 21px;
#             margin-bottom: 8px;
#             color: #172554;
#         }

#         .panel > p {
#             color: #64748b;
#             margin-bottom: 20px;
#         }

#         .results-grid {
#             display: grid;
#             grid-template-columns: repeat(2, 1fr);
#             gap: 20px;
#             margin-top: 20px;
#         }

#         .card {
#             background: #f8fafc;
#             border: 1px solid #e2e8f0;
#             border-radius: 10px;
#             padding: 20px;
#         }

#         .card h3 {
#             color: #1e40af;
#             margin-bottom: 12px;
#         }

#         .card p {
#             font-size: 14px;
#             margin-bottom: 8px;
#             overflow-wrap: anywhere;
#             word-break: break-word;
#         }

#         button {
#             background: #2563eb;
#             color: #ffffff;
#             border: none;
#             padding: 12px 24px;
#             border-radius: 7px;
#             font-size: 15px;
#             font-weight: bold;
#             cursor: pointer;
#             margin-top: 15px;
#         }

#         button:hover {
#             background: #1d4ed8;
#         }

#         button:disabled {
#             background: #94a3b8;
#             cursor: not-allowed;
#         }

#         input[type="file"] {
#             width: 100%;
#             padding: 15px;
#             border: 2px dashed #cbd5e1;
#             border-radius: 8px;
#             background: #f8fafc;
#         }

#         .badge {
#             display: inline-block;
#             padding: 8px 0;
#             margin-bottom: 12px;
#             font-weight: bold;
#             font-size: 13px;
#             background: transparent;
#         }

#         .clear {
#             color: #16a34a;
#             animation: blink-green 3.5s infinite;
#         }

#         .detected {
#             color: #dc2626;
#             animation: blink-red 3.5s infinite;
#         }

#         .flagged {
#             color: #d97706;
#             animation: blink-amber 3.5s infinite;
#         }

#         .error {
#             color: #ea580c;
#         }

#         .scanning {
#             color: #2563eb;
#         }

#         @keyframes blink-green {
#             0%, 100% {
#                 opacity: 1;
#             }
#             50% {
#                 opacity: 0.4;
#             }
#         }

#         @keyframes blink-red {
#             0%, 100% {
#                 opacity: 1;
#             }
#             50% {
#                 opacity: 0.4;
#             }
#         }

#         @keyframes blink-amber {
#             0%, 100% {
#                 opacity: 1;
#             }
#             50% {
#                 opacity: 0.4;
#             }
#         }

#         .disclaimer {
#             margin-top: 25px;
#             font-size: 13px;
#             color: #64748b;
#             border-top: 1px solid #e2e8f0;
#             padding-top: 15px;
#         }

#         @media (max-width: 700px) {
#             .container {
#                 padding: 25px 15px;
#             }

#             .results-grid {
#                 grid-template-columns: 1fr;
#             }

#             .panel {
#                 padding: 20px;
#             }
#         }

#         .upload-area {
#             display: flex;
#             flex-direction: column;
#             align-items: center;
#             justify-content: center;
#             gap: 10px;
#             padding: 40px 20px;
#             border: 2px dashed #93c5fd;
#             border-radius: 10px;
#             background: #eff6ff;
#             cursor: pointer;
#             text-align: center;
#         }

#         .upload-area:hover {
#             background: #dbeafe;
#         }

#         .upload-icon {
#             font-size: 35px;
#             color: #2563eb;
#         }

#         .upload-area strong {
#             color: #1e3a8a;
#         }

#         .upload-area span,
#         .upload-area small {
#             color: #64748b;
#         }

#         #fileInput {
#             display: none;
#         }

#         #selectedFile {
#             margin-top: 15px;
#             font-size: 14px;
#             color: #475569;
#         }

#         #removeFileButton {
#         background: #fee2e2;
#         color: #b91c1c;
#         padding: 8px 14px;
#         font-size: 13px;
#         margin-top: 8px;
#     }

#     #removeFileButton:hover {
#         background: #fecaca;
#     }

#     .assessment-card {
#         background: #eff6ff;
#         border: 1px solid #bfdbfe;
#         border-left: 5px solid #2563eb;
#         padding: 22px;
#         border-radius: 10px;
#         margin-bottom: 20px;
#     }

#     .assessment-card h3 {
#         color: #1e40af;
#         margin-bottom: 10px;
#     }

#     .assessment-card p {
#         color: #334155;
#         margin-bottom: 6px;
#     }

#     .assessment-card.detected {
#         background: #fef2f2;
#         border-color: #fecaca;
#         border-left-color: #dc2626;
#     }

#     .assessment-card.flagged {
#         background: #fffbeb;
#         border-color: #fde68a;
#         border-left-color: #d97706;
#     }

#     .assessment-card.error {
#         background: #fff7ed;
#         border-color: #fed7aa;
#         border-left-color: #ea580c;
#     }

#     .assessment-card.clear,
#     .assessment-card.detected,
#     .assessment-card.flagged {
#         animation: none;
#     }

#     .scan-indicator {
#         text-align: center;
#         padding: 30px;
#         margin-bottom: 25px;
#     }

#     .scan-circle {
#         width: 90px;
#         height: 90px;
#         border: 5px solid #dbeafe;
#         border-top: 5px solid #2563eb;
#         border-radius: 50%;
#         margin: 0 auto 15px;
#         display: flex;
#         align-items: center;
#         justify-content: center;
#     }

#     .spinner {
#         width: 65px;
#         height: 65px;
#         border: 5px solid transparent;
#         border-top: 5px solid #2563eb;
#         border-right: 5px solid #2563eb;
#         border-radius: 50%;
#         animation: rotate 1s linear infinite;
#     }

#     @keyframes rotate {
#         from {
#             transform: rotate(0deg);
#         }

#         to {
#             transform: rotate(360deg);
#         }
#     }

#     .scan-indicator h3 {
#         color: #2563eb;
#         font-size: 15px;
#         letter-spacing: 1px;
#     }

#     .result-icon {
#         width: 65px;
#         height: 65px;
#         border: none;
#         border-radius: 50%;
#         display: flex;
#         align-items: center;
#         justify-content: center;
#         font-size: 45px;
#         font-weight: bold;
#         animation: result-appear 0.4s ease-out;
#     }

#     .result-icon.clear {
#         color: #16a34a;
#         background: #dcfce7;
#     }

#     .result-icon.flagged {
#         color: #d97706;
#         background: #fef3c7;
#     }

#     .result-icon.detected {
#         color: #dc2626;
#         background: #fee2e2;
#     }

#     .result-icon.error {
#         color: #ea580c;
#         background: #ffedd5;
#     }

#     @keyframes result-appear {
#         from {
#             transform: scale(0.5);
#             opacity: 0;
#         }

#         to {
#             transform: scale(1);
#             opacity: 1;
#         }
#     }
#     </style>
# </head>

#     <body>
#     <div class="container">

#         <header>
#             <h1>Sentrix</h1>
#             <p>Intelligent File Security &amp; Threat Analysis</p>
#             <span class="badge clear">SYSTEM ONLINE</span>
#         </header>

#         <section class="panel upload-panel">
#             <h2>Analyse a File</h2>
#             <p>Upload a file for security analysis using YARA-X and ClamAV.</p>

#             <form id="scanForm">
#                 <label for="fileInput" class="upload-area">
#                     <span class="upload-icon">↑</span>
#                     <strong>Choose a file to analyse</strong>
#                     <span>Click here to browse your computer</span>
#                     <small>Maximum file size: 20 MB</small>
#                 </label>

#                 <input type="file" id="fileInput" required>

#                 <p id="selectedFile">No file selected</p>
#                 <button type="button" id="removeFileButton" hidden>
#                     Remove File
#                 </button>

#                 <button type="submit" id="scanButton">Start Analysis</button>
#             </form>
#         </section>

#         <section class="panel">
#             <h2>Analysis Results</h2>

#             <span id="statusBadge" class="badge">
#                 WAITING FOR SCAN
#             </span>

#             <div id="scanIndicator" class="scan-indicator" hidden>
#                 <div class="scan-circle">
#                     <div class="spinner"></div>
#                 </div>

#                 <h3 id="scanStatusText">ANALYSING FILE...</h3>
#             </div>

#             <div id="results"></div>

#             <p class="disclaimer">
#                 Note: No detection does not guarantee that a file is safe.
#             </p>
#         </section>

#     </div>

#     <script>
#         const form = document.getElementById("scanForm");
#         const fileInput = document.getElementById("fileInput");
#         const selectedFile = document.getElementById("selectedFile");
#         const removeFileButton = document.getElementById("removeFileButton");

#         fileInput.addEventListener("change", function() {
#             const file = fileInput.files[0];

#             if (file) {
#                 const fileSize = (file.size / 1024).toFixed(2);

#                 selectedFile.textContent =
#                     "Selected file: " + file.name + " (" + fileSize + " KB)";

#                 removeFileButton.hidden = false;
#             } else {
#                 selectedFile.textContent = "No file selected";
#                 removeFileButton.hidden = true;
#             }
#         });

#         removeFileButton.addEventListener("click", function() {
#             fileInput.value = "";
#             selectedFile.textContent = "No file selected";
#             removeFileButton.hidden = true;
#         });
#         const scanButton = document.getElementById("scanButton");
#         const results = document.getElementById("results");
#         const statusBadge = document.getElementById("statusBadge");
#         const scanIndicator = document.getElementById("scanIndicator");
#         const scanStatusText = document.getElementById("scanStatusText");


#         form.addEventListener("submit", async function(event) {
#             event.preventDefault();

#             const file = fileInput.files[0];

#             if (!file) {
#                 return;
#             }

#             const formData = new FormData();
#             formData.append("file", file);

#             statusBadge.textContent = "SCANNING...";
#             statusBadge.className = "badge scanning";

#             scanIndicator.hidden = false;
#             scanStatusText.textContent = "ANALYSING FILE...";

#             const scanCircle = scanIndicator.querySelector(".scan-circle");

#             const spinner = document.createElement("div");
#             spinner.className = "spinner";

#             scanCircle.replaceChildren(spinner);

#             results.replaceChildren();

#             scanButton.disabled = true;

#             try {
#                 const response = await fetch("/scan", {
#                     method: "POST",
#                     body: formData
#                 });

#                 const data = await response.json();

#                 if (!response.ok) {
#                     throw new Error(data.detail || "Scan failed.");
#                 }

#                 const report = data.analysis;

#                 const fileInfo = report["file information"];
#                 const yara = report.yara_analysis;
#                 const clamav = report.clamav_analysis;

#                 displayResults(report, fileInfo, yara, clamav);

#             } catch (error) {
#                 statusBadge.textContent = "SCAN ERROR";
#                 statusBadge.className = "badge error";

#                 scanStatusText.textContent = "SCAN ERROR";

#                 const scanCircle = scanIndicator.querySelector(".scan-circle");

#                 const errorIcon = document.createElement("div");
#                 errorIcon.className = "result-icon error";
#                 errorIcon.textContent = "!";

#                 scanCircle.replaceChildren(errorIcon);

#                 results.textContent = error.message;

#             } finally {
#                 scanButton.disabled = false;
#             }
#         });

#         function displayResults(report, fileInfo, yara, clamav) {

#         // Determine overall assessment
#         let overallStatus;
#         let statusClass;

#         if (clamav.scan_status === "error" || yara.error || clamav.error) {
#             overallStatus = "SCAN ERROR";
#             statusClass = "error";

#         } else if (clamav.scan_status === "infected") {
#             overallStatus = "THREAT DETECTED";
#             statusClass = "detected";

#         } else if (yara.matches_found > 0) {
#             overallStatus = "FLAGGED FOR REVIEW";
#             statusClass = "flagged";

#         } else {
#             overallStatus = "NO DETECTION";
#             statusClass = "clear";
#         }

#         // Update status badge
#         statusBadge.textContent = overallStatus;
#         statusBadge.className = "badge " + statusClass;

#         scanStatusText.textContent = overallStatus;

#         const scanCircle = scanIndicator.querySelector(".scan-circle");

#         const resultIcon = document.createElement("div");
#         resultIcon.className = "result-icon " + statusClass;

#         if (statusClass === "clear") {
#             resultIcon.textContent = "✓";

#         } else if (statusClass === "flagged") {
#             resultIcon.textContent = "!";

#         } else if (statusClass === "detected") {
#             resultIcon.textContent = "✕";

#         } else {
#             resultIcon.textContent = "!";
#         }

#         scanCircle.replaceChildren(resultIcon);

#         // Clear previous results
#         results.replaceChildren();

#         // Create results grid
#         const grid = document.createElement("div");
#         grid.className = "results-grid";

#         // Helper function for creating cards
#         function createCard(title, details) {

#             const card = document.createElement("div");
#             card.className = "card";

#             const heading = document.createElement("h3");
#             heading.textContent = title;

#             card.appendChild(heading);

#             details.forEach(function(detail) {

#                 const paragraph = document.createElement("p");
#                 paragraph.textContent = detail;

#                 card.appendChild(paragraph);
#             });

#             grid.appendChild(card);
#         }

#         // File information

#         let assessmentMessage;

#         if (overallStatus === "THREAT DETECTED") {
#             assessmentMessage =
#                 "ClamAV detected a known threat signature. Treat this file as potentially malicious.";

#         } else if (overallStatus === "FLAGGED FOR REVIEW") {
#             assessmentMessage =
#                 "YARA-X identified a matching pattern. Further investigation is recommended.";

#         } else if (overallStatus === "SCAN ERROR") {
#             assessmentMessage =
#                 "One or more security scanners encountered an error. Analysis is incomplete.";

#         } else {
#             assessmentMessage =
#                 "No threats were detected by the available scanners. This does not guarantee that the file is safe.";
#         }

#         const assessmentCard = document.createElement("div");
#         assessmentCard.className = "assessment-card " + statusClass;

#         const assessmentHeading = document.createElement("h3");
#         assessmentHeading.textContent = "Analysis Summary";

#         const assessmentStatus = document.createElement("p");
#         assessmentStatus.textContent = "Overall Assessment: " + overallStatus;

#         const assessmentText = document.createElement("p");
#         assessmentText.textContent = assessmentMessage;

#         assessmentCard.appendChild(assessmentHeading);
#         assessmentCard.appendChild(assessmentStatus);
#         assessmentCard.appendChild(assessmentText);

#         results.appendChild(assessmentCard);

#         createCard("File Information", [
#             "Filename: " + fileInfo.filename,
#             "Extension: " + fileInfo.extension,
#             "File Size: " + fileInfo.file_size + " bytes",
#             "MIME Type: " + fileInfo.mime_type
#         ]);

#         // SHA-256 fingerprint
#         createCard("File Fingerprint", [
#             "SHA-256: " + report.sha256
#         ]);

#         // YARA-X results
#         createCard("YARA-X Analysis", [
#             "Matches Found: " + yara.matches_found,
#             "Detections: " + (yara.detections.join(", ") || "None")
#         ]);

#         // ClamAV results
#         createCard("ClamAV Analysis", [
#             "Status: " + clamav.scan_status,
#             "Return Code: " + clamav.return_code
#         ]);

#         results.appendChild(grid);
#     }
#     </script>
# </body>
#     </html>
#     """


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.get("/history")
def scan_history():
    history = get_scan_history()

    return {
        "total scans": len(history),
        "history": history
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

        if "error" in report:
            raise HTTPException(
                status_code=500,
                detail=report["error"]
            )

        # Determine the overall scan status
        overall_status, reason = get_overall_status(report)

        # Save the scan to SQLite
        save_scan(
            filename=filename,
            sha256=report["sha256"],
            status=overall_status,
            report=report
        )

        return {
            "uploaded_filename": filename,
            "analysis": report,
            "overall_status": overall_status,
            "reason": reason
        }

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        await file.close()