const form = document.getElementById("scanForm");
        const fileInput = document.getElementById("fileInput");
        const selectedFile = document.getElementById("selectedFile");
        const removeFileButton = document.getElementById("removeFileButton");

        fileInput.addEventListener("change", function() {
            const file = fileInput.files[0];

            if (file) {
                const fileSize = (file.size / 1024).toFixed(2);

                selectedFile.textContent =
                    "Selected file: " + file.name + " (" + fileSize + " KB)";

                removeFileButton.hidden = false;
            } else {
                selectedFile.textContent = "No file selected";
                removeFileButton.hidden = true;
            }
        });

        removeFileButton.addEventListener("click", function() {
            fileInput.value = "";
            selectedFile.textContent = "No file selected";
            removeFileButton.hidden = true;
        });
        const scanButton = document.getElementById("scanButton");
        const results = document.getElementById("results");
        const statusBadge = document.getElementById("statusBadge");
        const scanIndicator = document.getElementById("scanIndicator");
        const scanStatusText = document.getElementById("scanStatusText");


        form.addEventListener("submit", async function(event) {
            event.preventDefault();

            const file = fileInput.files[0];

            if (!file) {
                return;
            }

            const formData = new FormData();
            formData.append("file", file);

            statusBadge.textContent = "SCANNING...";
            statusBadge.className = "badge scanning";

            scanIndicator.hidden = false;
            scanStatusText.textContent = "ANALYSING FILE...";

            const scanCircle = scanIndicator.querySelector(".scan-circle");

            const spinner = document.createElement("div");
            spinner.className = "spinner";

            scanCircle.replaceChildren(spinner);

            results.replaceChildren();

            scanButton.disabled = true;

            try {
                const response = await fetch("/scan", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.detail || "Scan failed.");
                }

                const report = data.analysis;

                const fileInfo = report["file information"];
                const yara = report.yara_analysis;
                const clamav = report.clamav_analysis;

                displayResults(report, fileInfo, yara, clamav);

            } catch (error) {
                statusBadge.textContent = "SCAN ERROR";
                statusBadge.className = "badge error";

                scanStatusText.textContent = "SCAN ERROR";

                const scanCircle = scanIndicator.querySelector(".scan-circle");

                const errorIcon = document.createElement("div");
                errorIcon.className = "result-icon error";
                errorIcon.textContent = "!";

                scanCircle.replaceChildren(errorIcon);

                results.textContent = error.message;

            } finally {
                scanButton.disabled = false;
            }
        });

        function displayResults(report, fileInfo, yara, clamav) {

        // Determine overall assessment
        let overallStatus;
        let statusClass;

        if (clamav.scan_status === "error" || yara.error || clamav.error) {
            overallStatus = "SCAN ERROR";
            statusClass = "error";

        } else if (clamav.scan_status === "infected") {
            overallStatus = "THREAT DETECTED";
            statusClass = "detected";

        } else if (yara.matches_found > 0) {
            overallStatus = "FLAGGED FOR REVIEW";
            statusClass = "flagged";

        } else {
            overallStatus = "NO DETECTION";
            statusClass = "clear";
        }

        // Update status badge
        statusBadge.textContent = overallStatus;
        statusBadge.className = "badge " + statusClass;

        scanStatusText.textContent = overallStatus;

        const scanCircle = scanIndicator.querySelector(".scan-circle");

        const resultIcon = document.createElement("div");
        resultIcon.className = "result-icon " + statusClass;

        if (statusClass === "clear") {
            resultIcon.textContent = "✓";

        } else if (statusClass === "flagged") {
            resultIcon.textContent = "!";

        } else if (statusClass === "detected") {
            resultIcon.textContent = "✕";

        } else {
            resultIcon.textContent = "!";
        }

        scanCircle.replaceChildren(resultIcon);

        // Clear previous results
        results.replaceChildren();

        // Create results grid
        const grid = document.createElement("div");
        grid.className = "results-grid";

        // Helper function for creating cards
        function createCard(title, details) {

            const card = document.createElement("div");
            card.className = "card";

            const heading = document.createElement("h3");
            heading.textContent = title;

            card.appendChild(heading);

            details.forEach(function(detail) {

                const paragraph = document.createElement("p");
                paragraph.textContent = detail;

                card.appendChild(paragraph);
            });

            grid.appendChild(card);
        }

        // File information

        let assessmentMessage;

        if (overallStatus === "THREAT DETECTED") {
            assessmentMessage =
                "ClamAV detected a known threat signature. Treat this file as potentially malicious.";

        } else if (overallStatus === "FLAGGED FOR REVIEW") {
            assessmentMessage =
                "YARA-X identified a matching pattern. Further investigation is recommended.";

        } else if (overallStatus === "SCAN ERROR") {
            assessmentMessage =
                "One or more security scanners encountered an error. Analysis is incomplete.";

        } else {
            assessmentMessage =
                "No threats were detected by the available scanners. This does not guarantee that the file is safe.";
        }

        const assessmentCard = document.createElement("div");
        assessmentCard.className = "assessment-card " + statusClass;

        const assessmentHeading = document.createElement("h3");
        assessmentHeading.textContent = "Analysis Summary";

        const assessmentStatus = document.createElement("p");
        assessmentStatus.textContent = "Overall Assessment: " + overallStatus;

        const assessmentText = document.createElement("p");
        assessmentText.textContent = assessmentMessage;

        assessmentCard.appendChild(assessmentHeading);
        assessmentCard.appendChild(assessmentStatus);
        assessmentCard.appendChild(assessmentText);

        results.appendChild(assessmentCard);

        createCard("File Information", [
            "Filename: " + fileInfo.filename,
            "Extension: " + fileInfo.extension,
            "File Size: " + fileInfo.file_size + " bytes",
            "MIME Type: " + fileInfo.mime_type
        ]);

        // SHA-256 fingerprint
        createCard("File Fingerprint", [
            "SHA-256: " + report.sha256
        ]);

        // YARA-X results
        createCard("YARA-X Analysis", [
            "Matches Found: " + yara.matches_found,
            "Detections: " + (yara.detections.join(", ") || "None")
        ]);

        // ClamAV results
        createCard("ClamAV Analysis", [
            "Status: " + clamav.scan_status,
            "Return Code: " + clamav.return_code
        ]);

        results.appendChild(grid);
    }