// ============================================================
// TagRivo - Digital Metadata Privacy Auditor
// Custom JavaScript Frontend
// ============================================================

"use strict";


// ============================================================
// 1. CONNECT HTML ELEMENTS
// ============================================================

const fileInput = document.getElementById("fileInput");

const browseButton = document.getElementById("browseButton");

const uploadZone = document.getElementById("uploadZone");

const filePreview = document.getElementById("filePreview");

const selectedName = document.getElementById("selectedName");

const selectedSize = document.getElementById("selectedSize");

const removeButton = document.getElementById("removeButton");

const scanButton = document.getElementById("scanButton");

const resultsPanel = document.getElementById("resultsPanel");


// ============================================================
// 2. APPLICATION CONFIGURATION
// ============================================================

const MAX_FILE_BYTES = 20 * 1024 * 1024;

const ALLOWED_EXTENSIONS = [
    ".jpg",
    ".jpeg",
    ".png",
    ".pdf"
];

const RISK_CLASSES = {
    "No Detected Risk": "risk-none",
    "Low": "risk-low",
    "Moderate": "risk-moderate",
    "High": "risk-high",
    "Critical": "risk-critical"
};


// ============================================================
// 3. APPLICATION STATE
// ============================================================

let activeFile = null;

let auditController = null;

let sanitizeController = null;

let scanSequence = 0;


// ============================================================
// 4. COMMON HELPER FUNCTIONS
// ============================================================

function createElement(
    tag,
    className = "",
    text = null
) {

    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== null && text !== undefined) {
        element.textContent = String(text);
    }

    return element;
}


function formatFileSize(bytes) {

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}


// ============================================================
// 5. CANCEL ACTIVE FILE OPERATIONS
// ============================================================

function cancelInFlightWork() {

    scanSequence += 1;

    if (auditController) {
        auditController.abort();
    }

    if (sanitizeController) {
        sanitizeController.abort();
    }

    auditController = null;

    sanitizeController = null;

    scanButton.textContent = "Run Privacy Audit →";
}


// ============================================================
// 6. DISPLAY MESSAGES
// ============================================================

function showMessage(
    message,
    success = false
) {

    resultsPanel.hidden = false;

    resultsPanel.className = success
        ? "results-panel success"
        : "results-panel error";

    resultsPanel.replaceChildren();

    const heading = createElement(
        "h3",
        "",
        success
            ? "Operation Completed"
            : "File Processing Issue"
    );

    const description = createElement(
        "p",
        "",
        message
    );

    resultsPanel.append(
        heading,
        description
    );
}


// ============================================================
// 7. CLEAR SELECTED FILE
// ============================================================

function clearSelectedFile() {

    cancelInFlightWork();

    activeFile = null;

    fileInput.value = "";

    filePreview.hidden = true;

    selectedName.textContent = "";

    selectedSize.textContent = "";

    resultsPanel.hidden = true;

    resultsPanel.replaceChildren();

    scanButton.disabled = true;
}


// ============================================================
// 8. SELECT AND VALIDATE FILE
// ============================================================

function selectFile(file) {

    if (!file) {
        return;
    }

    clearSelectedFile();

    const lowerName = file.name.toLowerCase();

    const extensionAllowed = ALLOWED_EXTENSIONS.some(
        extension => lowerName.endsWith(extension)
    );

    if (!extensionAllowed) {

        showMessage(
            "Unsupported file format. Please select a JPEG, PNG or PDF file."
        );

        return;
    }

    if (file.size === 0) {

        showMessage(
            "The selected file is empty. Please choose another file."
        );

        return;
    }

    if (file.size > MAX_FILE_BYTES) {

        showMessage(
            "The selected file exceeds the maximum allowed size of 20 MB."
        );

        return;
    }

    // Client-side validation improves usability.
    // Python independently verifies the actual file content.

    activeFile = file;

    selectedName.textContent = file.name;

    selectedSize.textContent = formatFileSize(
        file.size
    );

    filePreview.hidden = false;

    scanButton.disabled = false;
}


// ============================================================
// 9. FILE BROWSING
// ============================================================

browseButton.addEventListener(
    "click",
    () => {

        fileInput.click();

    }
);


fileInput.addEventListener(
    "change",
    () => {

        selectFile(
            fileInput.files[0]
        );

    }
);


removeButton.addEventListener(
    "click",
    clearSelectedFile
);


// ============================================================
// 10. DRAG AND DROP SUPPORT
// ============================================================

uploadZone.addEventListener(
    "dragover",
    event => {

        event.preventDefault();

        uploadZone.classList.add(
            "dragging"
        );

    }
);


uploadZone.addEventListener(
    "dragleave",
    event => {

        if (!uploadZone.contains(event.relatedTarget)) {

            uploadZone.classList.remove(
                "dragging"
            );

        }

    }
);


uploadZone.addEventListener(
    "drop",
    event => {

        event.preventDefault();

        uploadZone.classList.remove(
            "dragging"
        );

        selectFile(
            event.dataTransfer.files[0]
        );

    }
);


// ============================================================
// 11. CREATE AUDIT METRIC
// ============================================================

function buildMetric(
    label,
    value
) {

    const card = createElement(
        "div",
        "audit-metric"
    );

    const title = createElement(
        "span",
        "metric-label",
        label
    );

    const number = createElement(
        "strong",
        "metric-value",
        value
    );

    card.append(
        title,
        number
    );

    return card;
}


// ============================================================
// 12. CREATE RISK INDICATOR
// ============================================================

function buildRiskIndicator(score) {

    const track = createElement(
        "div",
        "risk-track"
    );

    const fill = createElement(
        "div",
        "risk-fill"
    );

    const numeric = Number(score);

    const bounded = Number.isFinite(numeric)
        ? Math.min(
            100,
            Math.max(0, numeric)
        )
        : 0;

    fill.style.width = `${bounded}%`;

    fill.setAttribute(
        "role",
        "progressbar"
    );

    fill.setAttribute(
        "aria-label",
        "Detected metadata privacy risk"
    );

    fill.setAttribute(
        "aria-valuemin",
        "0"
    );

    fill.setAttribute(
        "aria-valuemax",
        "100"
    );

    fill.setAttribute(
        "aria-valuenow",
        String(bounded)
    );

    track.appendChild(fill);

    return track;
}


// ============================================================
// 13. CREATE METADATA FINDING CARD
// ============================================================

function buildFindingCard(finding) {

    const card = createElement(
        "article",
        "finding-card"
    );

    const heading = createElement(
        "div",
        "finding-top"
    );

    const fields = Array.isArray(finding.fields)
        ? finding.fields
        : [];

    heading.append(
        createElement(
            "strong",
            "",
            finding.category
        ),

        createElement(
            "span",
            "finding-points",
            `+${finding.points} points`
        )
    );

    const detectedFields = createElement(
        "p",
        "finding-fields",
        `Detected fields: ${fields.join(", ")}`
    );

    const explanation = createElement(
        "p",
        "finding-description",
        finding.explanation
    );

    card.append(
        heading,
        detectedFields,
        explanation
    );

    return card;
}


// ============================================================
// 14. METADATA INSPECTION PREVIEW
// ============================================================

function buildMetadataPreview(entries) {

    const wrapper = createElement(
        "div",
        "metadata-list"
    );

    if (
        !Array.isArray(entries) ||
        entries.length === 0
    ) {

        wrapper.appendChild(
            createElement(
                "p",
                "empty-findings",
                "No supported metadata fields found."
            )
        );

        return wrapper;
    }

    for (const item of entries) {

        const row = createElement(
            "div",
            "metadata-row"
        );

        row.append(
            createElement(
                "span",
                "",
                item.field
            ),

            createElement(
                "strong",
                "",
                item.value
            )
        );

        wrapper.appendChild(row);
    }

    return wrapper;
}


// ============================================================
// 15. TECHNICAL FILE INFORMATION PANEL
// STEP 6D.2
// ============================================================

function buildTechnicalPanel(properties) {

    const section = createElement(
        "section",
        "technical-panel"
    );

    const heading = createElement(
        "h4",
        "result-section-title",
        "Technical File Information"
    );

    section.appendChild(heading);

    const grid = createElement(
        "div",
        "technical-grid"
    );

    const entries = Object.entries(
        properties || {}
    );

    if (entries.length === 0) {

        grid.appendChild(
            createElement(
                "p",
                "",
                "No additional technical properties reported."
            )
        );

    } else {

        for (const [key, value] of entries) {

            const card = createElement(
                "div",
                "technical-item"
            );

            const label = createElement(
                "span",
                "",
                key.replaceAll("_", " ")
            );

            let displayValue;

            if (typeof value === "boolean") {

                displayValue = value ? "Yes" : "No";

            } else if (
                value === null ||
                value === undefined
            ) {

                displayValue = "Not available";

            } else {

                displayValue = String(value);
            }

            const content = createElement(
                "strong",
                "",
                displayValue
            );

            card.append(
                label,
                content
            );

            grid.appendChild(card);
        }
    }

    section.appendChild(grid);

    return section;
}


// ============================================================
// 16. CREATE SECURE DOWNLOAD LINKS
// ============================================================

function makeDownloadLink(
    token,
    type,
    label
) {

    const link = createElement(
        "a",
        "download-action",
        label
    );

    link.href = (
        `/api/download/${encodeURIComponent(token)}/${type}`
    );

    link.setAttribute(
        "download",
        ""
    );

    return link;
}


// ============================================================
// 17. BEFORE AND AFTER RISK COMPARISON
// ============================================================

function buildComparisonCard(
    before,
    after
) {

    const grid = createElement(
        "div",
        "comparison-grid"
    );

    const beforeCard = createElement(
        "div",
        "comparison-card before-card"
    );

    const afterCard = createElement(
        "div",
        "comparison-card after-card"
    );

    beforeCard.append(
        createElement(
            "span",
            "",
            "ORIGINAL RISK"
        ),

        createElement(
            "strong",
            "",
            `${before.risk_score}/100`
        ),

        createElement(
            "small",
            "",
            before.risk_level
        )
    );

    afterCard.append(
        createElement(
            "span",
            "",
            "AFTER SANITIZATION"
        ),

        createElement(
            "strong",
            "",
            `${after.risk_score}/100`
        ),

        createElement(
            "small",
            "",
            after.risk_level
        )
    );

    grid.append(
        beforeCard,
        afterCard
    );

    return grid;
}


// ============================================================
// 18. CLEAR TEMPORARY DOWNLOADS
// NEW FEATURE - STEP 6D.3
// ============================================================

function buildClearDownloadsButton(
    token,
    downloadArea,
    feedback
) {

    const clearButton = createElement(
        "button",
        "clear-downloads-button",
        "Clear Temporary Downloads"
    );

    clearButton.type = "button";

    clearButton.addEventListener(
        "click",
        async () => {

            if (clearButton.disabled) {
                return;
            }

            clearButton.disabled = true;

            clearButton.textContent = "Clearing...";

            try {

                const response = await fetch(
                    `/api/discard/${encodeURIComponent(token)}`,
                    {
                        method: "POST"
                    }
                );

                const result = await response.json()
                    .catch(() => null);

                // A successful response confirms that
                // the temporary server session was removed.

                if (
                    response.ok &&
                    result &&
                    result.success === true
                ) {

                    downloadArea.replaceChildren();

                    clearButton.textContent = "Downloads Cleared";

                    feedback.appendChild(
                        createElement(
                            "p",
                            "verification-note",
                            "Temporary cleaned file and reports " +
                            "have been removed from the active " +
                            "server download cache. Files already " +
                            "downloaded to your device are unaffected."
                        )
                    );

                    return;
                }

                // A 404 means there is no active session.
                // It may already have expired or been cleared.

                if (response.status === 404) {

                    downloadArea.replaceChildren();

                    clearButton.textContent = "Session Unavailable";

                    feedback.appendChild(
                        createElement(
                            "p",
                            "verification-note",
                            "The download session is no longer " +
                            "available. It may have expired or " +
                            "already been cleared."
                        )
                    );

                    return;
                }

                throw new Error(
                    result?.message ||
                    "Could not clear the download session."
                );

            } catch (error) {

                clearButton.disabled = false;

                clearButton.textContent =
                    "Retry Clearing Downloads";

                feedback.appendChild(
                    createElement(
                        "p",
                        "sanitize-error",
                        "Could not confirm download removal. " +
                        "Please check the server and try again."
                    )
                );
            }
        }
    );

    return clearButton;
}


// ============================================================
// 19. SANITIZATION AND VERIFICATION SECTION
// ============================================================

function buildSanitizeSection(
    auditedFile,
    auditVersion
) {

    const section = createElement(
        "section",
        "sanitize-section"
    );

    const heading = createElement(
        "h4",
        "result-section-title",
        "Metadata Sanitization & Verification"
    );

    const description = createElement(
        "p",
        "sanitize-description",
        "Create a separate cleaned copy, rescan its metadata " +
        "and compare the privacy exposure. Your original file " +
        "will not be overwritten."
    );

    const sanitizeButton = createElement(
        "button",
        "sanitize-button",
        "Sanitize & Verify File →"
    );

    sanitizeButton.type = "button";

    const feedback = createElement(
        "div",
        "sanitize-feedback"
    );

    feedback.setAttribute(
        "aria-live",
        "polite"
    );

    section.append(
        heading,
        description,
        sanitizeButton,
        feedback
    );


    // --------------------------------------------------------
    // SANITIZATION BUTTON CLICK EVENT
    // --------------------------------------------------------

    sanitizeButton.addEventListener(
        "click",
        async () => {

            if (
                sanitizeButton.disabled ||
                auditedFile !== activeFile ||
                auditVersion !== scanSequence
            ) {
                return;
            }

            sanitizeButton.disabled = true;

            sanitizeButton.textContent =
                "Sanitizing & verifying...";

            feedback.replaceChildren();

            const controller = new AbortController();

            sanitizeController = controller;

            const formData = new FormData();

            formData.append(
                "file",
                auditedFile,
                auditedFile.name
            );

            try {

                const response = await fetch(
                    "/api/sanitize",
                    {
                        method: "POST",
                        body: formData,
                        signal: controller.signal
                    }
                );

                const payload = await response.json()
                    .catch(() => null);


                // Ignore stale results if the
                // selected file or scan has changed.

                if (
                    auditedFile !== activeFile ||
                    auditVersion !== scanSequence
                ) {
                    return;
                }


                // Handle rejected or failed requests.

                if (
                    !response.ok ||
                    !payload ||
                    !payload.success
                ) {

                    feedback.appendChild(
                        createElement(
                            "p",
                            "sanitize-error",
                            payload?.message ||
                            "Sanitization failed or the output " +
                            "could not be verified."
                        )
                    );

                    return;
                }


                // Require confirmation from Python
                // that the supported checks passed.

                if (
                    payload.verification?.status !==
                        "Verified (supported checks)" ||
                    payload.after?.risk_score !== 0 ||
                    typeof payload.token !== "string" ||
                    !/^[A-Za-z0-9_-]{16,}$/.test(payload.token)
                ) {

                    feedback.appendChild(
                        createElement(
                            "p",
                            "sanitize-error",
                            "The server did not confirm a " +
                            "verified cleaned copy."
                        )
                    );

                    return;
                }


                // ------------------------------------------------
                // VERIFICATION RESULT
                // ------------------------------------------------

                const verifiedHeading = createElement(
                    "div",
                    "verified-heading",
                    "✓ Sanitization Verified (Supported Checks)"
                );

                feedback.appendChild(
                    verifiedHeading
                );


                // ------------------------------------------------
                // BEFORE AND AFTER RISK SCORE
                // ------------------------------------------------

                const comparison = buildComparisonCard(
                    payload.before,
                    payload.after
                );

                feedback.appendChild(
                    comparison
                );


                // ------------------------------------------------
                // RISK REDUCTION
                // ------------------------------------------------

                const reduction = createElement(
                    "p",
                    "risk-reduction",
                    `Detected risk reduced by ` +
                    `${payload.risk_reduction} points.`
                );

                feedback.appendChild(
                    reduction
                );


                // ------------------------------------------------
                // VERIFICATION INFORMATION
                // ------------------------------------------------

                const verificationText = createElement(
                    "p",
                    "verification-note",
                    "The cleaned copy passed the supported " +
                    "metadata checks and was rescanned. " +
                    "The original file on your device remains unchanged."
                );

                feedback.appendChild(
                    verificationText
                );


                // ------------------------------------------------
                // DOWNLOAD SECTION
                // ------------------------------------------------

                const downloadTitle = createElement(
                    "h4",
                    "download-title",
                    "Download Your Results"
                );

                feedback.appendChild(
                    downloadTitle
                );

                const downloadArea = createElement(
                    "div",
                    "download-actions"
                );


                // Download 1: Sanitized file.

                downloadArea.appendChild(
                    makeDownloadLink(
                        payload.token,
                        "clean",
                        "↓ Download Clean Copy"
                    )
                );


                // Download 2: JSON report.

                downloadArea.appendChild(
                    makeDownloadLink(
                        payload.token,
                        "json",
                        "↓ Download JSON Report"
                    )
                );


                // Download 3: CSV report.

                downloadArea.appendChild(
                    makeDownloadLink(
                        payload.token,
                        "csv",
                        "↓ Download CSV Report"
                    )
                );

                feedback.appendChild(
                    downloadArea
                );


                // ------------------------------------------------
                // NEW: CLEAR TEMPORARY DOWNLOADS BUTTON
                // ------------------------------------------------

                const clearButton = buildClearDownloadsButton(
                    payload.token,
                    downloadArea,
                    feedback
                );

                feedback.appendChild(
                    clearButton
                );


                // ------------------------------------------------
                // SANITIZATION LIMITATIONS
                // ------------------------------------------------

                const limitationText = Array.isArray(
                    payload.limitations
                )
                    ? payload.limitations.join(" ")
                    : (
                        typeof payload.limitations === "string"
                            ? payload.limitations
                            : "Metadata removal does not guarantee anonymity."
                    );

                const warning = createElement(
                    "p",
                    "sanitize-warning",
                    `${limitationText} ` +
                    "Review the cleaned file before sharing. " +
                    "Temporary downloads expire after 15 minutes."
                );

                feedback.appendChild(
                    warning
                );

            } catch (error) {

                if (
                    error.name === "AbortError" ||
                    auditedFile !== activeFile ||
                    auditVersion !== scanSequence
                ) {
                    return;
                }

                feedback.appendChild(
                    createElement(
                        "p",
                        "sanitize-error",
                        "Could not connect to the local " +
                        "sanitization service."
                    )
                );

            } finally {

                if (sanitizeController === controller) {
                    sanitizeController = null;
                }

                if (
                    auditedFile === activeFile &&
                    auditVersion === scanSequence
                ) {

                    sanitizeButton.disabled = false;

                    sanitizeButton.textContent =
                        "Sanitize & Verify Again →";
                }
            }
        }
    );

    return section;
}


// ============================================================
// 20. RENDER COMPLETE METADATA AUDIT DASHBOARD
// ============================================================

function renderAudit(
    report,
    auditedFile,
    auditVersion
) {

    const findings = Array.isArray(report.findings)
        ? report.findings
        : [];

    resultsPanel.hidden = false;

    resultsPanel.className = "results-panel success";


    // --------------------------------------------------------
    // SEVERITY-BASED STYLING
    // STEP 6D.1
    // --------------------------------------------------------

    const riskClass = RISK_CLASSES[
        report.risk_level
    ];

    if (riskClass) {

        resultsPanel.classList.add(
            riskClass
        );
    }


    // Remove previous results.

    resultsPanel.replaceChildren();


    // --------------------------------------------------------
    // AUDIT HEADER
    // --------------------------------------------------------

    const heading = createElement(
        "h3",
        "audit-heading",
        "Privacy Audit Results"
    );

    const subtitle = createElement(
        "p",
        "audit-subtitle",
        `${report.file_type} file · ` +
        `${formatFileSize(report.size_bytes)}`
    );

    resultsPanel.append(
        heading,
        subtitle
    );


    // --------------------------------------------------------
    // PRIVACY METRICS
    // --------------------------------------------------------

    const metrics = createElement(
        "div",
        "audit-metrics"
    );

    metrics.append(
        buildMetric(
            "Privacy Risk Score",
            `${report.risk_score}/100`
        ),

        buildMetric(
            "Risk Severity",
            report.risk_level
        ),

        buildMetric(
            "Exposure Categories",
            findings.length
        )
    );

    resultsPanel.appendChild(
        metrics
    );


    // --------------------------------------------------------
    // RISK PROGRESS BAR
    // --------------------------------------------------------

    resultsPanel.appendChild(
        buildRiskIndicator(
            report.risk_score
        )
    );


    // --------------------------------------------------------
    // TECHNICAL FILE INFORMATION
    // STEP 6D.2
    // --------------------------------------------------------

    resultsPanel.appendChild(
        buildTechnicalPanel(
            report.properties
        )
    );


    // --------------------------------------------------------
    // PRIVACY FINDINGS
    // --------------------------------------------------------

    const findingsHeading = createElement(
        "h4",
        "result-section-title",
        "Detected Privacy Exposures"
    );

    resultsPanel.appendChild(
        findingsHeading
    );

    if (findings.length === 0) {

        resultsPanel.appendChild(
            createElement(
                "p",
                "empty-findings",
                "No supported privacy-risk metadata fields detected."
            )
        );

    } else {

        for (const finding of findings) {

            resultsPanel.appendChild(
                buildFindingCard(
                    finding
                )
            );
        }
    }


    // --------------------------------------------------------
    // METADATA PREVIEW
    // --------------------------------------------------------

    const metadataHeading = createElement(
        "h4",
        "result-section-title",
        "Metadata Inspection Preview"
    );

    resultsPanel.appendChild(
        metadataHeading
    );

    resultsPanel.appendChild(
        buildMetadataPreview(
            report.metadata_preview
        )
    );


    // --------------------------------------------------------
    // PRIVACY AUDIT DISCLAIMER
    // --------------------------------------------------------

    const disclaimer = createElement(
        "p",
        "audit-disclaimer",
        report.note ||
        "This risk score evaluates supported metadata only, " +
        "not the overall safety of the file."
    );

    resultsPanel.appendChild(
        disclaimer
    );


    // --------------------------------------------------------
    // SANITIZATION AND DOWNLOAD CONTROLS
    // --------------------------------------------------------

    resultsPanel.appendChild(
        buildSanitizeSection(
            auditedFile,
            auditVersion
        )
    );


    // Scroll results into view.

    resultsPanel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


// ============================================================
// 21. RUN PRIVACY AUDIT
// ============================================================

scanButton.addEventListener(
    "click",
    async () => {

        if (
            !activeFile ||
            auditController
        ) {
            return;
        }


        // Invalidate any older sanitization result.

        if (sanitizeController) {

            sanitizeController.abort();
        }

        sanitizeController = null;

        scanSequence += 1;

        const auditVersion = scanSequence;

        const fileToScan = activeFile;

        const controller = new AbortController();

        auditController = controller;


        // Update loading state.

        scanButton.disabled = true;

        scanButton.textContent =
            "Analyzing metadata...";

        resultsPanel.hidden = true;


        // Prepare file upload.

        const formData = new FormData();

        formData.append(
            "file",
            fileToScan,
            fileToScan.name
        );


        try {

            const response = await fetch(
                "/api/audit",
                {
                    method: "POST",
                    body: formData,
                    signal: controller.signal
                }
            );

            const payload = await response.json()
                .catch(() => null);


            // Ignore an outdated audit response.

            if (
                fileToScan !== activeFile ||
                auditVersion !== scanSequence
            ) {
                return;
            }


            // Display server errors.

            if (
                !response.ok ||
                !payload ||
                !payload.success
            ) {

                showMessage(
                    payload?.message ||
                    "Metadata audit could not be completed."
                );

                return;
            }


            // Verify minimum response structure.

            if (
                !payload.report ||
                !Number.isFinite(
                    payload.report.risk_score
                )
            ) {

                showMessage(
                    "The server returned an incomplete audit report."
                );

                return;
            }


            // Render successful audit.

            renderAudit(
                payload.report,
                fileToScan,
                auditVersion
            );

        } catch (error) {

            if (
                error.name === "AbortError" ||
                fileToScan !== activeFile ||
                auditVersion !== scanSequence
            ) {
                return;
            }

            showMessage(
                "Cannot reach the TagRivo server. " +
                "Please confirm that app.py is running."
            );

        } finally {

            if (auditController === controller) {

                auditController = null;
            }

            if (
                fileToScan === activeFile &&
                auditVersion === scanSequence
            ) {

                scanButton.disabled = false;

                scanButton.textContent =
                    "Run Privacy Audit →";
            }
        }
    }
);


// ============================================================
// 22. INITIALIZE APPLICATION
// ============================================================

scanButton.disabled = true;

console.log(
    "TagRivo initialized successfully."
);

console.log(
    "Features: Upload, Audit, Risk Analysis, Technical " +
    "Information, Sanitization, Verification, Downloads, " +
    "and Temporary Download Revocation."
);

