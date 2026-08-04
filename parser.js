// js/parser.js

/**
 * Handles reading the uploaded JSON scanner report and rendering it to the table
 * @param {Event} event - The file input change event
 */
// js/parser.js

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();

    reader.onload = function(e) {
        try {
            const scanData = JSON.parse(e.target.result);
            const uploadedVulns = Array.isArray(scanData) ? scanData : (scanData.vulnerabilities || []);

            // === THE TAMARA INTELLIGENT FILTER ===
            // We only keep vulnerabilities that are matched in our high-priority DB 
            // OR are Critical/High severity. We ignore the low-level noise!
            const priorityVulns = uploadedVulns.filter(uploaded => {
                const isMatchedInDb = vulnerabilityData.some(dbVuln => 
                    dbVuln.vulnerabilityTitle === uploaded.vulnerabilityTitle || 
                    dbVuln.title === uploaded.vulnerabilityTitle ||
                    dbVuln.cveId === uploaded.cveId
                );
                
                const isHighSeverity = uploaded.severity === "Critical" || uploaded.severity === "High";

                return isMatchedInDb || isHighSeverity;
            });
            localStorage.setItem('tamara_fileName', file.name);
            localStorage.setItem('tamara_priorityVulns', JSON.stringify(priorityVulns));

            const tableBody = document.getElementById('vulnerability-table-body');
            tableBody.innerHTML = ''; // Clear the table

            let totalCvss = 0;
            let criticalHighCount = 0;
            let openCount = 0;
            let matchedVulnsCount = 0;

            // We loop through our FILTERED list instead of the messy raw list!
            priorityVulns.forEach((uploaded, index) => {
                const match = vulnerabilityData.find(dbVuln => 
                    dbVuln.vulnerabilityTitle === uploaded.vulnerabilityTitle || 
                    dbVuln.title === uploaded.vulnerabilityTitle ||
                    dbVuln.cveId === uploaded.cveId
                );

                const assetName = match ? match.assetName : (uploaded.assetName || "Unknown Asset");
                const ipAddress = match ? match.ipAddress : (uploaded.ipAddress || "0.0.0.0");
                const title = match ? (match.title || match.vulnerabilityTitle) : (uploaded.vulnerabilityTitle || "Unnamed Vulnerability");
                const severity = match ? match.severity : (uploaded.severity || "Low");
                const cveId = match ? match.cveId : (uploaded.cveId || "N/A");
                const status = match ? match.status : (uploaded.status || "Open");
                const dueDate = match ? match.dueDate : (uploaded.dueDate || "No Date Set");
                const assignedTo = match ? match.assignedTo : "Unassigned";
                
                const cvss = match ? parseFloat(match.cvss || 0) : parseFloat(uploaded.cvss || 0);
                totalCvss += cvss;
                matchedVulnsCount++;

                if (severity.toLowerCase() === 'critical' || severity.toLowerCase() === 'high') {
                    criticalHighCount++;
                }
                if (status.toLowerCase() === 'open') {
                    openCount++;
                }

                const description = match ? match.description : "No further details are available.";
                const recommendation = match ? match.recommendation : "No remediation steps found.";

                const severityClass = getSeverityBadgeClass(severity);
                const statusClass = status.toLowerCase() === "open" ? "bg-warning text-dark" : "bg-success text-white";

                const detailsRowId = `details-row-${index}`;

                const mainRow = document.createElement('tr');
                mainRow.classList.add('vulnerability-row');
                mainRow.innerHTML = `
                    <td>
                        <strong>${assetName}</strong><br>
                        <small class="text-muted font-monospace">${ipAddress}</small>
                    </td>
                    <td>
                        <strong>${title}</strong> <small class="text-muted">(${cveId})</small><br>
                        <span class="badge bg-secondary text-light">CVSS: ${cvss.toFixed(1)}</span>
                    </td>
                    <td>
                        <span class="badge ${severityClass}">${severity}</span>
                    </td>
                    <td>
                        <span class="badge ${statusClass}">${status}</span>
                    </td>
                    <td>
                        <strong class="text-primary">${assignedTo}</strong>
                    </td>
                    <td>
                        ${dueDate}
                    </td>
                    <td>
                        <button class="btn btn-sm btn-info text-white" onclick="toggleDetailsRow('${detailsRowId}')">
                            View Details
                        </button>
                    </td>
                `;

                const detailsRow = document.createElement('tr');
                detailsRow.id = detailsRowId;
                detailsRow.style.display = "none";
                detailsRow.style.backgroundColor = "rgba(255, 255, 255, 0.03)";
                
                detailsRow.innerHTML = `
                    <td colspan="7" class="p-3 border-top-0">
                        <div class="row">
                            <div class="col-md-6 border-end border-secondary">
                                <h6 class="text-info"><strong>Vulnerability Description:</strong></h6>
                                <p class="text-light small" style="line-height: 1.5;">${description}</p>
                            </div>
                            <div class="col-md-6">
    <h6 class="text-success"><strong>Remediation Steps (How to Fix):</strong></h6>
    <p class="text-light small" style="line-height: 1.5;">${recommendation}</p>
    
    <!-- EVIDENCE AND REMEDIATION BUTTON SYSTEM -->
    <div style="margin-top: 15px;">
        <p class="text-light small"><strong>Evidence:</strong> [Link to Screenshot]</p>
       ${status.toLowerCase() === 'open' ? 
            '<button class="btn btn-sm btn-success remediate-btn" style="margin-top: 5px;">✓ Mark as Remediated</button>' : 
            '<div style="margin-top: 10px; color: #198754; font-weight: bold;">✓ This vulnerability has been successfully resolved.</div>'
        }
    </div>
</div>
                        </div>
                    </td>
                `;

                tableBody.appendChild(mainRow);
                tableBody.appendChild(detailsRow);
    // --- UPLOADED FILE REMEDIATION CLICK LOGIC ---
        const remediateBtn = detailsRow.querySelector('.remediate-btn');
        if (remediateBtn) {
            remediateBtn.addEventListener('click', () => {
                // 1. Update status locally in the filtered array item
                if (priorityVulns[index]) {
                    priorityVulns[index].status = "Closed";
                }

                // 2. Also locate and update the status inside the master array tracking object
                const globalMatch = vulnerabilityData.find(dbVuln => 
                    dbVuln.vulnerabilityTitle === uploaded.vulnerabilityTitle ||
                    dbVuln.title === uploaded.vulnerabilityTitle ||
                    dbVuln.cveId === uploaded.cveId
                );
                if (globalMatch) {
                    globalMatch.status = "Closed";
                }

                // 3. Visual UI update for the remediation row panel
                remediateBtn.parentElement.innerHTML = '<div style="margin-top: 10px; color: #198754; font-weight: bold;">✓ This vulnerability has been successfully resolved.</div>';
                
                // 4. Instantly switch the badge color inside the main table row to Closed
                const cells = mainRow.querySelectorAll('td');
                if (cells && cells.length >= 4) {
                    cells[3].innerHTML = '<span class="badge bg-success text-white">Closed</span>';
                }

                // 5. Fresh independent recount loop with CVSS reduction for Closed items
                let freshTotalCvss = 0;
                let freshCriticalHighCount = 0;
                let freshOpenCount = 0;

                priorityVulns.forEach(v => {
                    const targetMatch = vulnerabilityData.find(db => 
                        db.vulnerabilityTitle === v.vulnerabilityTitle ||
                        db.title === v.vulnerabilityTitle ||
                        db.cveId === v.cveId
                    );

                    const currentStatus = String(targetMatch ? targetMatch.status : (v.status || 'Open')).toLowerCase().trim();
                    const currentSeverity = String(targetMatch ? targetMatch.severity : (v.severity || 'Low')).toLowerCase().trim();
                    
                    // CRITICAL FIX: If the issue is closed, its risk contribution drops to 0!
                    let currentCvss = 0;
                    if (currentStatus !== 'closed') {
                        currentCvss = parseFloat(targetMatch ? targetMatch.cvss : (v.cvss || 0)) || 0;
                    }

                    if (currentSeverity === 'critical' || currentSeverity === 'high') {
                        freshCriticalHighCount++;
                    }
                    if (currentStatus !== 'closed') {
                        freshOpenCount++;
                    }
                    freshTotalCvss += currentCvss;
                });

                // 6. Push the accurate recalculated totals directly back up to the dashboard layout cards
                if (typeof calculateAndDisplayMetrics === 'function') {
                    calculateAndDisplayMetrics(priorityVulns.length, freshCriticalHighCount, freshOpenCount, freshTotalCvss, file.name);
                    localStorage.setItem('tamara_fileName', file.name);
                    localStorage.setItem('tamara_priorityVulns', JSON.stringify(priorityVulns));
                }
            });
        }
                
            });
           
            // Run calculations ONLY on the filtered priority list!
            calculateAndDisplayMetrics(matchedVulnsCount, criticalHighCount, openCount, totalCvss, file.name);
            localStorage.setItem('tamara_fileName', file.name);
            localStorage.setItem('tamara_priorityVulns', JSON.stringify(priorityVulns));

        } catch (error) {
            console.error("Error parsing JSON:", error);
            alert("Invalid scanner report format.");
        }
    };

    reader.readAsText(file);
}

// TOGGLE EXPAND DRAWER
function toggleDetailsRow(rowId) {
    const row = document.getElementById(rowId);
    row.style.display = row.style.display === "none" ? "table-row" : "none";
}

// THE MATHEMATICAL FORMULA FUNCTION (SMART VERSION)
function calculateAndDisplayMetrics(totalVulns, critHigh, openIssues, totalCvssSum, fileName = null) {
    // 1. Calculate Risk Score based on your formula
    let globalRiskScorePercentage = 0;
    if (totalVulns > 0) {
        const scoreFraction = totalCvssSum / (totalVulns * 10);
        globalRiskScorePercentage = Math.round(scoreFraction * 100); 
    }

    // 2. Clear out old hardcoded data and use our unified update function!
    const total = totalVulns;
    const criticalHigh = critHigh;
    
    // Pass the parameters down directly
    updateMetricsUsingData(total, criticalHigh, openIssues, globalRiskScorePercentage, fileName);
}

// 5. Global helper function to toggle the drawer open and closed
function toggleDetailsRow(rowId) {
    const row = document.getElementById(rowId);
    if (row.style.display === "none") {
        row.style.display = "table-row";
    } else {
        row.style.display = "none";
    }
}
/**
 * Helper to determine Bootstrap badge colors for severity levels
 */
function getSeverityBadgeClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'bg-danger text-white';
        case 'high': return 'bg-warning text-dark'; // Keeping the orange/yellow accent tone
        case 'medium': return 'bg-info text-dark';
        case 'low': return 'bg-success text-white';
        default: return 'bg-secondary text-white';
    }
}
let selectedFile = null;

// 1. Trigger Modal when a file is picked from the dashboard card
document.getElementById('vulnerabilityUpload').addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (!file) return;

    selectedFile = file;

    // Display file name & size inside the modal
    document.getElementById('fileNameDisplay').textContent = `Selected File: ${file.name}`;
    document.getElementById('fileSizeDisplay').textContent = `Size: ${(file.size / 1024).toFixed(2)} KB`;

    // Reset UI state
    document.getElementById('loadingArea').classList.add('d-none');
    document.getElementById('filePreviewArea').classList.remove('d-none');
    document.getElementById('processBtn').disabled = false;

    // Show confirmation modal
    const uploadModal = new bootstrap.Modal(document.getElementById('uploadModal'));
    uploadModal.show();
});
// 2. Handle clicking "Process Scan File" inside the modal
document.getElementById('processBtn').addEventListener('click', function() {
    if (!selectedFile) return;

    // Show loading spinner inside modal
    document.getElementById('filePreviewArea').classList.add('d-none');
    document.getElementById('loadingArea').classList.remove('d-none');
    this.disabled = true;

    // Simulate realistic parsing delay (1.5 seconds)
    setTimeout(() => {
        try {
            // Mock an event object containing selectedFile and pass to main parser logic
            const mockEvent = {
                target: {
                    files: [selectedFile]
                }
            };

            // Call primary upload parser
            if (typeof handleFileUpload === 'function') {
                handleFileUpload(mockEvent);
            } else {
                console.error("handleFileUpload function was not found!");
            }

            // Hide modal on success
            const modalElement = document.getElementById('uploadModal');
            const modalInstance = bootstrap.Modal.getInstance(modalElement);
            if (modalInstance) modalInstance.hide();

            // Clear input field and reset modal state
            document.getElementById('loadingArea').classList.add('d-none');
            document.getElementById('filePreviewArea').classList.remove('d-none');
            document.getElementById('processBtn').disabled = false;

        } catch (error) {
            console.error("Upload error details:", error);
            alert('Error processing file. Check browser console for details.');
            document.getElementById('loadingArea').classList.add('d-none');
            document.getElementById('filePreviewArea').classList.remove('d-none');
            document.getElementById('processBtn').disabled = false;
        }
    }, 1500);
});

window.addEventListener('load', () => {
    const savedName = localStorage.getItem('tamara_fileName');
    const savedVulns = localStorage.getItem('tamara_priorityVulns');

    if (savedName && savedVulns) {
        priorityVulns = JSON.parse(savedVulns);
        console.log("Restored Tamara session data successfully!");
        
        let restoredCriticalHigh = 0;
        let restoredOpenCount = 0;
        let restoredTotalCvss = 0;
        
        priorityVulns.forEach(v => {
            // Count open vs resolved vulnerabilities
            if (v.status !== 'closed' && v.remediated !== true) {
                restoredOpenCount++;
            }
            
            // Sum up the remaining CVSS scores
            let cvss = parseFloat(v.cvss) || 0;
            restoredTotalCvss += cvss;
            
            // Check for critical/high levels
            let severity = (v.severity || '').toLowerCase();
            if (severity === 'critical' || severity === 'high') {
                restoredCriticalHigh++;
            }
        });

        calculateAndDisplayMetrics(
            priorityVulns.length, 
            restoredCriticalHigh, 
            restoredOpenCount, 
            restoredTotalCvss, 
            savedName
        );
    }
});
 function exportExecutiveSummary() {
    const fileName = localStorage.getItem('tamara_fileName') || 'Executive_Summary';

    // 1. Target elements inside the content container to temporarily hide
    const elementsToHide = document.querySelectorAll('#exportPdfBtn, #clearReportBtn, #upload-section, .input-group, th:last-child, td:last-child');
    elementsToHide.forEach(el => el.style.display = 'none');

    // 2. Target main body container ONLY (skips navbar/header whitespace)
    const element = document.querySelector('.container-lg') || document.body;

    const options = {
        margin: [0.2, 0.2, 0.2, 0.2],
        filename: `${fileName}_Summary.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: {
            scale: 2,
            useCORS: true,
            logging: false,
            backgroundColor: '#0f172a'
        },
        jsPDF: { unit: 'in', format: 'a4', orientation: 'landscape' },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
    };

    // 3. Render PDF and cleanly restore elements
    html2pdf().set(options).from(element).save().then(() => {
        elementsToHide.forEach(el => el.style.display = '');
    }).catch(err => {
        console.error('PDF Generation Error:', err);
        elementsToHide.forEach(el => el.style.display = '');
    });
}
    
document.addEventListener('DOMContentLoaded', () => {
    const exportBtn = document.getElementById('exportPdfBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (typeof exportExecutiveSummary === 'function') {
                exportExecutiveSummary();
            } else {
                console.error('exportExecutiveSummary function is not defined in parser.js!');
            }
        });
    }
});
function clearReport() {
  if (confirm("Are you sure you want to clear the current report data?")) {
    // 1. Flush saved storage
    localStorage.removeItem('tamara_fileName');
    localStorage.removeItem('tamara_reportData');

    // 2. Refresh page to reset the state
    window.location.reload();
  }
}