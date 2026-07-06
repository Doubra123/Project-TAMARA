// This is a sample array representing the data Marianna will provide
 
    
    const vulnerabilityData = [
    {
      id: "details1",
      assetName: "Server-01",
      title: "Weak SSH Config",
      severity: "Medium",
      severityClass: "bg-warning text-white",
      status: "Open",
      dueDate: "2026-07-20",
      ipAddress: "192.168.1.10",
      cvss: "5.8",
      cveId: "CVE-2026-1234",
      description: "The SSH server allows insecure ciphers.",
      recommendation: "Disable weak ciphers in sshd_config.",
      assignedTo: "Marianna",
      evidence: "[Link to Screenshot]"
    },
    // FUTURE DATA GOES HERE
  ];
  
  // This function automatically builds the rows in your dashboard
  function loadDashboardData(data) {
    const tableBody = document.getElementById("vulnerability-table-body");
    tableBody.innerHTML = ""; // Clears the table

    data.forEach(vuln => {
      // 1. Create the main visible row
      const mainRow = document.createElement("tr");
      mainRow.innerHTML = `
        <td>${vuln.assetName}</td>
        <td>${vuln.title}</td>
        <td><span class="badge ${vuln.severityClass}">${vuln.severity}</span></td>
        <td>${vuln.status}</td>
        <td>${vuln.dueDate}</td>
        <td>
          <button class="btn btn-sm btn-primary" type="button" data-coreui-toggle="collapse" data-coreui-target="#${vuln.id}">
            View
          </button>
        </td>
      `;
        // 2. Create the hidden collapsible details row
      const detailsRow = document.createElement("tr");
      detailsRow.innerHTML = `
        <td colspan="6" class="p-0">
          <div class="collapse" id="${vuln.id}">
            <div class="card card-body">
              <strong>IP Address:</strong> ${vuln.ipAddress} | <strong>CVSS:</strong> ${vuln.cvss} | <strong>CVE ID:</strong> ${vuln.cveId}
              <p><strong>Description:</strong> ${vuln.description}</p>
              <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
              <p><strong>Assigned To:</strong> ${vuln.assignedTo}</p>
              <p><strong>Evidence:</strong> ${vuln.evidence}</p>
            </div>
          </div>
        </td>
      `;

      // 3. Append both rows into your table body
      tableBody.appendChild(mainRow);
      tableBody.appendChild(detailsRow);
    });
  }
  // Run the functions and setup search when the page loads
document.addEventListener("DOMContentLoaded", () => {
  loadDashboardData(vulnerabilityData);
  updateMetrics(vulnerabilityData);

  // 🔍 REAL-TIME SEARCH FUNCTIONALITY
  const searchInput = document.getElementById('search-input');
  searchInput.addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    
    // Filter the array based on Asset Name or Title matching the search term
    const filteredData = vulnerabilityData.filter(v => 
      v.assetName.toLowerCase().includes(searchTerm) || 
      v.title.toLowerCase().includes(searchTerm)
    );
    
    // Reload the table rows with only the filtered results
    loadDashboardData(filteredData);
  });
});
  //for th card calculation

  function updateMetrics(data) {
  const total = data.length;
  const criticalHigh = data.filter(v => v.severity === 'Critical' || v.severity === 'High').length;
  const openIssues = data.filter(v => v.status === 'Open').length;
  const remediated = data.filter(v => v.status === 'Remediated').length;

  document.getElementById('total-vulns').innerText = total;
  document.getElementById('critical-vulns').innerText = criticalHigh;
  document.getElementById('open-vulns').innerText = openIssues;
  document.getElementById('remediated-vulns').innerText = remediated;
}