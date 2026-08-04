// This is a sample array representing the data Marianna will provide
 
    
    const vulnerabilityData = [
  {
    "id": "details1",
    "assetName": "Cisco-SD-WAN-Controller",
    "title": "SD-WAN Controller Authentication Bypass",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Open",
    "dueDate": "2026-07-14",
    "ipAddress": "10.0.0.15",
    "cvss": "10.0",
    "cveId": "CVE-2026-20182",
    "description": "The vdaemon service's DTLS control-connection handshake skips certificate verification when a peer claims to be a vHub device. An unauthenticated remote attacker can become a trusted control-plane peer, inject SSH keys, manipulate NETCONF config, and push changes across the entire SD-WAN overlay.",
    "recommendation": "Upgrade to fixed releases: 20.9.9.1, 20.12.5.4+, 20.15.4.4+, 20.18.2.2, or 26.1.1.1. No workarounds exist. Inspect SD-WAN peering logs for unauthorized peer establishment.",
    "assignedTo": "Robert",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details2",
    "assetName": "PaloAlto-GlobalProtect-GW",
    "title": "PAN-OS GlobalProtect Authentication Bypass",
    "severity": "High",
    "severityClass": "bg-orange text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.22",
    "cvss": "7.8",
    "cveId": "CVE-2026-0257",
    "description": "The authentication override cookie encryption certificate is shared with the HTTPS portal service, allowing an attacker to forge valid session cookies without credentials and establish unauthorized VPN connections.",
    "recommendation": "Apply the May 2026 PAN-OS update immediately. Disable authentication override or generate a dedicated certificate. Review GlobalProtect logs for unexpected auth-override cookie usage.",
    "assignedTo": "Owens",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details3",
    "assetName": "Linux-Kernel-Node-01",
    "title": "Linux Kernel \"Copy Fail\" Privilege Escalation",
    "severity": "High",
    "severityClass": "bg-orange text-white",
    "status": "Open",
    "dueDate": "2026-07-14",
    "ipAddress": "192.168.50.10",
    "cvss": "7.8",
    "cveId": "CVE-2026-31431",
    "description": "A logic flaw in the algif_aead module allows unprivileged local users to corrupt the page cache of privileged binaries (e.g., /usr/bin/su) via AF_ALG socket + splice() abuse. Deterministic 732-byte Python exploit; no disk forensics trace. Container escape possible.",
    "recommendation": "Apply patched kernel packages immediately. Interim: disable algif_aead module with echo \\\"install algif_aead /bin/false\\\" > /etc/modprobe.d/disable-algif.conf then rmmod algif_aead.",
    "assignedTo": "Ivanka",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details4",
    "assetName": "cPanel-WHM-Host-01",
    "title": "cPanel & WHM Authentication Bypass",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Open",
    "dueDate": "2026-07-07",
    "ipAddress": "203.0.113.45",
    "cvss": "9.8",
    "cveId": "CVE-2026-41940",
    "description": "Chains CRLF injection in session writer with encryption-skip via malformed cookie and session caching quirk to achieve unauthenticated privileged login. ~1.5M internet-exposed instances. Ransomware (.sorry extension) and espionage campaigns confirmed.",
    "recommendation": "Upgrade to cPanel & WHM 11.136.0.5+ immediately. Block TCP 2083/2087 from untrusted networks as temp measure. Rotate all credentials post-patch. Audit for .sorry extension files.",
    "assignedTo": "Trump",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details5",
    "assetName": "FortiClient-EMS-Server",
    "title": "FortiClient EMS Pre-Authentication API Bypass",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Open",
    "dueDate": "2026-07-07",
    "ipAddress": "10.0.0.30",
    "cvss": "9.1",
    "cveId": "CVE-2026-35616",
    "description": "Improper access control in EMS API allows unauthenticated attackers to bypass auth and escalate to full server privileges. Attackers pushed credential stealer (EKZ Infostealer) disguised as legitimate Fortinet endpoint updates via VPN on-connect scripts.",
    "recommendation": "Upgrade to FortiClient EMS 7.4.7. 7.4.5/7.4.6 users apply hotfix 7.4.6.2170.1277073. Restrict EMS behind VPN/firewall. Audit VPN on-connect scripts for unauthorized modifications.",
    "assignedTo": "Tommas",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details6",
    "assetName": "Dynamics365-OnPrem-01",
    "title": "Dynamics 365 On-Premises Code Injection RCE",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Open",
    "dueDate": "2026-07-14",
    "ipAddress": "10.0.0.55",
    "cvss": "9.9",
    "cveId": "CVE-2026-42898",
    "description": "Insufficient validation of serialized process session state allows authenticated low-privilege attackers to inject malicious code. Scope change enables breakout beyond Dynamics into adjacent systems.",
    "recommendation": "Apply May 2026 Cumulative Update for Dynamics 365 on-premises. Limit user permissions to minimum required. Monitor CRM process logs for unexpected serialization activity.",
    "assignedTo": "Madonna",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details7",
    "assetName": "Windows-DC-Primary",
    "title": "Windows Netlogon Remote Code Execution",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Closed",
    "dueDate": "2026-07-07",
    "ipAddress": "10.0.0.5",
    "cvss": "9.8",
    "cveId": "CVE-2026-41089",
    "description": "Stack-based buffer overflow in Netlogon Remote Protocol (MS-NRPC) triggered by unvalidated caller-specified length value during auth handshake. Unauthenticated remote attacker can execute code as SYSTEM on domain controllers.",
    "recommendation": "Apply May 2026 Patch Tuesday to all DCs first. Restrict Netlogon to required source networks. Remove DC reachability from DMZ and user VLANs. Monitor for unexpected RPC endpoint connections.",
    "assignedTo": "Coleman",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details8",
    "assetName": "Windows-Endpoint-Fleet",
    "title": "Microsoft Defender Elevation of Privilege",
    "severity": "low",
    "severityClass": "bg-success text-white",
    "status": "Closed",
    "dueDate": "2026-07-14",
    "ipAddress": "192.168.10.0/24",
    "cvss": "7.8",
    "cveId": "CVE-2026-41091",
    "description": "Malware Protection Engine (mpengine.dll) improperly resolves symlinks before sensitive file access. Local low-priv attacker can redirect privileged file access to escalate to SYSTEM. Paired with CVE-2026-45498 (DoS) to disable Defender during exploitation.",
    "recommendation": "Verify engine updated to 1.1.26040.8 and platform to 4.18.26040.7. Manually confirm on domain-joined systems and servers with impaired update connectivity. Check CVE-2026-45498 patch simultaneously.",
    "assignedTo": "Charlie",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details9",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Terminal WebSocket Auth Bypass",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Closed",
    "dueDate": "2026-07-14",
    "ipAddress": "10.0.0.80",
    "cvss": "9.9",
    "cveId": "CVE-2026-34048",
    "description": "Terminal websocket bootstrap routes only check authentication but do not enforce terminal authorization. Low-privileged team member can connect to terminal routes and execute commands on team servers.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review team member permissions and audit terminal access logs for unauthorized connections.",
    "assignedTo": "Ekira",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details10",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Terminal WebSocket Scope Escape",
    "severity": "Critical",
    "severityClass": "bg-danger text-white",
    "status": "Closed",
    "dueDate": "2026-07-14",
    "ipAddress": "10.0.0.80",
    "cvss": "9.9",
    "cveId": "CVE-2026-34047",
    "description": "Terminal WebSocket bootstrap routes did not enforce expected authorization middleware. Authenticated user can access terminal functionality for resources outside authorized scope and execute commands.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Implement additional network segmentation for terminal access. Audit all terminal session logs.",
    "assignedTo": "Marianna",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details11",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Command Injection in GetLogs",
    "severity": "medium",
    "severityClass": "bg-warning text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-34599",
    "description": "Authenticated command injection in GetLogs Livewire component. $container property interpolated directly into shell commands without sanitization. Lowest-privilege team member can execute arbitrary commands as root on managed servers.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review Livewire component security. Audit docker logs access patterns for unusual container IDs.",
    "assignedTo": "Austine",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details12",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Docker Compose Command Injection",
    "severity": "High",
    "severityClass": "bg-orange text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-34158",
    "description": "executeInDocker() helper wraps user-controlled commands in single quotes without escaping embedded single quotes. Attackers editing app settings can inject single quotes to break out and execute arbitrary commands on the managed server host.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.469+. Review application settings permissions. Audit deployment logs for unusual command execution patterns.",
    "assignedTo": "Malcom",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details13",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify PostgreSQL Init Script Path Traversal",
    "severity": "low",
    "severityClass": "bg-success text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-42200",
    "description": "PostgreSQL initialization script filename handling did not restrict paths sufficiently. Authenticated user can write files outside intended directory and achieve command execution through database initialization.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.474+. Review database backup/restore procedures. Audit file system for unauthorized files in PostgreSQL directories.",
    "assignedTo": "Clay",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details14",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Persistent Volume Shell Injection",
    "severity": "medium",
    "severityClass": "bg-warning text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-42143",
    "description": "User-controlled persistent volume names interpolated into shell commands without escaping or validation. Authenticated member can inject shell metacharacters and execute commands as root when volume operations are triggered.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review volume naming conventions and input validation. Audit volume operation logs for injected commands.",
    "assignedTo": "Troy",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details15",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify LocalPersistentVolume Shell Injection",
    "severity": "High",
    "severityClass": "bg-orange text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-34168",
    "description": "LocalPersistentVolume.name field interpolated directly into docker volume shell commands without escaping. Authenticated user can set storage name with shell metacharacters to execute commands on managed servers during resource deletion.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Implement strict input validation on storage names. Audit docker volume operations for anomalies.",
    "assignedTo": "Jesse",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details16",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Pre/Post-Deployment Command Injection",
    "severity": "medium",
    "severityClass": "bg-warning text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-34152",
    "description": "Pre-deployment and post-deployment commands are single-quote escaped but sent through SSH heredoc that preserves newlines. Authenticated user can inject additional shell statements executing on remote server during deployment.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review deployment pipeline security. Audit deployment logs for multi-line command injections.",
    "assignedTo": "Tony",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details17",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Server Resources Command Injection",
    "severity": "High",
    "severityClass": "bg-orange text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-34058",
    "description": "Server\\Resources Livewire component exposes public methods (startUnmanaged, stopUnmanaged, restartUnmanaged) accepting container ID from browser without sanitization. Parameter interpolated into SSH shell commands enabling arbitrary OS command execution.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review Livewire public method exposure. Audit SSH command logs for unauthorized container operations.",
    "assignedTo": "Stephen",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details18",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Database Import Command Injection",
    "severity": "High",
    "severityClass": "bg-danger text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.8",
    "cveId": "CVE-2026-34057",
    "description": "Database import Livewire component allows client-controlled container and server properties to reach shell commands without locking or validation. Authenticated user can inject commands through database import container name.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review import workflow security. Audit database import logs for unusual container names.",
    "assignedTo": "Marie",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details19",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Invitation Password Reset Takeover",
    "severity": "high",
    "severityClass": "bg-danger text-white",
    "status": "Closed",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.80",
    "cvss": "8.0",
    "cveId": "CVE-2026-34171",
    "description": "GET /invitations/{uuid} endpoint performs state-changing password reset using attacker-known invitation UUID. Attacker can cause victim to visit crafted URL to reset victim account password to predictable value.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review invitation token generation and expiration. Audit password reset logs for suspicious invitation UUID usage.",
    "assignedTo": "Pepper",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details20",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Host Header Password Reset Spoofing",
    "severity": "Medium",
    "severityClass": "bg-warning text-white",
    "status": "Closed",
    "dueDate": "2026-07-28",
    "ipAddress": "10.0.0.80",
    "cvss": "5.3",
    "cveId": "CVE-2026-34198",
    "description": "TrustProxies middleware trusts all proxies (*), accepting X-Forwarded-Host from any source. TrustHosts middleware has circular caching dependency preventing host validation. Password reset URL uses spoofable request host, allowing unauthenticated attacker to intercept reset links.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Configure explicit trusted proxy list. Review password reset email delivery and URL generation.",
    "assignedTo": "Benjamin",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details21",
    "assetName": "Ajenti-Admin-Panel",
    "title": "Ajenti Clickjacking in Admin UI",
    "severity": "Medium",
    "severityClass": "bg-warning text-white",
    "status": "Open",
    "dueDate": "2026-07-28",
    "ipAddress": "10.0.0.90",
    "cvss": "6.1",
    "cveId": "CVE-2026-38979",
    "description": "ajenti through v2.2.13 has clickjacking weakness in browser-facing login and admin UI. HTTP response path initializes empty header list and finalizes through WSGI without adding X-Frame-Options or CSP frame-ancestors restrictions.",
    "recommendation": "Upgrade to ajenti v2.2.14+ or apply custom middleware adding X-Frame-Options: DENY and Content-Security-Policy frame-ancestors restrictions.",
    "assignedTo": "Stella",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details22",
    "assetName": "mrubyc-Runtime-Server",
    "title": "mrubyc NULL Pointer Dereference",
    "severity": "High",
    "severityClass": "bg-orange text-white",
    "status": "Open",
    "dueDate": "2026-07-21",
    "ipAddress": "10.0.0.95",
    "cvss": "7.5",
    "cveId": "CVE-2026-38976",
    "description": "mrubyc through 3.4.1 contains NULL pointer dereference in src/vm.c in op_super() / OP_SUPER due to missing runtime guard for top-level super calls, leading to denial of service or potential code execution.",
    "recommendation": "Upgrade to mrubyc 3.4.2+. Review VM runtime guards. Audit application logs for unexpected crashes in mrubyc processes.",
    "assignedTo": "Marianna",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details23",
    "assetName": "mrubyc-Runtime-Server",
    "title": "mrubyc Out-of-Bounds Read in Method Lookup",
    "severity": "low",
    "severityClass": "bg-success text-white",
    "status": "Open",
    "dueDate": "2026-07-14",
    "ipAddress": "10.0.0.95",
    "cvss": "9.8",
    "cveId": "CVE-2026-38973",
    "description": "mrubyc through 3.4.1 contains out-of-bounds read in builtin missing-method lookup inside mrbc_find_method(). Can leak sensitive memory or be chained for remote code execution.",
    "recommendation": "Upgrade to mrubyc 3.4.2+. Implement input validation on method names. Monitor for memory access anomalies in mrubyc runtime.",
    "assignedTo": "Clark",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details24",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify S3 Storage SSRF",
    "severity": "Medium",
    "severityClass": "bg-warning text-white",
    "status": "Closed",
    "dueDate": "2026-07-28",
    "ipAddress": "10.0.0.80",
    "cvss": "4.9",
    "cveId": "CVE-2026-42147",
    "description": "S3 storage endpoint validation only checks URL format; testConnection() sends server-side request to configured endpoint. Authenticated user with storage management permissions can make Coolify request internal or metadata-service URLs.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.474+. Implement endpoint allowlisting and block private IP ranges. Audit S3 connection test logs for internal URL requests.",
    "assignedTo": "Kent",
    "evidence": "[Link to Screenshot]"
  },
  {
    "id": "details25",
    "assetName": "Coolify-App-Server-01",
    "title": "Coolify Database Backup Shell Injection",
    "severity": "Medium",
    "severityClass": "bg-warning text-white",
    "status": "Closed",
    "dueDate": "2026-07-28",
    "ipAddress": "10.0.0.80",
    "cvss": "5.3",
    "cveId": "CVE-2026-34149",
    "description": "DatabaseBackupJob interpolates user-controlled database credentials and MongoDB collection exclusion names into backup shell commands without adequate escaping. Authenticated user with DB management permissions can execute commands on managed servers.",
    "recommendation": "Upgrade to Coolify 4.0.0-beta.471+. Review backup job parameterization. Audit backup command logs for shell metacharacters in credentials.",
    "assignedTo": "Baron",
    "evidence": "[Link to Screenshot]"
  },
  {
  "id": "details7",
  "assetName": "Staff-Workstation-05",
  "title": "Unencrypted HTTP Traffic Allowed",
  "severity": "Low",
  "severityClass": "bg-success text-white",
  "status": "Open",
  "dueDate": "2026-08-14",
  "ipAddress": "10.0.0.55",
  "cvss": "2.5",
  "cveId": "CVE-2026-9999",
  "description": "The web server allows unencrypted communication.",
  "recommendation": "Enforce HTTPS configuration.",
  "assignedTo": "Mercy",
  "evidence": "[Link to Screenshot]"
}
  
]
  
  // This function automatically builds the rows in your dashboard
 function loadDashboardData(data) {
  const tableBody = document.getElementById("vulnerability-table-body");
  tableBody.innerHTML = ""; 

  data.forEach((vuln, index) => {
    // 1. Create the main data row with our search class
    const mainRow = document.createElement("tr");
    mainRow.className = "vulnerability-row";
    
    mainRow.innerHTML = `
      <td><strong>${vuln.assetName || "Unknown"}</strong><br><small class="text-muted font-monospace">${vuln.ipAddress || "0.0.0.0"}</small></td>
      <td><strong>${vuln.title}</strong><br><small class="text-muted">${vuln.cveId || "N/A"}</small> <span class="badge bg-secondary text-light">CVSS: ${vuln.cvss || "0.0"}</span></td>
      <td><span class="badge ${vuln.severityClass || 'bg-secondary'}">${vuln.severity}</span></td>
      <td><span class="badge ${vuln.status.toLowerCase() === 'open' ? 'bg-warning text-dark' : 'bg-success'}">${vuln.status}</span></td>
      <td><strong>${vuln.assignedTo || "Unassigned"}</strong></td>
      <td>${vuln.dueDate || "No Date Set"}</td>
      <td>
        <button class="btn btn-sm btn-primary" type="button" data-coreui-toggle="collapse" data-coreui-target="#details-${index}">
          View
        </button>
      </td>
    `;
    tableBody.appendChild(mainRow);

    // 2. Create the hidden collapsible details row
    const detailsRow = document.createElement("tr");
   detailsRow.innerHTML = `
    <td colspan="7" class="p-0">
        <div class="collapse" id="details-${index}">
            <div class="card card-body">
                <p><strong>Description:</strong> ${vuln.description || "No description provided."}</p>
                <p><strong>Recommendation:</strong> ${vuln.recommendation || "No recommendation provided."}</p>
                <p><strong>Evidence:</strong> ${vuln.evidence || "None"}</p>

                <!-- NEW REMEDIATION BUTTON SYSTEM -->
                ${vuln.status.toLowerCase() === 'open' ? `
                    <div style="margin-top: 15px;">
                        <button class="btn btn-sm btn-success remediate-btn" data-index="${index}">
                            ✓ Mark as Remediated
                        </button>
                    </div>
                ` : `
                    <div style="margin-top: 15px; color: #198754; font-weight: bold;">
                        ✓ This vulnerability has been successfully resolved.
                    </div>
                `}
            </div>
        </div>
    </td>
`;
    tableBody.appendChild(detailsRow);
    // --- REMEDIATION BUTTON CLICK LOGIC ---
        const remediateBtn = detailsRow.querySelector('.remediate-btn');
        if (remediateBtn) {
            remediateBtn.addEventListener('click', () => {
                vulnerabilityData[index].status = "Closed";
                loadDashboardData(vulnerabilityData);
                
                const total = vulnerabilityData.length;
                const criticalHigh = vulnerabilityData.filter(v => v.severity === "Critical" || v.severity === "High").length;
                const openIssues = vulnerabilityData.filter(v => v.status.toLowerCase() === "open").length;
                const riskPercentage = total > 0 ? Math.round((criticalHigh / total) * 100) : 0;
                
                updateMetricsUsingData(total, criticalHigh, openIssues, riskPercentage, "vulnerabilityData");
            });
        }
  });

}
  // Run the functions and setup search when the page loads
document.addEventListener("DOMContentLoaded", () => {
    // 1. Load the initial table rows
    loadDashboardData(vulnerabilityData);
    
    // 2. Calculate the real metrics dynamically
    const total = vulnerabilityData.length;
    const criticalHigh = vulnerabilityData.filter(v => v.severity === "Critical" || v.severity === "High").length;
    const openIssues = vulnerabilityData.filter(v => v.status.toLowerCase() === "open").length;
    
    // Simple custom risk metric calculation (e.g., percentage of open severe issues)
    const riskPercentage = total > 0 ? Math.round((criticalHigh / total) * 100) : 0;
    
    // 3. Update the metric cards at the top
    updateMetricsUsingData(total, criticalHigh, openIssues, riskPercentage, "Initial_System_Scan");

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
  //for the card calculation

 function updateMetricsUsingData(total, criticalHigh, openIssues, riskPercentage, fileName = null) {
    // Update the 4 Pillar Cards directly by their exact IDs
    document.getElementById('total-vulns').innerText = total;
    document.getElementById('critical-vulns').innerText = criticalHigh;
    document.getElementById('open-vulns').innerText = openIssues;
    document.getElementById('remediated-vulns').innerText = 0; // Stays at 0 until remediated

    // Update the Global Risk Score Card using your exact math formula percentage
    document.getElementById('global-risk-score').innerText = riskPercentage + '%';
    updateRiskUI(riskPercentage);

    // Update Metadata (File Name & Live Timestamp) if a new file is uploaded
    if (fileName) {
        document.getElementById('report-name').innerText = fileName;
        
        const now = new Date();
        const options = { day: '2-digit', month: 'short', year: 'numeric' };
        const timeOptions = { hour: 'numeric', minute: '2-digit', hour12: true };
        const formattedDate = now.toLocaleDateString('en-GB', options);
        const formattedTime = now.toLocaleTimeString('en-US', timeOptions).toLowerCase();
        
        document.getElementById('scan-timestamp').innerText = `${formattedDate} • ${formattedTime}`;
    }
}
// --- TASK 1: LIVE TABLE SEARCH FILTER ---
document.getElementById('search-input').addEventListener('input', function (e) {
    const query = e.target.value.toLowerCase().trim();
    const tableRows = document.querySelectorAll('tbody tr.vulnerability-row');

    tableRows.forEach(row => {
        // Extract text from the first column (Asset Name) and second column (Vulnerability Title)
        const assetName = row.cells[0]?.textContent.toLowerCase() || '';
        const vulnTitle = row.cells[1]?.textContent.toLowerCase() || '';

        // If the query matches either column, display the row, otherwise hide it
        if (assetName.includes(query) || vulnTitle.includes(query)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
});
function updateRiskUI(score) {
  const riskCard = document.getElementById('global-risk-card');
  const riskScoreText = document.getElementById('global-risk-score');
  
  // Clear any existing border accent classes
  riskCard.classList.remove('border-start-danger', 'border-start-warning', 'border-start-success');
  
  if (score >= 50) {
    // High / Critical Risk: Red
    riskCard.classList.add('border-start-danger');
    riskScoreText.style.color = '#ef4444';
  } else if (score > 0) {
    // Medium / Low Risk: Amber/Yellow
    riskCard.classList.add('border-start-warning');
    riskScoreText.style.color = '#f59e0b';
  } else {
    // 0% / Clean: Green
    riskCard.classList.add('border-start-success');
    riskScoreText.style.color = '#10b981';
  }
}
