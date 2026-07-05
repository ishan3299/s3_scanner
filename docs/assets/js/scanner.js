/**
 * S3 Misconfiguration Scanner - Passive Client-Side Scanner
 * 
 * This script performs safe, passive checks against S3 buckets.
 * It respects all CORS policies and does not perform destructive actions.
 */

const TIMEOUT_MS = 5000;

class S3Scanner {
    constructor() {
        this.reset('');
    }

    reset(bucketName) {
        this.results = {
            bucketName: bucketName,
            exists: false,
            region: 'Unknown',
            endpoint: '',
            publicAccess: false,
            listingEnabled: false,
            websiteEnabled: false,
            corsOpen: false,
            findings: [],
            checks: [], // { name, status: 'Pass'/'Fail'/'Error', icon }
            score: 0,
            riskLevel: 'Safe'
        };
    }

    async scan(bucketName) {
        this.reset(bucketName);
        console.log(`Starting scan for: ${bucketName}`);

        // 1. Check Existence & Regional Redirects
        await this.checkExistenceAndRegion(bucketName);

        if (this.results.exists) {
            // Concurrent checks for speed
            await Promise.allSettled([
                this.checkPublicListing(bucketName),
                this.checkWebsiteEndpoint(bucketName),
                this.checkCommonFiles(bucketName),
                this.checkACL(bucketName),
                this.checkPolicy(bucketName),
                this.checkCors(bucketName),
                this.checkVersioning(bucketName)
            ]);
        }

        this.calculateRisk();
        return this.results;
    }

    async fetchWithTimeout(resource, options = {}) {
        const { timeout = TIMEOUT_MS } = options;

        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(resource, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(id);
            return response;
        } catch (error) {
            clearTimeout(id);
            throw error;
        }
    }

    async fetchViaProxy(url, options = {}) {
        // Use allorigins.win JSON wrapper endpoint to get status code and headers
        const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
        const response = await this.fetchWithTimeout(proxyUrl, { method: 'GET' });
        if (!response.ok) {
            throw new Error(`Proxy error: ${response.statusText}`);
        }
        const data = await response.json();
        const httpCode = data.status?.http_code || 500;
        
        // Reconstruct response-like object
        return {
            status: httpCode,
            ok: httpCode >= 200 && httpCode < 300,
            text: async () => data.contents || '',
            headers: {
                get: (headerName) => {
                    const headers = data.status?.response_headers || {};
                    // Look up case-insensitively since header keys can vary
                    const key = Object.keys(headers).find(k => k.toLowerCase() === headerName.toLowerCase());
                    return key ? headers[key] : null;
                }
            }
        };
    }

    async fetchWithFallback(url, options = {}) {
        try {
            // Try standard fetch first (fast, direct, preserves credentials if any)
            return await this.fetchWithTimeout(url, options);
        } catch (error) {
            // Fallback to CORS proxy
            console.log(`Direct fetch failed for ${url} (likely CORS). Retrying via proxy...`);
            return await this.fetchViaProxy(url, options);
        }
    }

    async checkExistenceAndRegion(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/`;
        this.results.endpoint = url;

        try {
            const response = await this.fetchWithFallback(url, { method: 'GET' });
            
            // A bucket exists if the status is not a 404
            if (response.status !== 404) {
                this.results.exists = true;
            }

            const regionHeader = response.headers.get('x-amz-bucket-region');
            if (regionHeader) {
                this.results.region = regionHeader;
            }

            if (response.status === 200) {
                this.addFinding({
                    id: 'public-access',
                    title: 'Publicly Accessible Root',
                    severity: 'High',
                    description: 'The bucket root URL returns a 200 OK status. This often implies public access.',
                    remediation: 'Disable public access via S3 Block Public Access settings.'
                });
                this.results.publicAccess = true;
                this.results.corsOpen = true;
            }
        } catch (error) {
            // If even proxy fails (e.g. invalid bucket name that fails DNS)
            this.results.exists = false;
        }

        // Log existence check
        this.results.checks.push({
            name: 'Bucket Existence',
            status: this.results.exists ? 'Pass' : 'Fail',
            icon: 'fa-box'
        });
    }

    probeImage(url) {
        return new Promise((resolve) => {
            const img = new Image();
            const timer = setTimeout(() => {
                img.src = ""; // Stop loading
                resolve(false);
            }, TIMEOUT_MS);

            img.onload = () => { clearTimeout(timer); resolve(true); };
            img.onerror = () => { clearTimeout(timer); resolve(false); };
            img.src = url + 'favicon.ico';
        });
    }

    async checkPublicListing(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/?list-type=2`;
        let status = 'Pass';
        try {
            const response = await this.fetchWithFallback(url);
            if (response.status === 200) {
                const text = await response.text();
                if (text.includes('ListBucketResult')) {
                    this.results.listingEnabled = true;
                    status = 'Fail';
                    this.addFinding({
                        id: 'list-objects',
                        title: 'Public Object Listing Enabled',
                        severity: 'Critical',
                        description: 'Anyone can list all files in your bucket. This leads to data scraping and leakage.',
                        remediation: 'Remove the "s3:ListBucket" permission from the "Everyone" principal in the Bucket Policy.'
                    });
                }
            } else if (response.status === 403) {
                status = 'Pass'; // Explicit Access Denied is good
            }
        } catch (e) {
            status = 'Error'; // Network error or CORS blocking
        }
        this.results.checks.push({ name: 'Object Listing', status, icon: 'fa-list' });
    }

    async checkWebsiteEndpoint(bucket) {
        let status = 'Pass';
        let regionsToCheck = this.results.region !== 'Unknown' ? [this.results.region] : ['us-east-1', 'us-west-2', 'eu-west-1'];

        // We only really need to find one exposed endpoint
        for (const region of regionsToCheck) {
            const url = `http://${bucket}.s3-website-${region}.amazonaws.com`;
            try {
                const response = await this.fetchWithFallback(url);
                if (response.status === 200) {
                    status = 'Fail';
                    this.results.websiteEnabled = true;
                    this.addFinding({
                        id: 'website-endpoint',
                        title: 'Website Hosting Enabled',
                        severity: 'Low',
                        description: `The S3 website hosting endpoint is publicly accessible at ${url}`,
                        remediation: 'Disable static website hosting if the bucket is only used for object storage.'
                    });
                    break;
                }
            } catch (e) { }
        }
        this.results.checks.push({ name: 'Website Endpoint', status, icon: 'fa-globe' });
    }

    async checkACL(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/?acl`;
        let status = 'Pass';
        try {
            const response = await this.fetchWithFallback(url);
            if (response.status === 200) {
                const text = await response.text();
                if (text.includes('AccessControlPolicy')) {
                    status = 'Fail';
                    this.addFinding({
                        id: 'exposed-acl',
                        title: 'Public ACL Configuration',
                        severity: 'High',
                        description: 'The Access Control List (ACL) is publicly readable.',
                        remediation: 'Remove s3:GetBucketAcl permission for anonymous users.'
                    });
                }
            }
        } catch (e) { status = 'Error'; }
        this.results.checks.push({ name: 'Bucket ACL', status, icon: 'fa-id-badge' });
    }

    async checkPolicy(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/?policy`;
        let status = 'Pass';
        try {
            const response = await this.fetchWithFallback(url);
            if (response.status === 200) {
                status = 'Fail';
                this.addFinding({
                    id: 'exposed-policy',
                    title: 'Public Bucket Policy',
                    severity: 'High',
                    description: 'The Bucket Policy is publicly readable. Attackers can learn permissions structure.',
                    remediation: 'Remove s3:GetBucketPolicy permission for anonymous users.'
                });
            }
        } catch (e) { status = 'Error'; }
        this.results.checks.push({ name: 'Bucket Policy', status, icon: 'fa-file-shield' });
    }

    async checkCors(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/?cors`;
        let status = 'Pass';
        try {
            const response = await this.fetchWithFallback(url);
            if (response.status === 200) {
                status = 'Fail'; // Check if it's too open? For now, just exposure is a hint.
                // Actually reading CORS config is rare.
                this.addFinding({
                    id: 'exposed-cors',
                    title: 'CORS Configuration Exposed',
                    severity: 'Low',
                    description: 'CORS configuration is readable.',
                    remediation: 'Restrict s3:GetBucketCORS.'
                });
            }
        } catch (e) { status = 'Error'; }
        this.results.checks.push({ name: 'CORS Config', status, icon: 'fa-code' });
    }

    async checkVersioning(bucket) {
        // Checking object versions listing
        const url = `https://${bucket}.s3.amazonaws.com/?versions`;
        let status = 'Pass';
        try {
            const response = await this.fetchWithFallback(url);
            if (response.status === 200) {
                status = 'Fail';
                this.addFinding({
                    id: 'list-versions',
                    title: 'Object Versions Exposed',
                    severity: 'Critical',
                    description: 'Old versions of files can be listed and retrieved.',
                    remediation: 'Remove s3:ListBucketVersions permission.'
                });
            }
        } catch (e) { status = 'Error'; }
        this.results.checks.push({ name: 'Object Versions', status, icon: 'fa-clock-rotate-left' });
    }

    async checkCommonFiles(bucket) {
        const files = ['robots.txt', 'index.html', '.env', 'config.json', '.git/HEAD', 'backup.zip', '.DS_Store'];
        let exposedCount = 0;

        const checks = files.map(async (file) => {
            const url = `https://${bucket}.s3.amazonaws.com/${file}`;
            try {
                const response = await this.fetchWithFallback(url, { method: 'HEAD' }); // Use HEAD first
                if (response.status === 200) {
                    exposedCount++;
                    this.addFinding({
                        id: 'exposed-file-' + file,
                        title: `Exposed File: ${file}`,
                        severity: (file === '.env' || file === 'config.json' || file.includes('.git')) ? 'Critical' : 'Low',
                        description: `The file '${file}' is publicly readable.`,
                        remediation: 'Ensure only public assets are readable. Review bucket policies.'
                    });
                }
            } catch (e) { }
        });

        await Promise.allSettled(checks);
        this.results.checks.push({ name: 'Common Files', status: exposedCount > 0 ? 'Fail' : 'Pass', icon: 'fa-file' });
    }

    addFinding(finding) {
        // Dedup
        if (!this.results.findings.some(f => f.id === finding.id)) {
            this.results.findings.push(finding);
        }
    }

    calculateRisk() {
        let score = 0;

        // Base weights
        if (this.results.listingEnabled) score += 50;
        if (this.results.publicAccess) score += 30;

        this.results.findings.forEach(f => {
            if (f.severity === 'Critical') score += 20;
            if (f.severity === 'High') score += 15;
            if (f.severity === 'Medium') score += 10;
        });

        this.results.score = Math.min(score, 100);

        if (this.results.score === 0) this.results.riskLevel = 'Safe';
        else if (this.results.score < 30) this.results.riskLevel = 'Low';
        else if (this.results.score < 70) this.results.riskLevel = 'Medium';
        else this.results.riskLevel = 'Critical';
    }
}

// UI Controller
document.addEventListener('DOMContentLoaded', () => {
    const scanner = new S3Scanner();
    
    // Tab Elements
    const s3ScannerTabBtn = document.getElementById('s3ScannerTabBtn');
    const awsDashboardTabBtn = document.getElementById('awsDashboardTabBtn');
    const s3ScannerTabContent = document.getElementById('s3ScannerTabContent');
    const awsDashboardTabContent = document.getElementById('awsDashboardTabContent');

    // S3 Scanner Elements
    const scanBtn = document.getElementById('scanBtn');
    const bucketInput = document.getElementById('bucketInput');
    const resultsSection = document.getElementById('resultsSection');
    const spinner = document.querySelector('.spinner');
    const btnText = document.querySelector('.btn-text');
    const exportBtn = document.getElementById('exportBtn');

    // Dashboard Elements
    const dashboardNoReport = document.getElementById('dashboardNoReport');
    const dashboardContent = document.getElementById('dashboardContent');
    const demoReportBtn = document.getElementById('demoReportBtn');
    const dashAccountId = document.getElementById('dashAccountId');
    const dashLastAudited = document.getElementById('dashLastAudited');
    const dashRiskStatus = document.getElementById('dashRiskStatus');
    const dashScoreValue = document.getElementById('dashScoreValue');
    const dashRiskLevel = document.getElementById('dashRiskLevel');
    const dashRiskSummary = document.getElementById('dashRiskSummary');
    const dashScoreRing = document.getElementById('dashScoreRing');
    const countCritical = document.getElementById('countCritical');
    const countHigh = document.getElementById('countHigh');
    const countMedium = document.getElementById('countMedium');
    const countLow = document.getElementById('countLow');
    const dashboardFindingsList = document.getElementById('dashboardFindingsList');

    let loadedReport = null;
    let activeServiceFilter = 'ALL';

    // Tab Navigation Logic
    s3ScannerTabBtn.addEventListener('click', () => switchTab('S3'));
    awsDashboardTabBtn.addEventListener('click', () => switchTab('AWS'));

    function switchTab(tab) {
        if (tab === 'S3') {
            s3ScannerTabBtn.classList.add('active');
            awsDashboardTabBtn.classList.remove('active');
            s3ScannerTabContent.classList.remove('hidden');
            awsDashboardTabContent.classList.add('hidden');
        } else {
            awsDashboardTabBtn.classList.add('active');
            s3ScannerTabBtn.classList.remove('active');
            awsDashboardTabContent.classList.remove('hidden');
            s3ScannerTabContent.classList.add('hidden');
            
            // Try to load scan report if not already loaded
            if (!loadedReport) {
                loadScanReport();
            }
        }
    }

    // S3 Scanner Events
    scanBtn.addEventListener('click', handleScan);
    bucketInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleScan();
    });
    exportBtn.addEventListener('click', generatePDF);

    async function handleScan() {
        const bucket = bucketInput.value.trim();
        if (!bucket) return;

        // UI Reset
        scanBtn.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        document.getElementById('findingsGrid').innerHTML = '';
        document.getElementById('remediationList').innerHTML = '';

        // Extract bucket name from URL if needed
        let cleanBucket = bucket;
        if (bucket.includes('://')) {
            try {
                const urlObj = new URL(bucket);
                if (urlObj.hostname.includes('.s3')) {
                    const parts = urlObj.hostname.split('.s3');
                    cleanBucket = parts[0];
                }
            } catch (e) {
                console.error("Invalid URL");
            }
        }

        try {
            const results = await scanner.scan(cleanBucket);
            renderResults(results);
        } catch (error) {
            console.error(error);
            alert('An error occurred during scanning: ' + error.message);
        } finally {
            scanBtn.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    }

    function renderResults(results) {
        resultsSection.classList.remove('hidden');
        document.getElementById('targetBucketName').textContent = results.bucketName;
        document.getElementById('scoreValue').textContent = results.score;
        document.getElementById('riskLevel').textContent = results.riskLevel;

        document.getElementById('infoRegion').textContent = results.region;
        document.getElementById('infoEndpoint').textContent = results.endpoint || '-';
        document.getElementById('infoStatus').textContent = results.exists ? 'Exists' : 'Not Found';
        if (!results.exists) {
            document.getElementById('infoStatus').style.color = '#ef4444';
        } else {
            document.getElementById('infoStatus').style.color = '#10b981';
        }

        const circle = document.getElementById('scoreRing');
        const circumference = 326.72;
        const offset = circumference - (results.score / 100) * circumference;
        circle.style.strokeDashoffset = offset;

        let color = '#10b981';
        if (results.score > 29) color = '#f59e0b';
        if (results.score > 69) color = '#e11d48';
        circle.style.stroke = color;
        document.getElementById('riskLevel').style.color = color;

        const summary = document.getElementById('riskSummary');
        if (results.score === 0 && results.exists) summary.textContent = "The bucket exists but appears secure against public scanning.";
        else if (!results.exists) summary.textContent = "Bucket could not be reached via public endpoints (may be private or non-existent).";
        else summary.textContent = "Potential vulnerabilities were detected.";

        // Findings
        const grid = document.getElementById('findingsGrid');
        const remediationList = document.getElementById('remediationList');
        const remSection = document.getElementById('remediationSection');
        const coverageGrid = document.getElementById('coverageGrid');

        if (results.findings.length > 0) {
            results.findings.forEach(f => {
                const card = document.createElement('div');
                card.className = 'finding-card';
                card.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-title">${f.title}</span>
                        <span class="finding-badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                    </div>
                    <p class="finding-desc">${f.description}</p>
                    <div class="finding-status status-danger">
                        <i class="fa-solid fa-circle-exclamation"></i> Detected
                    </div>
                `;
                grid.appendChild(card);

                const li = document.createElement('li');
                li.textContent = f.remediation;
                remediationList.appendChild(li);
            });
            remSection.classList.remove('hidden');
        } else {
            const card = document.createElement('div');
            card.className = 'finding-card';
            card.innerHTML = `
                <div class="finding-header">
                    <span class="finding-title">No Issues Found</span>
                    <span class="finding-badge badge-low">SAFE</span>
                </div>
                <p class="finding-desc">Passive scans did not detect any obvious public exposures.</p>
                <div class="finding-status status-success">
                    <i class="fa-solid fa-check-circle"></i> Secure
                </div>
             `;
            grid.appendChild(card);
            remSection.classList.add('hidden');
        }

        // Coverage Grid
        coverageGrid.innerHTML = '';
        if (results.checks && results.checks.length > 0) {
            results.checks.forEach(check => {
                const item = document.createElement('div');
                item.className = 'check-item';

                let iconClass = 'check-pass';
                let icon = 'fa-check';

                if (check.status === 'Fail') {
                    iconClass = 'check-fail';
                    icon = 'fa-xmark';
                } else if (check.status === 'Error') {
                    iconClass = 'check-warn';
                    icon = 'fa-exclamation';
                }

                item.innerHTML = `<i class="fa-solid ${icon} ${iconClass}"></i> ${check.name}`;
                coverageGrid.appendChild(item);
            });
        }
    }

    function generatePDF() {
        if (!window.jspdf) {
            alert('PDF library not loaded.');
            return;
        }
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        const name = document.getElementById('targetBucketName').textContent;
        const score = document.getElementById('scoreValue').textContent;
        const level = document.getElementById('riskLevel').textContent;

        doc.setFontSize(20);
        doc.text("S3 Misconfiguration Report", 10, 20);

        doc.setFontSize(12);
        doc.text(`Bucket: ${name}`, 10, 30);
        doc.text(`Date: ${new Date().toLocaleString()}`, 10, 36);
        doc.text(`Risk Score: ${score}/100 (${level})`, 10, 42);

        doc.setLineWidth(0.5);
        doc.line(10, 45, 200, 45);

        let y = 55;
        doc.setFontSize(14);
        doc.text("Findings:", 10, y);
        y += 10;

        const findings = document.querySelectorAll('.finding-card');
        if (findings.length === 0 || findings[0].querySelector('.finding-title').textContent === 'No Issues Found') {
            doc.setFontSize(10);
            doc.text("- No high-risk public configurations detected via passive scan.", 15, y);
        } else {
            findings.forEach(f => {
                const title = f.querySelector('.finding-title').textContent;
                const severity = f.querySelector('.finding-badge').textContent;
                const desc = f.querySelector('.finding-desc').textContent;

                doc.setFontSize(11);
                doc.setTextColor(200, 0, 0);
                doc.text(`[${severity}] ${title}`, 15, y);
                doc.setTextColor(0, 0, 0);
                doc.setFontSize(10);
                y += 6;
                doc.text(desc, 15, y, { maxWidth: 170 });
                y += 10;
            });
        }

        doc.save(`${name}_scan_report.pdf`);
    }

    // --- AWS Security Dashboard Logic ---
    async function loadScanReport() {
        try {
            const response = await fetch('scan_report.json');
            if (!response.ok) throw new Error('Report file not found');
            const data = await response.json();
            renderDashboard(data);
        } catch (error) {
            console.log("No report JSON found, prompting user.");
            dashboardNoReport.classList.remove('hidden');
            dashboardContent.classList.add('hidden');
        }
    }

    demoReportBtn.addEventListener('click', () => {
        const demoData = {
            "scan_time": new Date().toISOString(),
            "account_id": "123456789012",
            "risk_score": 48,
            "summary": {
                "total_findings": 5,
                "severity_counts": {
                    "Critical": 1,
                    "High": 1,
                    "Medium": 2,
                    "Low": 1
                }
            },
            "findings": [
                {
                    "service": "IAM",
                    "resource": "Root Account",
                    "id": "iam-root-no-mfa",
                    "severity": "Critical",
                    "title": "MFA Not Enabled on Root Account",
                    "description": "The root user of this AWS account does not have Multi-Factor Authentication (MFA) enabled.",
                    "remediation": "Log in as the root user and configure a virtual or physical MFA device immediately."
                },
                {
                    "service": "EC2",
                    "resource": "Security Group: sg-08df1f885a06 (default)",
                    "id": "ec2-sg-port-22-public",
                    "severity": "High",
                    "title": "Sensitive Port Publicly Accessible: SSH (22)",
                    "description": "Security Group 'sg-08df1f885a06' exposes sensitive port 22 (SSH) to public access (0.0.0.0/0).",
                    "remediation": "Limit traffic on port 22 to authorized office IPs or use AWS Systems Manager Session Manager for remote access."
                },
                {
                    "service": "S3",
                    "resource": "my-logs-bucket-unencrypted",
                    "id": "s3-unencrypted",
                    "severity": "Medium",
                    "title": "Server-Side Encryption Disabled",
                    "description": "Default encryption is not configured for bucket 'my-logs-bucket-unencrypted'. Objects might be stored unencrypted.",
                    "remediation": "Enable S3 default encryption using SSE-S3 (AES-256) or SSE-KMS."
                },
                {
                    "service": "RDS",
                    "resource": "DB Instance: prod-postgres",
                    "id": "rds-backups-disabled",
                    "severity": "Medium",
                    "title": "RDS Backups Disabled",
                    "description": "Automated backups are disabled for the database instance 'prod-postgres' (retention period set to 0).",
                    "remediation": "Configure an automated backup retention period greater than 0 days (e.g. 7 or 30 days) to prevent data loss."
                },
                {
                    "service": "CloudTrail",
                    "resource": "Trail: primary-trail",
                    "id": "cloudtrail-not-multi-region",
                    "severity": "Low",
                    "title": "Trail is Single-Region Only",
                    "description": "The trail 'primary-trail' only logs events in its home region.",
                    "remediation": "Update the trail configuration to be a Multi-Region Trail."
                }
            ]
        };
        renderDashboard(demoData);
    });

    function renderDashboard(report) {
        loadedReport = report;
        dashboardNoReport.classList.add('hidden');
        dashboardContent.classList.remove('hidden');

        // Set Metadata
        dashAccountId.textContent = report.account_id || 'Unknown';
        dashLastAudited.textContent = new Date(report.scan_time).toLocaleString();
        
        let status = 'Secure';
        let color = '#10b981';
        if (report.risk_score > 0) {
            status = 'Warning';
            color = '#f59e0b';
        }
        if (report.risk_score > 69) {
            status = 'Critical';
            color = '#e11d48';
        }
        dashRiskStatus.textContent = status;
        dashRiskStatus.style.color = color;

        // Score Ring
        dashScoreValue.textContent = report.risk_score;
        let riskLevelText = 'Safe';
        let summaryText = 'All audited services configured securely.';
        if (report.risk_score > 0) riskLevelText = 'Low Risk';
        if (report.risk_score > 30) riskLevelText = 'Medium Risk';
        if (report.risk_score > 69) riskLevelText = 'Critical Risk';
        
        if (report.findings.length > 0) {
            summaryText = `Auditor detected ${report.findings.length} configuration vulnerabilities.`;
        }

        dashRiskLevel.textContent = riskLevelText;
        dashRiskLevel.style.color = color;
        dashRiskSummary.textContent = summaryText;

        const circumference = 326.72;
        const offset = circumference - (report.risk_score / 100) * circumference;
        dashScoreRing.style.strokeDashoffset = offset;
        dashScoreRing.style.stroke = color;

        // Metric Counts
        countCritical.textContent = report.summary?.severity_counts?.Critical ?? 0;
        countHigh.textContent = report.summary?.severity_counts?.High ?? 0;
        countMedium.textContent = report.summary?.severity_counts?.Medium ?? 0;
        countLow.textContent = report.summary?.severity_counts?.Low ?? 0;

        // Render Findings List
        renderDashboardFindings();
    }

    function renderDashboardFindings() {
        if (!loadedReport) return;
        dashboardFindingsList.innerHTML = '';

        const filtered = loadedReport.findings.filter(f => {
            if (activeServiceFilter === 'ALL') return true;
            return f.service.toUpperCase() === activeServiceFilter.toUpperCase();
        });

        if (filtered.length === 0) {
            dashboardFindingsList.innerHTML = `
                <div class="no-report-card" style="padding: 2rem;">
                    <i class="fa-solid fa-square-check" style="color: #10b981; font-size: 2.5rem;"></i>
                    <h4>No Findings for ${activeServiceFilter}</h4>
                    <p style="margin-bottom:0;">Everything is configured securely in this category.</p>
                </div>
            `;
            return;
        }

        filtered.forEach(f => {
            const item = document.createElement('div');
            item.className = 'dashboard-finding-item';
            item.innerHTML = `
                <div class="finding-meta">
                    <span class="finding-service-badge"><i class="fa-solid fa-server"></i> ${f.service}</span>
                    <span class="finding-badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                </div>
                <h4 style="margin-bottom: 0.5rem;">${f.title}</h4>
                <div class="finding-resource">Resource: <code>${f.resource}</code></div>
                <p style="color: var(--text-secondary); font-size: 0.95rem; margin-bottom: 0.75rem;">${f.description}</p>
                <div class="finding-remediation-box">
                    <strong><i class="fa-solid fa-wrench"></i> Remediation Action</strong>
                    ${f.remediation}
                </div>
            `;
            dashboardFindingsList.appendChild(item);
        });
    }

    // Set up filter click handlers
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterButtons.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            activeServiceFilter = e.target.dataset.service;
            renderDashboardFindings();
        });
    });
});
