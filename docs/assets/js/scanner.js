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
            publicAccess: false,
            listingEnabled: false,
            websiteEnabled: false,
            corsOpen: false,
            findings: [],
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
                this.checkCommonFiles(bucketName)
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

    async checkExistenceAndRegion(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/`;
        try {
            const response = await this.fetchWithTimeout(url, { method: 'GET' });

            this.results.exists = true;

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
            // If CORS fails or timeout, we try an image probe to confirm existence
            const imgExists = await this.probeImage(url);
            if (imgExists) {
                this.results.exists = true;
            }
        }
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
        try {
            const response = await this.fetchWithTimeout(url);
            if (response.status === 200) {
                const text = await response.text();
                if (text.includes('ListBucketResult')) {
                    this.results.listingEnabled = true;
                    this.addFinding({
                        id: 'list-objects',
                        title: 'Public Object Listing Enabled',
                        severity: 'Critical',
                        description: 'Anyone can list all files in your bucket. This leads to data scraping and leakage.',
                        remediation: 'Remove the "s3:ListBucket" permission from the "Everyone" principal in the Bucket Policy.'
                    });
                }
            }
        } catch (e) { }
    }

    async checkWebsiteEndpoint(bucket) {
        if (window.location.protocol === 'https:') {
            console.warn('Skipping HTTP website check due to Mixed Content restrictions.');
            return;
        }

        let regionsToCheck = this.results.region !== 'Unknown' ? [this.results.region] : ['us-east-1', 'us-west-2', 'eu-west-1'];

        for (const region of regionsToCheck) {
            const url = `http://${bucket}.s3-website-${region}.amazonaws.com`;
            try {
                // Just a probe
                await this.fetchWithTimeout(url, { mode: 'no-cors' });
                // If no error, implicit success (though hard to prove 100% without proxy)
            } catch (e) { }
        }
    }

    async checkCommonFiles(bucket) {
        const files = ['robots.txt', 'index.html', '.env', 'config.json', '.git/HEAD', 'backup.zip', '.DS_Store'];

        const checks = files.map(async (file) => {
            const url = `https://${bucket}.s3.amazonaws.com/${file}`;
            try {
                const response = await this.fetchWithTimeout(url, { method: 'HEAD' }); // Use HEAD first
                if (response.status === 200) {
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
    const scanBtn = document.getElementById('scanBtn');
    const bucketInput = document.getElementById('bucketInput');
    const resultsSection = document.getElementById('resultsSection');
    const spinner = document.querySelector('.spinner');
    const btnText = document.querySelector('.btn-text');
    const exportBtn = document.getElementById('exportBtn');

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
                // Handle subdomains like bucket.s3.amazonaws.com
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

        // Animate Ring (approximate)
        const circle = document.getElementById('scoreRing');
        const circumference = 326.72;
        const offset = circumference - (results.score / 100) * circumference;
        circle.style.strokeDashoffset = offset;

        // Color
        let color = '#10b981'; // green
        if (results.score > 29) color = '#f59e0b'; // orange
        if (results.score > 69) color = '#e11d48'; // red
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

                // Add Remediation
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
});
