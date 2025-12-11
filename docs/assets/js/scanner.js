/**
 * S3 Misconfiguration Scanner - Passive Client-Side Scanner
 * 
 * This script performs safe, passive checks against S3 buckets.
 * It respects all CORS policies and does not perform destructive actions.
 */

// Regions to attempt to guess
const REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
];

class S3Scanner {
    constructor() {
        this.results = {
            bucketName: '',
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
            // 2. Check Public Listing
            await this.checkPublicListing(bucketName);
            
            // 3. Check Website Endpoint
            await this.checkWebsiteEndpoint(bucketName);
            
            // 4. Check Common Files
            await this.checkCommonFiles(bucketName);
        }

        this.calculateRisk();
        return this.results;
    }

    async checkExistenceAndRegion(bucket) {
        // We use the standard endpoint to start. 
        // Note: fetch() will fail if CORS is not allowed, which is GOOD security.
        // If it succeeds with 200 or returns XML, CORS is open.
        // If it throws detailed NetworkError, we assume it might exist but is secured or CORS blocked.
        // To accurately detect existence without CORS, we'd need an img tag or script tag hack, 
        // but for this tool, we rely on standard fetch to check for *Misconfigurations* (which usually imply open CORS).
        
        const url = `https://${bucket}.s3.amazonaws.com/`;
        try {
            const response = await fetch(url, { method: 'GET' });
            
            this.results.exists = true; // If we got ANY response (even 403), it exists.
            
            // Check headers for region
            const regionHeader = response.headers.get('x-amz-bucket-region');
            if (regionHeader) {
                this.results.region = regionHeader;
            }

            if (response.status === 200) {
                this.results.findings.push({
                    id: 'public-access',
                    title: 'Publicly Accessible Root',
                    severity: 'High',
                    description: 'The bucket root URL returns a 200 OK status. This often implies public access.',
                    remediation: 'Disable public access via S3 Block Public Access settings.'
                });
                this.results.publicAccess = true;
                this.results.corsOpen = true; // If we read it, CORS is open or we are same-origin (unlikely).
            } else if (response.status === 403) {
                 // 403 is good! It means "Access Denied".
                 console.log('Bucket exists but checks out secure (403) on root.' );
            }

        } catch (error) {
            // Network error can mean:
            // 1. Domain doesn't exist (NXDOMAIN)
            // 2. CORS blocked the read (but it might exist)
            // 3. Network issue
            
            // We can try to infer using an image load for existence if fetch failed due to CORS.
            const imgExists = await this.probeImage(url);
            if (imgExists) {
                this.results.exists = true;
                // If we could load an image/favicon, it's public but scan blocked by CORS probably? 
                // Actually an image loading means GET is allowed.
                // But we can't see headers.
            } else {
                 // Try one more common region just in case DNS propagation is weird, but usually standard endpoint handles redirects.
            }
        }
    }

    probeImage(url) {
        return new Promise((resolve) => {
            const img = new Image();
            img.onload = () => resolve(true);
            img.onerror = () => resolve(false); // Could be 403 or 404, hard to tell on images without CORS
            img.src = url + 'favicon.ico'; // Try a common file
        });
    }

    async checkPublicListing(bucket) {
        const url = `https://${bucket}.s3.amazonaws.com/?list-type=2`;
        try {
            const response = await fetch(url);
            if (response.status === 200) {
                const text = await response.text();
                if (text.includes('ListBucketResult')) {
                    this.results.listingEnabled = true;
                    this.results.findings.push({
                        id: 'list-objects',
                        title: 'Public Object Listing Enabled',
                        severity: 'Critical',
                        description: 'Anyone can list all files in your bucket. This leads to data scraping and leakage.',
                        remediation: 'Remove the "s3:ListBucket" permission from the "Everyone" principal in the Bucket Policy.'
                    });
                }
            }
        } catch (e) {
            // CORS blocked or other error
        }
    }

    async checkWebsiteEndpoint(bucket) {
        // Guess commonly used regions if we don't know it
        let regionsToCheck = this.results.region !== 'Unknown' ? [this.results.region] : ['us-east-1', 'us-west-2'];
        
        for (const region of regionsToCheck) {
            const url = `http://${bucket}.s3-website-${region}.amazonaws.com`;
            try {
                // We use 'no-cors' mode just to check if it resolves/connects
                // Note: we can't inspect status in no-cors, but if it doesn't throw, it's "alive" in some sense.
                // However, 's3-website' endpoints usually return 404 HTML if bucket not found, 403 if restricted.
                // This is a weak check client-side.
                
                // Better check: use fetch and see if we get a response. CORS might block it though.
                // Static website endpoints do NOT support HTTPS usually (unless CloudFront).
                // Browsers verify mixed content. If we serve scanning site on HTTPS, we cannot fetch HTTP.
                // If this is hosted on GitHub Pages (HTTPS), we can't easily check HTTP website endpoints.
                
                // Skipping HTTP check if we are on HTTPS to avoid mixed content errors blocking everything.
                if (window.location.protocol === 'https:') {
                    console.warn('Skipping HTTP website check due to Mixed Content restrictions.');
                    break;
                }
            } catch (e) { }
        }
    }
    
    async checkCommonFiles(bucket) {
        const files = ['robots.txt', 'index.html', '.env', 'config.json'];
        for (const file of files) {
            const url = `https://${bucket}.s3.amazonaws.com/${file}`;
            try {
                const response = await fetch(url);
                if (response.status === 200) {
                     this.results.findings.push({
                        id: 'exposed-file-' + file,
                        title: `Exposed File: ${file}`,
                        severity: file === '.env' || file === 'config.json' ? 'Critical' : 'Low',
                        description: `The file '${file}' is publicly readable.`,
                        remediation: 'Ensure only public assets are readable. Review bucket policies.'
                    });
                }
            } catch(e) {}
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
                    cleanBucket = urlObj.hostname.split('.s3')[0];
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
            alert('An error occurred during scanning.');
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
        
        // Hacky way to grab findings from DOM for this simple implementation
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
