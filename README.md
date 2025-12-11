# S3 Misconfiguration Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

A safe, client-side S3 bucket misconfiguration scanner designed to help security professionals and bucket owners detect vulnerabilities such as public listing, open CORS, and website exposure.

[**Launch Scanner**](https://ishan3299.github.io/s3_scanner/)

## Features

- **Client-Side Only**: Runs entirely in your browser. No data is sent to any backend server.
- **Passive Scanning**: Performs safe, non-destructive checks (GET/HEAD requests only).
- **Risk Scoring**: Calculates a risk score based on detected misconfigurations.
- **Remediation Advice**: Provides actionable steps to fix detected issues.
- **Authenticated Mode**: Includes Python scripts for bucket owners to perform deep scans using their own credentials.

## Usage

### Public Passive Scan (Browser)
1. Go to the [deployed scanner](https://ishan3299.github.io/s3_scanner/).
2. Enter the Bucket Name or S3 URL.
3. Click **Scan Bucket**.
4. Review the findings and download the PDF report.

### Authenticated Deep Scan (CLI)
For bucket owners who want to check permissions (ACLs, Policies) that are not visible publicly:

1. Clone the repository.
   ```bash
   git clone https://github.com/ishan3299/s3_scanner.git
   cd s3_scanner
   ```
2. Install dependencies.
   ```bash
   pip install -r scripts/requirements.txt
   ```
3. Configure AWS credentials (`aws configure` or env vars).
4. Run the helper script:
   ```bash
   python scripts/owner_scan_helper.py my-bucket-name
   # Or with a specific profile
   python scripts/owner_scan_helper.py my-bucket-name --profile my-aws-profile
   # JSON output for CI/CD
   python scripts/owner_scan_helper.py my-bucket-name --json
   ```

### GitHub Actions Integration
You can run the authenticated scan automatically in your CI/CD pipeline using the provided template.
Copy `templates/github-actions-owner-scan.yml.template` to `.github/workflows/s3-scan.yml` and configure the secrets.

## Community & Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

-   **Code of Conduct**: Please review our [Code of Conduct](CODE_OF_CONDUCT.md).
-   **Security**: For security issues, please refer to our [Security Policy](SECURITY.md).
-   **Issues**: Found a bug or have a suggestion? Open an issue using our [templates](.github/ISSUE_TEMPLATE/).

## Disclaimer

**For Educational and Authorized Use Only.**
Do not use this tool to scan buckets you do not own or have checks authorized for. Scanning unauthorized targets may violate the AWS Acceptable Use Policy and local laws. Use responsibly.

## License

MIT License. See [LICENSE](LICENSE) for details.
