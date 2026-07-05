#!/usr/bin/env python3
import argparse
import json
import sys
import os
import webbrowser
from datetime import datetime, timezone
import boto3

from aws_scanner.modules.s3 import S3Auditor
from aws_scanner.modules.iam import IAMAuditor
from aws_scanner.modules.ec2 import EC2Auditor
from aws_scanner.modules.rds import RDSAuditor
from aws_scanner.modules.cloudtrail import CloudTrailAuditor

def calculate_risk(findings) -> int:
    score = 0
    for f in findings:
        severity = f.get('severity', 'Low')
        if severity == 'Critical':
            score += 25
        elif severity == 'High':
            score += 15
        elif severity == 'Medium':
            score += 8
        elif severity == 'Low':
            score += 2
    return min(score, 100)

def main():
    parser = argparse.ArgumentParser(description="All-in-One AWS Vulnerability Scanner")
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    parser.add_argument("--region", help="Default AWS region to target", default="us-east-1")
    parser.add_argument("--output", help="Path to write JSON output", default="docs/scan_report.json")
    args = parser.parse_args()

    print("[*] Initializing AWS Vulnerability Scanner...")
    
    # Check if valid AWS credentials can be automatically loaded
    try:
        temp_session = boto3.Session(profile_name=args.profile, region_name=args.region)
        # Force a call to verify credentials
        temp_session.client('sts').get_caller_identity()
        session = temp_session
        print("[+] AWS Credentials loaded successfully from environment/profile.")
    except Exception:
        print("[-] No valid AWS credentials found in environment or default CLI profile.")
        print("[*] Please configure credentials below to run the scan locally:")
        access_key = input("    AWS Access Key ID: ").strip()
        if not access_key:
            print("[-] No keys provided. Exiting.")
            sys.exit(1)
        secret_key = input("    AWS Secret Access Key: ").strip()
        region = input("    AWS Region [us-east-1]: ").strip() or "us-east-1"
        session_token = input("    AWS Session Token (Optional - press Enter to skip): ").strip()
        
        try:
            if session_token:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token,
                    region_name=region
                )
            else:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
            # Verify credentials immediately
            session.client('sts').get_caller_identity()
            print("[+] AWS Credentials validated successfully.")
        except Exception as e:
            print(f"[-] Invalid AWS credentials: {e}", file=sys.stderr)
            sys.exit(1)

    # Instantiate auditors
    auditors = {
        "S3": S3Auditor(session),
        "IAM": IAMAuditor(session),
        "EC2": EC2Auditor(session),
        "RDS": RDSAuditor(session),
        "CloudTrail": CloudTrailAuditor(session)
    }

    all_findings = []

    for name, auditor in auditors.items():
        print(f"[*] Scanning service: {name}...")
        try:
            findings = auditor.audit()
            print(f"    -> Found {len(findings)} issues.")
            all_findings.extend(findings)
        except Exception as e:
            print(f"[-] Error scanning {name}: {e}", file=sys.stderr)
            all_findings.append({
                "service": name,
                "id": f"{name.lower()}-global-scan-error",
                "severity": "High",
                "title": f"Failed to Audit {name}",
                "description": str(e),
                "remediation": "Check IAM permissions and network connectivity."
            })

    # Prepare report metadata
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev = f.get('severity', 'Low')
        if sev in severity_counts:
            severity_counts[sev] += 1

    risk_score = calculate_risk(all_findings)
    
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "account_id": "unknown",
        "risk_score": risk_score,
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts
        },
        "findings": all_findings
    }

    # Resolve account ID
    try:
        sts = session.client('sts')
        report['account_id'] = sts.get_caller_identity().get('Account', 'unknown')
    except Exception:
        pass

    # Save JSON report
    try:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Scan report written to {args.output}")
    except Exception as e:
        print(f"[-] Failed to write scan report file: {e}", file=sys.stderr)

    # Save as JS file for local CORS-free HTML loading (essential for offline file://)
    js_output_path = os.path.join(os.path.dirname(args.output), "assets", "js", "report_data.js")
    try:
        os.makedirs(os.path.dirname(js_output_path), exist_ok=True)
        with open(js_output_path, 'w') as f:
            f.write(f"window.AWS_SCAN_REPORT = {json.dumps(report, indent=2, default=str)};")
        print(f"[+] Local offline report data saved to {js_output_path}")
    except Exception as e:
        print(f"[-] Failed to write JS report data: {e}", file=sys.stderr)

    # Console Summary Output
    print("\n" + "="*50)
    print("AWS SECURITY SCAN SUMMARY")
    print("="*50)
    print(f"Account ID: {report['account_id']}")
    print(f"Risk Score: {risk_score}/100")
    print(f"Total Findings: {len(all_findings)}")
    print(f"  - Critical: {severity_counts['Critical']}")
    print(f"  - High:     {severity_counts['High']}")
    print(f"  - Medium:   {severity_counts['Medium']}")
    print(f"  - Low:      {severity_counts['Low']}")
    print("="*50)

    # Automatically open local HTML report in default browser
    html_report_path = os.path.abspath(os.path.join(os.path.dirname(args.output), "index.html"))
    if os.path.exists(html_report_path):
        print(f"[*] Opening local dashboard: file://{html_report_path}")
        webbrowser.open(f"file://{html_report_path}")

    # Exit code
    if severity_counts['Critical'] > 0 or severity_counts['High'] > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
