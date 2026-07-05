#!/usr/bin/env python3
import argparse
import json
import sys
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
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        print(f"[-] Error initializing AWS session: {e}", file=sys.stderr)
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
        "account_id": "unknown",  # We will resolve this below
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

    # Save to file
    try:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Scan report written to {args.output}")
    except Exception as e:
        print(f"[-] Failed to write scan report file: {e}", file=sys.stderr)

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

    # Exit with code 1 if critical or high findings exist to flag builds
    if severity_counts['Critical'] > 0 or severity_counts['High'] > 0:
        print("[-] Security check failed: Critical or High findings detected.", file=sys.stderr)
        sys.exit(1)
    
    print("[+] Security check passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
