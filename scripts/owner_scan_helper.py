#!/usr/bin/env python3
import boto3
import argparse
import sys
import json
from botocore.exceptions import ClientError
from typing import Dict, List, Any, Optional

class S3Scanner:
    def __init__(self, bucket_name: str, profile: Optional[str] = None):
        self.bucket_name = bucket_name
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.s3 = self.session.client('s3')
        self.results = {
            "bucket": bucket_name,
            "region": "unknown",
            "risk_score": 0,
            "findings": []
        }

    def add_finding(self, message: str, score_impact: int = 0):
        self.results['findings'].append(message)
        self.results['risk_score'] += score_impact

    def check_location(self):
        try:
            loc = self.s3.get_bucket_location(Bucket=self.bucket_name)
            self.results['region'] = loc['LocationConstraint'] or 'us-east-1'
        except ClientError as e:
            self.add_finding(f"Error getting location: {e}", 0)

    def check_acl(self):
        try:
            acl = self.s3.get_bucket_acl(Bucket=self.bucket_name)
            for grant in acl['Grants']:
                grantee = grant['Grantee'].get('URI', grant['Grantee'].get('DisplayName', 'Unknown'))
                permission = grant['Permission']
                
                if 'AllUsers' in grantee or 'AuthenticatedUsers' in grantee:
                     self.add_finding(f"Public ACL detected: {grantee} has {permission}", 20)
        except ClientError as e:
            self.add_finding(f"Error getting ACL: {e}")

    def check_policy(self):
        try:
            policy_resp = self.s3.get_bucket_policy(Bucket=self.bucket_name)
            policy = json.loads(policy_resp['Policy'])
            
            # Simple heuristic check for public wildcards
            pol_str = json.dumps(policy)
            if '"Effect": "Allow"' in pol_str and '"Principal": "*"' in pol_str:
                self.add_finding("Bucket Policy allows public access based on wildcards (*).", 30)
                
        except ClientError as e:
            if 'NoSuchBucketPolicy' not in str(e):
                 self.add_finding(f"Error getting Policy: {e}")

    def check_public_access_block(self):
        try:
            pab = self.s3.get_public_access_block(Bucket=self.bucket_name)
            # Just having it is good, strictly speaking we should check values
            conf = pab['PublicAccessBlockConfiguration']
            if not (conf['BlockPublicAcls'] and conf['IgnorePublicAcls'] and conf['BlockPublicPolicy'] and conf['RestrictPublicBuckets']):
                self.add_finding("Public Access Block is not fully enabled.", 5)
                
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                self.add_finding("No Public Access Block configuration found (High Risk).", 10)
            else:
                self.add_finding(f"Error getting PAB: {e}")

    def scan(self) -> Dict[str, Any]:
        print(f"[*] Scanning bucket: {self.bucket_name}...")
        self.check_location()
        self.check_acl()
        self.check_policy()
        self.check_public_access_block()
        return self.results

def main():
    parser = argparse.ArgumentParser(description="Authenticated S3 Bucket Scanner for Owners")
    parser.add_argument("bucket", help="Name of the S3 bucket to scan")
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    parser.add_argument("--json", action="store_true", help="Output only JSON")
    args = parser.parse_args()

    try:
        scanner = S3Scanner(args.bucket, args.profile)
        report = scanner.scan()
        
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print("\n" + "="*40)
            print(f"SCAN REPORT FOR: {report['bucket']}")
            print("="*40)
            print(f"Region: {report['region']}")
            print(f"Risk Score: {report['risk_score']}")
            print("Findings:")
            if not report['findings']:
                print("  - No issues found.")
            for f in report['findings']:
                print(f"  - {f}")
            print("="*40)
        
        if report['risk_score'] > 0:
            sys.exit(1) # Fail for CI/CD
        
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
