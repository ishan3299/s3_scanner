#!/usr/bin/env python3
import boto3
import argparse
import sys
import json
from botocore.exceptions import ClientError

def scan_bucket(bucket_name):
    """
    Scans a single bucket using authenticated credentials (boto3 default chain).
    """
    s3 = boto3.client('s3')
    results = {
        "bucket": bucket_name,
        "region": "unknown",
        "acl": None,
        "policy": None,
        "cors": None,
        "public_access_block": None,
        "website": None,
        "risk_score": 0,
        "findings": []
    }

    print(f"[*] Scanning bucket: {bucket_name}...")

    # 1. Get Location
    try:
        loc = s3.get_bucket_location(Bucket=bucket_name)
        results['region'] = loc['LocationConstraint'] or 'us-east-1'
    except ClientError as e:
        print(f"[-] Error getting location: {e}")
        results['findings'].append(f"Error getting location: {e}")

    # 2. Get ACL
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        results['acl'] = []
        for grant in acl['Grants']:
            permission = grant['Permission']
            grantee = grant['Grantee'].get('URI', grant['Grantee'].get('DisplayName', 'Unknown'))
            results['acl'].append(f"{grantee} -> {permission}")
            
            # Check for public ACL
            if 'AllUsers' in grantee or 'AuthenticatedUsers' in grantee:
                 results['findings'].append(f"Public ACL detected: {grantee} has {permission}")
                 results['risk_score'] += 20
    except ClientError as e:
        print(f"[-] Error getting ACL: {e}")

    # 3. Get Policy
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        results['policy'] = json.loads(policy['Policy'])
        # Simple heuristic check
        pol_str = json.dumps(results['policy'])
        if '"Effect": "Allow"' in pol_str and '"Principal": "*"' in pol_str:
            results['findings'].append("Bucket Policy allows public access based on wildcards (*).")
            results['risk_score'] += 30
    except ClientError as e:
        # Policy might not exist, which raises an error but is fine
        if 'NoSuchBucketPolicy' not in str(e):
             print(f"[-] Error getting Policy: {e}")

    # 4. Get Public Access Block
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        results['public_access_block'] = pab['PublicAccessBlockConfiguration']
    except ClientError as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            results['findings'].append("No Public Access Block configuration found (Bucket might be public).")
            results['risk_score'] += 10
        else:
            print(f"[-] Error getting PAB: {e}")

    # 5. Get CORS
    try:
        cors = s3.get_bucket_cors(Bucket=bucket_name)
        results['cors'] = cors['CORSRules']
        results['findings'].append("CORS configuration exists.")
    except ClientError:
        pass # No CORS is fine usually

    # 6. Get Website
    try:
        website = s3.get_bucket_website(Bucket=bucket_name)
        results['website'] = website
        results['findings'].append(f"Bucket is configured as a website. Index document: {website.get('IndexDocument', {}).get('Suffix')}")
    except ClientError:
        pass

    return results

def main():
    parser = argparse.ArgumentParser(description="Authenticated S3 Bucket Scanner for Owners")
    parser.add_argument("bucket", help="Name of the S3 bucket to scan")
    args = parser.parse_args()

    try:
        report = scan_bucket(args.bucket)
        print("\n" + "="*40)
        print("SCAN REPORT")
        print("="*40)
        print(json.dumps(report, indent=2, default=str))
        
        if report['risk_score'] > 0:
            sys.exit(1) # Fail for CI/CD
        
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
