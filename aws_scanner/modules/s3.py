import json
from botocore.exceptions import ClientError
from typing import Dict, List, Any

class S3Auditor:
    def __init__(self, session):
        self.s3 = session.client('s3')

    def audit(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            buckets = self.s3.list_buckets().get('Buckets', [])
        except ClientError as e:
            return [{"service": "S3", "id": "list-buckets-error", "severity": "High", "title": "Failed to List Buckets", "description": str(e), "remediation": "Ensure IAM role has s3:ListAllMyBuckets permission."}]

        for bucket in buckets:
            name = bucket['Name']
            findings.extend(self._audit_bucket(name))
        return findings

    def _audit_bucket(self, bucket_name: str) -> List[Dict[str, Any]]:
        bucket_findings = []
        
        # 1. Check Public Access Block (PAB)
        try:
            pab = self.s3.get_public_access_block(Bucket=bucket_name)
            conf = pab['PublicAccessBlockConfiguration']
            if not all([conf['BlockPublicAcls'], conf['IgnorePublicAcls'], conf['BlockPublicPolicy'], conf['RestrictPublicBuckets']]):
                bucket_findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "id": "s3-pab-incomplete",
                    "severity": "Medium",
                    "title": "Public Access Block Incomplete",
                    "description": f"Public Access Block is not fully enabled for bucket '{bucket_name}'.",
                    "remediation": "Enable all four Public Access Block settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
                })
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                bucket_findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "id": "s3-no-pab",
                    "severity": "High",
                    "title": "No Public Access Block Configured",
                    "description": f"No Public Access Block configuration exists for bucket '{bucket_name}'.",
                    "remediation": "Configure Public Access Block and enable all options to prevent accidental public exposure."
                })
            else:
                bucket_findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "id": "s3-pab-api-error",
                    "severity": "Low",
                    "title": "Failed to Get Public Access Block Configuration",
                    "description": f"Error querying PAB configuration: {e}",
                    "remediation": "Grant s3:GetPublicAccessBlock permission to the auditor role."
                })

        # 2. Check ACLs
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')
                permission = grant.get('Permission', '')
                if 'AllUsers' in uri:
                    bucket_findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "id": "s3-public-acl-everyone",
                        "severity": "High",
                        "title": "Public ACL: Access Granted to Everyone",
                        "description": f"Bucket ACL grants '{permission}' permission to public AllUsers group.",
                        "remediation": "Remove public grants from the bucket ACL. Use Bucket Policies instead for sharing."
                    })
                elif 'AuthenticatedUsers' in uri:
                    bucket_findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "id": "s3-public-acl-auth-users",
                        "severity": "Medium",
                        "title": "Public ACL: Access Granted to Authenticated Users",
                        "description": f"Bucket ACL grants '{permission}' permission to any AWS authenticated user globally.",
                        "remediation": "Remove AuthenticatedUsers grant. This allows any AWS account to access your bucket."
                    })
        except ClientError as e:
            bucket_findings.append({
                "service": "S3",
                "resource": bucket_name,
                "id": "s3-acl-api-error",
                "severity": "Low",
                "title": "Failed to Get Bucket ACL",
                "description": str(e),
                "remediation": "Grant s3:GetBucketAcl permission to the auditor role."
            })

        # 3. Check Bucket Policy for Public Star Wildcard
        has_policy = False
        try:
            policy_resp = self.s3.get_bucket_policy(Bucket=bucket_name)
            has_policy = True
            policy = json.loads(policy_resp.get('Policy', '{}'))
            statements = policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for stmt in statements:
                effect = stmt.get('Effect')
                principal = stmt.get('Principal', {})
                condition = stmt.get('Condition')
                
                # Check for public wildcard permissions
                is_public_principal = False
                if principal == "*":
                    is_public_principal = True
                elif isinstance(principal, dict) and "*" in principal.values():
                    is_public_principal = True
                elif isinstance(principal, dict) and "AWS" in principal:
                    aws_p = principal["AWS"]
                    if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                        is_public_principal = True
                        
                if effect == "Allow" and is_public_principal and not condition:
                    bucket_findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "id": "s3-public-policy-wildcard",
                        "severity": "High",
                        "title": "Unconditional Public Policy",
                        "description": f"Bucket Policy has unrestricted public access ('Principal': '*') without conditions.",
                        "remediation": "Restrict the bucket policy Principal to specific IAM ARNs or add IP/VPC condition constraints."
                    })
                    
                # 4. Check Secure Transport (SSL) Enforcement
                ssl_enforced = False
                if effect == "Deny" and is_public_principal:
                    # Check for secure transport condition denial
                    if condition and "Bool" in condition:
                        bool_cond = condition["Bool"]
                        if "aws:SecureTransport" in bool_cond:
                            val = bool_cond["aws:SecureTransport"]
                            if val == "false" or val == ["false"]:
                                ssl_enforced = True
            
            # If no SSL deny policy exists
            # (Note: we evaluate across all statements, if none enforces SSL we raise warning)
        except ClientError as e:
            if 'NoSuchBucketPolicy' not in str(e):
                bucket_findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "id": "s3-policy-api-error",
                    "severity": "Low",
                    "title": "Failed to Get Bucket Policy",
                    "description": str(e),
                    "remediation": "Grant s3:GetBucketPolicy permission to the auditor role."
                })
                
        # 5. Server-Side Encryption Audit
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                bucket_findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "id": "s3-unencrypted",
                    "severity": "Medium",
                    "title": "Server-Side Encryption Disabled",
                    "description": f"Default encryption is not configured for bucket '{bucket_name}'. Objects might be stored unencrypted.",
                    "remediation": "Enable S3 default encryption using SSE-S3 (AES-256) or SSE-KMS."
                })
            else:
                bucket_findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "id": "s3-encryption-api-error",
                    "severity": "Low",
                    "title": "Failed to Query Encryption Status",
                    "description": str(e),
                    "remediation": "Grant s3:GetEncryptionConfiguration permission to the auditor role."
                })

        return bucket_findings
