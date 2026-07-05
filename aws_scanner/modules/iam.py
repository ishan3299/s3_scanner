from botocore.exceptions import ClientError
from datetime import datetime, timezone
from typing import Dict, List, Any

class IAMAuditor:
    def __init__(self, session):
        self.iam = session.client('iam')

    def audit(self) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Audit Account Summary (Root MFA, Password Policy)
        try:
            summary = self.iam.get_account_summary().get('SummaryMap', {})
            # Check Root MFA (AccountMFAEnabled key)
            if summary.get('AccountMFAEnabled', 0) == 0:
                findings.append({
                    "service": "IAM",
                    "resource": "Root Account",
                    "id": "iam-root-no-mfa",
                    "severity": "Critical",
                    "title": "MFA Not Enabled on Root Account",
                    "description": "The root user of this AWS account does not have Multi-Factor Authentication (MFA) enabled.",
                    "remediation": "Log in as the root user and configure a virtual or physical MFA device immediately."
                })
        except ClientError as e:
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "id": "iam-summary-error",
                "severity": "Low",
                "title": "Failed to Get IAM Account Summary",
                "description": str(e),
                "remediation": "Ensure IAM role has iam:GetAccountSummary permission."
            })

        # 2. Audit Password Policy
        try:
            policy = self.iam.get_account_password_policy().get('PasswordPolicy', {})
            min_len = policy.get('MinimumPasswordLength', 0)
            if min_len < 14:
                findings.append({
                    "service": "IAM",
                    "resource": "Password Policy",
                    "id": "iam-password-policy-weak",
                    "severity": "Medium",
                    "title": "Weak IAM Password Policy",
                    "description": f"The minimum password length is set to {min_len} (recommended is at least 14 characters).",
                    "remediation": "Update the IAM password policy to require a minimum length of 14 characters and enable complex characters."
                })
        except ClientError as e:
            if 'NoSuchEntity' in str(e):
                findings.append({
                    "service": "IAM",
                    "resource": "Password Policy",
                    "id": "iam-password-policy-missing",
                    "severity": "Medium",
                    "title": "No IAM Password Policy Configured",
                    "description": "No custom IAM password policy is defined for the AWS account. Default S3 settings may apply.",
                    "remediation": "Create a strong IAM password policy requiring uppercase, lowercase, numbers, non-alphanumeric, and rotation."
                })

        # 3. Audit IAM Users (MFA, Access Keys, Policies)
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                findings.extend(self._audit_user(username))
        except ClientError as e:
            findings.append({
                "service": "IAM",
                "resource": "Users",
                "id": "iam-list-users-error",
                "severity": "High",
                "title": "Failed to List IAM Users",
                "description": str(e),
                "remediation": "Ensure IAM role has iam:ListUsers permission."
            })

        return findings

    def _audit_user(self, username: str) -> List[Dict[str, Any]]:
        user_findings = []
        now = datetime.now(timezone.utc)

        # A. Check user MFA (only relevant if they have a login profile / console password)
        has_console_access = False
        try:
            self.iam.get_login_profile(UserName=username)
            has_console_access = True
        except ClientError as e:
            if 'NoSuchEntity' not in str(e):
                # Ignore NoSuchEntity (means user has no console password)
                pass

        if has_console_access:
            try:
                mfa_devices = self.iam.list_mfa_devices(UserName=username).get('MFADevices', [])
                if not mfa_devices:
                    user_findings.append({
                        "service": "IAM",
                        "resource": f"User: {username}",
                        "id": "iam-user-no-mfa",
                        "severity": "High",
                        "title": "IAM User Console Access Without MFA",
                        "description": f"User '{username}' has console login credentials but no Multi-Factor Authentication (MFA) device enabled.",
                        "remediation": "Enforce MFA for user login via policy or ask user to register an MFA device."
                    })
            except ClientError as e:
                pass

        # B. Check Access Keys Age
        try:
            keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            for key in keys:
                status = key['Status']
                key_id = key['AccessKeyId']
                created_date = key['CreateDate']
                
                if status == 'Active':
                    age_days = (now - created_date).days
                    if age_days > 90:
                        user_findings.append({
                            "service": "IAM",
                            "resource": f"User: {username} (Key: {key_id})",
                            "id": "iam-key-old",
                            "severity": "Medium",
                            "title": "Outdated AWS Access Key",
                            "description": f"Access key '{key_id}' for user '{username}' was created {age_days} days ago (recommended rotation is 90 days).",
                            "remediation": "Deactivate, delete, and rotate the access key."
                        })
        except ClientError as e:
            pass

        # C. Check directly attached policies (instead of using group permissions)
        try:
            policies = self.iam.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
            for pol in policies:
                pol_name = pol['PolicyName']
                pol_arn = pol['PolicyArn']
                
                # Flag AdminAccess
                if pol_name == 'AdministratorAccess':
                    user_findings.append({
                        "service": "IAM",
                        "resource": f"User: {username}",
                        "id": "iam-direct-admin",
                        "severity": "High",
                        "title": "Direct Administrator Privileges",
                        "description": f"User '{username}' has full AdministratorAccess attached directly.",
                        "remediation": "Remove direct policy assignments. Map the user to an IAM Group (e.g. Administrators) instead."
                    })
                else:
                    user_findings.append({
                        "service": "IAM",
                        "resource": f"User: {username}",
                        "id": "iam-direct-policy",
                        "severity": "Low",
                        "title": "Direct Policy Attached to User",
                        "description": f"User '{username}' has the policy '{pol_name}' attached directly (violates group principal alignment).",
                        "remediation": "Move policies from user to group level. Assign group memberships to users."
                    })
        except ClientError as e:
            pass

        return user_findings
