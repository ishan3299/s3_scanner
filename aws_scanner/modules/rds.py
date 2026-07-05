from botocore.exceptions import ClientError
from typing import Dict, List, Any

class RDSAuditor:
    def __init__(self, session):
        self.rds = session.client('rds')

    def audit(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            for db in instances:
                db_id = db.get('DBInstanceIdentifier', '')
                is_public = db.get('PubliclyAccessible', False)
                encrypted = db.get('StorageEncrypted', False)
                backup_retention = db.get('BackupRetentionPeriod', 0)
                
                # 1. Public accessibility
                if is_public:
                    findings.append({
                        "service": "RDS",
                        "resource": f"DB Instance: {db_id}",
                        "id": "rds-publicly-accessible",
                        "severity": "Critical",
                        "title": "RDS Database Publicly Accessible",
                        "description": f"The database instance '{db_id}' is configured with public accessibility enabled.",
                        "remediation": "Modify the database instance settings to disable Publicly Accessible status, ensuring it only has private/internal subnet access."
                    })
                
                # 2. Storage Encryption
                if not encrypted:
                    findings.append({
                        "service": "RDS",
                        "resource": f"DB Instance: {db_id}",
                        "id": "rds-unencrypted",
                        "severity": "High",
                        "title": "RDS Storage Encryption Disabled",
                        "description": f"The database instance '{db_id}' does not have storage encryption enabled at rest.",
                        "remediation": "Enable storage encryption. For existing databases, create a snapshot, copy the snapshot with encryption enabled, and restore a new database instance from the encrypted snapshot."
                    })
                
                # 3. Backup Retention
                if backup_retention == 0:
                    findings.append({
                        "service": "RDS",
                        "resource": f"DB Instance: {db_id}",
                        "id": "rds-backups-disabled",
                        "severity": "Medium",
                        "title": "RDS Backups Disabled",
                        "description": f"Automated backups are disabled for the database instance '{db_id}' (retention period set to 0).",
                        "remediation": "Configure an automated backup retention period greater than 0 days (e.g. 7 or 30 days) to prevent data loss."
                    })
        except ClientError as e:
            findings.append({
                "service": "RDS",
                "resource": "DB Instances",
                "id": "rds-list-error",
                "severity": "Low",
                "title": "Failed to List RDS Instances",
                "description": str(e),
                "remediation": "Ensure IAM role has rds:DescribeDBInstances permission."
            })
        return findings
