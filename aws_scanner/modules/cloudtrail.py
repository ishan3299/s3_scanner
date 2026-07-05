from botocore.exceptions import ClientError
from typing import Dict, List, Any

class CloudTrailAuditor:
    def __init__(self, session):
        self.cloudtrail = session.client('cloudtrail')

    def audit(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            trails = self.cloudtrail.describe_trails().get('trailList', [])
            if not trails:
                findings.append({
                    "service": "CloudTrail",
                    "resource": "Trails",
                    "id": "cloudtrail-no-trails",
                    "severity": "High",
                    "title": "No CloudTrail Configured",
                    "description": "No CloudTrails are configured in this region, which means user and API activity logging is disabled.",
                    "remediation": "Create a multi-region organizational CloudTrail to capture audit events across the entire AWS account."
                })
                return findings

            for trail in trails:
                trail_name = trail.get('Name', '')
                trail_arn = trail.get('TrailARN', '')
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                validation_enabled = trail.get('LogFileValidationEnabled', False)
                
                # Check status (if active/logging)
                try:
                    status = self.cloudtrail.get_trail_status(Name=trail_arn)
                    is_logging = status.get('IsLogging', False)
                    if not is_logging:
                        findings.append({
                            "service": "CloudTrail",
                            "resource": f"Trail: {trail_name}",
                            "id": "cloudtrail-disabled",
                            "severity": "High",
                            "title": "CloudTrail Logging Disabled",
                            "description": f"The trail '{trail_name}' is configured but logging is currently stopped/inactive.",
                            "remediation": "Enable logging for the CloudTrail immediately."
                        })
                except ClientError as e:
                    pass
                
                # Check log file validation
                if not validation_enabled:
                    findings.append({
                        "service": "CloudTrail",
                        "resource": f"Trail: {trail_name}",
                        "id": "cloudtrail-validation-disabled",
                        "severity": "Medium",
                        "title": "Log File Validation Disabled",
                        "description": f"Log file validation is disabled for trail '{trail_name}'. Attackers could alter logged events undetected.",
                        "remediation": "Enable log file validation on the trail settings to enforce log integrity validation."
                    })
                    
                # Check multi-region
                if not is_multi_region:
                    findings.append({
                        "service": "CloudTrail",
                        "resource": f"Trail: {trail_name}",
                        "id": "cloudtrail-not-multi-region",
                        "severity": "Low",
                        "title": "Trail is Single-Region Only",
                        "description": f"The trail '{trail_name}' only logs events in its home region.",
                        "remediation": "Update the trail configuration to be a Multi-Region Trail."
                    })
        except ClientError as e:
            findings.append({
                "service": "CloudTrail",
                "resource": "Trails",
                "id": "cloudtrail-list-error",
                "severity": "Low",
                "title": "Failed to List CloudTrails",
                "description": str(e),
                "remediation": "Ensure IAM role has cloudtrail:DescribeTrails and cloudtrail:GetTrailStatus permissions."
            })
        return findings
