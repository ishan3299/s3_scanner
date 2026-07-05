from botocore.exceptions import ClientError
from typing import Dict, List, Any

class EC2Auditor:
    def __init__(self, session):
        # EC2 requires checking regions, but we start with the session default region first.
        self.ec2 = session.client('ec2')

    def audit(self) -> List[Dict[str, Any]]:
        findings = []
        
        # SGs, EBS and VPC audits
        findings.extend(self._audit_security_groups())
        findings.extend(self._audit_ebs_volumes())
        findings.extend(self._audit_vpc_flow_logs())
        
        return findings

    def _audit_security_groups(self) -> List[Dict[str, Any]]:
        sg_findings = []
        sensitive_ports = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            1521: "Oracle DB",
            27017: "MongoDB"
        }

        try:
            sgs = self.ec2.describe_security_groups().get('SecurityGroups', [])
            for sg in sgs:
                sg_name = sg.get('GroupName', '')
                sg_id = sg.get('GroupId', '')
                vpc_id = sg.get('VpcId', '')
                
                # Iterate through ingress permissions
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    ip_protocol = rule.get('IpProtocol')
                    
                    # Unrestricted range
                    is_unrestricted = False
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            is_unrestricted = True
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            is_unrestricted = True
                            
                    if is_unrestricted:
                        # Protocol -1 is all protocols
                        if ip_protocol == '-1':
                            sg_findings.append({
                                "service": "EC2",
                                "resource": f"Security Group: {sg_id} ({sg_name})",
                                "id": "ec2-sg-all-ports-public",
                                "severity": "High",
                                "title": "Security Group Allows All Public Inbound Traffic",
                                "description": f"Security Group '{sg_id}' allows unrestricted inbound traffic for all protocols and ports from public sources.",
                                "remediation": "Restrict security group inbound rules to specific source IP ranges or security group references."
                            })
                        else:
                            # Individual ports
                            ports_checked = []
                            if from_port is not None and to_port is not None:
                                ports_checked = list(range(from_port, to_port + 1))
                            
                            for p in ports_checked:
                                if p in sensitive_ports:
                                    port_name = sensitive_ports[p]
                                    sg_findings.append({
                                        "service": "EC2",
                                        "resource": f"Security Group: {sg_id} ({sg_name})",
                                        "id": f"ec2-sg-port-{p}-public",
                                        "severity": "High" if p in [22, 3389] else "Medium",
                                        "title": f"Sensitive Port Publicly Accessible: {port_name} ({p})",
                                        "description": f"Security Group '{sg_id}' exposes sensitive port {p} ({port_name}) to public access.",
                                        "remediation": f"Limit traffic on port {p} to authorized office IPs or use AWS Systems Manager Session Manager for remote access."
                                    })
        except ClientError as e:
            sg_findings.append({
                "service": "EC2",
                "resource": "Security Groups",
                "id": "ec2-sg-list-error",
                "severity": "Low",
                "title": "Failed to List Security Groups",
                "description": str(e),
                "remediation": "Ensure IAM role has ec2:DescribeSecurityGroups permission."
            })
            
        return sg_findings

    def _audit_ebs_volumes(self) -> List[Dict[str, Any]]:
        ebs_findings = []
        try:
            volumes = self.ec2.describe_volumes().get('Volumes', [])
            for vol in volumes:
                vol_id = vol.get('VolumeId', '')
                encrypted = vol.get('Encrypted', False)
                state = vol.get('State', '')
                
                if state == 'in-use' and not encrypted:
                    ebs_findings.append({
                        "service": "EC2",
                        "resource": f"EBS Volume: {vol_id}",
                        "id": "ec2-ebs-unencrypted",
                        "severity": "Medium",
                        "title": "Active EBS Volume Unencrypted",
                        "description": f"The EBS volume '{vol_id}' currently in-use is not encrypted at rest.",
                        "remediation": "Enable EBS encryption by default in the account settings, or snapshot the volume, copy the snapshot with encryption enabled, and replace the volume."
                    })
        except ClientError as e:
            ebs_findings.append({
                "service": "EC2",
                "resource": "EBS Volumes",
                "id": "ec2-ebs-list-error",
                "severity": "Low",
                "title": "Failed to List EBS Volumes",
                "description": str(e),
                "remediation": "Ensure IAM role has ec2:DescribeVolumes permission."
            })
        return ebs_findings

    def _audit_vpc_flow_logs(self) -> List[Dict[str, Any]]:
        vpc_findings = []
        try:
            vpcs = self.ec2.describe_vpcs().get('Vpcs', [])
            flow_logs = self.ec2.describe_flow_logs().get('FlowLogs', [])
            
            # Map of VPC IDs that have at least one active flow log
            vpcs_with_logs = set()
            for fl in flow_logs:
                resource_id = fl.get('ResourceId', '')
                deliver_status = fl.get('DeliverLogsStatus', '')
                if resource_id.startswith('vpc-') and fl.get('FlowLogStatus') == 'ACTIVE':
                    vpcs_with_logs.add(resource_id)
            
            for vpc in vpcs:
                vpc_id = vpc.get('VpcId', '')
                is_default = vpc.get('IsDefault', False)
                
                if vpc_id not in vpcs_with_logs:
                    vpc_findings.append({
                        "service": "EC2",
                        "resource": f"VPC: {vpc_id}",
                        "id": "ec2-vpc-flow-logs-disabled",
                        "severity": "Low" if is_default else "Medium",
                        "title": "VPC Flow Logs Disabled",
                        "description": f"VPC Flow Logs are not enabled for VPC '{vpc_id}'. Network traffic audits cannot be collected.",
                        "remediation": "Create a new VPC Flow Log for the VPC directing traffic logs to Amazon CloudWatch Logs or S3."
                    })
        except ClientError as e:
            vpc_findings.append({
                "service": "EC2",
                "resource": "VPCs",
                "id": "ec2-vpc-list-error",
                "severity": "Low",
                "title": "Failed to List VPCs / Flow Logs",
                "description": str(e),
                "remediation": "Ensure IAM role has ec2:DescribeVpcs and ec2:DescribeFlowLogs permissions."
            })
        return vpc_findings
