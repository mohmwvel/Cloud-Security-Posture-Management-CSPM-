import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from .base_scanner import BaseScanner

class SGScanner(BaseScanner):
    def scan(self):
        self.logger.info("Starting Security Group scan")
        sensitive_ports = {22: 'SSH', 3389: 'RDP'}
        
        try:
            ec2 = boto3.client('ec2')
            paginator = ec2.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    sg_id = sg['GroupId']
                    sg_name = sg.get('GroupName', '')
                    
                    for ip_perm in sg.get('IpPermissions', []):
                        from_port = ip_perm.get('FromPort')
                        to_port = ip_perm.get('ToPort')
                        
                        if from_port is None or to_port is None:
                            if ip_perm.get('IpProtocol') == '-1':
                                for ip_range in ip_perm.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        self.add_finding(
                                            resource_id=f"Security Group: {sg_id} ({sg_name})",
                                            issue="Allows all inbound traffic on ALL ports from 0.0.0.0/0.",
                                            risk="Critical",
                                            remediation="Restrict inbound traffic to specific IP ranges and minimum required ports."
                                        )
                            continue

                        for port, port_name in sensitive_ports.items():
                            if from_port <= port <= to_port:
                                for ip_range in ip_perm.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        self.add_finding(
                                            resource_id=f"Security Group: {sg_id} ({sg_name})",
                                            issue=f"Unrestricted inbound {port_name} (Port {port}) from 0.0.0.0/0.",
                                            risk="High",
                                            remediation=f"Remove 0.0.0.0/0 rule for port {port} and restrict to your corporate VPN."
                                        )
                                        
        except NoCredentialsError:
            self.logger.error("AWS credentials not found.")
            raise
        except Exception as e:
            self.logger.error(f"Error scanning Security Groups: {str(e)}")
            
        return self.get_findings()
