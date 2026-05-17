import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from .base_scanner import BaseScanner

class EC2Scanner(BaseScanner):
    def scan(self):
        self.logger.info("Starting EBS Volume scan")
        try:
            ec2 = boto3.client('ec2')
            paginator = ec2.get_paginator('describe_volumes')
            
            for page in paginator.paginate():
                for volume in page['Volumes']:
                    vol_id = volume['VolumeId']
                    is_encrypted = volume.get('Encrypted', False)
                    
                    if not is_encrypted:
                        self.add_finding(
                            resource_id=f"EBS Volume: {vol_id}",
                            issue="EBS Volume is unencrypted, exposing data at rest.",
                            risk="Medium",
                            remediation="Create a snapshot, copy it with encryption enabled, and replace the volume."
                        )
                                        
        except NoCredentialsError:
            self.logger.error("AWS credentials not found.")
            raise
        except Exception as e:
            self.logger.error(f"Error scanning EBS Volumes: {str(e)}")
            
        return self.get_findings()
