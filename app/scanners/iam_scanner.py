import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from .base_scanner import BaseScanner

class IAMScanner(BaseScanner):
    def scan(self):
        self.logger.info("Starting IAM MFA scan")
        try:
            iam = boto3.client('iam')
            paginator = iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    try:
                        mfa_devices = iam.list_mfa_devices(UserName=user_name)
                        if len(mfa_devices['MFADevices']) == 0:
                            self.add_finding(
                                resource_id=f"IAM User: {user_name}",
                                issue="MFA is not enabled for this user.",
                                risk="High",
                                remediation="Enforce MFA for all IAM users via IAM policies."
                            )
                    except ClientError as e:
                        self.logger.error(f"Error checking MFA for {user_name}: {e}")
                        
        except NoCredentialsError:
            self.logger.error("AWS credentials not found.")
            raise
        except Exception as e:
            self.logger.error(f"Error scanning IAM: {str(e)}")
            
        return self.get_findings()
