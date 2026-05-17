import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from .base_scanner import BaseScanner

class S3Scanner(BaseScanner):
    def scan(self):
        self.logger.info("Starting S3 public access scan")
        try:
            s3 = boto3.client('s3')
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                is_public = False
                
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    conf = pab.get('PublicAccessBlockConfiguration', {})
                    if not conf.get('BlockPublicAcls') or not conf.get('BlockPublicPolicy'):
                        pass
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        pass
                    else:
                        continue
                        
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            is_public = True
                            break
                except ClientError:
                    pass
                
                if is_public:
                    self.add_finding(
                        resource_id=f"S3 Bucket: {bucket_name}",
                        issue="Bucket has public read/write ACLs (AllUsers).",
                        risk="Critical",
                        remediation="Enable 'Block all public access' in S3 bucket settings."
                    )
                    
        except NoCredentialsError:
            self.logger.error("AWS credentials not found.")
            raise
        except Exception as e:
            self.logger.error(f"Error scanning S3: {str(e)}")
            
        return self.get_findings()
