from app.scanners import S3Scanner, IAMScanner, SGScanner, EC2Scanner
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

def run_all_scanners():
    """Orchestrates all scanners and aggregates findings."""
    logger.info("Initiating full environment scan.")
    findings = []
    
    scanners = [
        S3Scanner(),
        IAMScanner(),
        SGScanner(),
        EC2Scanner()
    ]
    
    for scanner in scanners:
        try:
            findings.extend(scanner.scan())
        except Exception as e:
            logger.error(f"Scanner {scanner.__class__.__name__} failed: {str(e)}")
            
    logger.info(f"Scan complete. Found {len(findings)} issues.")
    return findings

def get_mock_findings():
    """Returns realistic mock data for demonstrations."""
    return [
        {
            "resource_id": "S3 Bucket: prod-db-backup-bucket-mock",
            "issue": "Bucket has public read/write ACLs (AllUsers).",
            "risk": "Critical",
            "remediation": "Enable 'Block all public access' in S3 bucket settings."
        },
        {
            "resource_id": "IAM User: dev-john-doe",
            "issue": "MFA is not enabled for this user.",
            "risk": "High",
            "remediation": "Enforce MFA for all IAM users via IAM policies."
        },
        {
            "resource_id": "Security Group: sg-0123456789abcde (Web-Tier)",
            "issue": "Unrestricted inbound SSH (Port 22) from 0.0.0.0/0.",
            "risk": "High",
            "remediation": "Remove 0.0.0.0/0 rule for port 22 and restrict to corporate VPN."
        },
        {
            "resource_id": "EBS Volume: vol-0abcd1234efgh5678",
            "issue": "EBS Volume is unencrypted, exposing data at rest.",
            "risk": "Medium",
            "remediation": "Create a snapshot, copy with encryption enabled, and replace volume."
        }
    ]
