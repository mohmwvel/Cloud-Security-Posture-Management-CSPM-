import pytest
from app.scanners.s3_scanner import S3Scanner
from unittest.mock import patch, MagicMock

@patch('boto3.client')
def test_s3_scanner_public_acls(mock_boto):
    mock_s3 = MagicMock()
    mock_boto.return_value = mock_s3
    
    # Mocking bucket list
    mock_s3.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-public-bucket'}]
    }
    
    # Mocking Public Access Block (not blocked)
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': False
        }
    }
    
    # Mocking ACLs
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [{
            'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}
        }]
    }
    
    scanner = S3Scanner()
    findings = scanner.scan()
    
    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'S3 Bucket: test-public-bucket'
    assert findings[0]['risk'] == 'Critical'
