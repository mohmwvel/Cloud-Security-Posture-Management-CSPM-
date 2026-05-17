import pytest
from app.scanners.iam_scanner import IAMScanner
from unittest.mock import patch, MagicMock

@patch('boto3.client')
def test_iam_scanner_no_mfa(mock_boto):
    mock_iam = MagicMock()
    mock_boto.return_value = mock_iam
    
    # Mocking paginator
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {'Users': [{'UserName': 'test-user'}]}
    ]
    
    # Mocking MFA response (empty list means no MFA)
    mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
    
    scanner = IAMScanner()
    findings = scanner.scan()
    
    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'IAM User: test-user'
    assert findings[0]['risk'] == 'High'
