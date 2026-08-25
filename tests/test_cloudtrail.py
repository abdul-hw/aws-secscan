from unittest.mock import patch

from cloudguard.checks.cloudtrail import check_cloudtrail


@patch("cloudguard.checks.cloudtrail.boto3.client")
def test_detects_missing_trail(mock_boto_client):
    mock_cloudtrail = mock_boto_client.return_value

    mock_cloudtrail.describe_trails.return_value = {
        "trailList": []
    }

    findings = check_cloudtrail()

    assert len(findings) == 1
    assert findings[0].id == "CT-001"
    assert findings[0].severity == "MEDIUM"


@patch("cloudguard.checks.cloudtrail.boto3.client")
def test_detects_disabled_logging(mock_boto_client):
    mock_cloudtrail = mock_boto_client.return_value

    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "test-trail"
            }
        ]
    }

    mock_cloudtrail.get_trail_status.return_value = {
        "IsLogging": False
    }

    findings = check_cloudtrail()

    assert len(findings) == 1
    assert findings[0].id == "CT-002"
    assert findings[0].resource == "test-trail"