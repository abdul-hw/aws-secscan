from unittest.mock import patch

from botocore.exceptions import ClientError

from cloudguard.checks.s3 import check_s3_buckets


@patch("cloudguard.checks.s3.boto3.client")
def test_detects_missing_public_access_block(mock_boto_client):
    mock_s3 = mock_boto_client.return_value

    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "test-bucket"
            }
        ]
    }

    mock_s3.get_public_access_block.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchPublicAccessBlockConfiguration",
                "Message": "No Public Access Block configuration exists",
            }
        },
        "GetPublicAccessBlock",
    )

    findings = check_s3_buckets()

    assert len(findings) == 1
    assert findings[0].id == "S3-001"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].resource == "test-bucket"


@patch("cloudguard.checks.s3.boto3.client")
def test_ignores_fully_protected_bucket(mock_boto_client):
    mock_s3 = mock_boto_client.return_value

    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "secure-bucket"
            }
        ]
    }

    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    findings = check_s3_buckets()

    assert findings == []