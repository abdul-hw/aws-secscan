from unittest.mock import patch

from cloudguard.checks.security_groups import check_security_groups


@patch("cloudguard.checks.security_groups.boto3.client")
def test_detects_public_ssh(mock_boto_client):
    mock_ec2 = mock_boto_client.return_value

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test123",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ],
                    }
                ],
            }
        ]
    }

    findings = check_security_groups()

    assert len(findings) == 1
    assert findings[0].id == "SG-001"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "sg-test123"


@patch("cloudguard.checks.security_groups.boto3.client")
def test_ignores_restricted_ssh(mock_boto_client):
    mock_ec2 = mock_boto_client.return_value

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test456",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "98.100.50.25/32"}
                        ],
                    }
                ],
            }
        ]
    }

    findings = check_security_groups()

    assert findings == []