from unittest.mock import patch

from cloudguard.checks.iam import check_iam_roles


@patch("cloudguard.checks.iam.boto3.client")
def test_detects_wildcard_s3_permissions(mock_boto_client):
    mock_iam = mock_boto_client.return_value

    mock_iam.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "test-role"
            }
        ]
    }

    mock_iam.list_role_policies.return_value = {
        "PolicyNames": ["bad-s3-policy"]
    }

    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ]
        }
    }

    findings = check_iam_roles()

    assert len(findings) == 1
    assert findings[0].id == "IAM-002"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "test-role"


@patch("cloudguard.checks.iam.boto3.client")
def test_ignores_deny_wildcard_policy(mock_boto_client):
    mock_iam = mock_boto_client.return_value

    mock_iam.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "test-role"
            }
        ]
    }

    mock_iam.list_role_policies.return_value = {
        "PolicyNames": ["deny-policy"]
    }

    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
    }

    findings = check_iam_roles()

    assert findings == []