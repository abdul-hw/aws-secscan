import boto3
from cloudguard.findings import Finding


def check_cloudtrail():
    cloudtrail = boto3.client("cloudtrail")

    findings = []

    response = cloudtrail.describe_trails()

    trails = response["trailList"]

    if not trails:
        findings.append(
            Finding(
                id="CT-001",
                severity="MEDIUM",
                service="CloudTrail",
                resource="account",
                title="No CloudTrail trail detected",
                description="No CloudTrail trail exists in this AWS account",
                remediation="Create and enable a CloudTrail trail",
            )
        )

        return findings

    for trail in trails:
        trail_name = trail["Name"]

        status = cloudtrail.get_trail_status(Name=trail_name)

        if not status["IsLogging"]:
            findings.append(
                Finding(
                    id="CT-002",
                    severity="MEDIUM",
                    service="CloudTrail",
                    resource=trail_name,
                    title="CloudTrail logging is disabled",
                    description=f"Trail {trail_name} exists but is not actively logging",
                    remediation="Enable logging for the CloudTrail trail",
                )
            )

    return findings