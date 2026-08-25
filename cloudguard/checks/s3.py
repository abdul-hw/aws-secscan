import boto3
from botocore.exceptions import ClientError
from cloudguard.findings import Finding

def check_s3_buckets():
    s3 = boto3.client("s3")

    findings = []

    response = s3.list_buckets()

    for bucket in response["Buckets"]:
        bucket_name = bucket["Name"]

        try:
            public_access_block = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = public_access_block["PublicAccessBlockConfiguration"]

            protections_enabled = (
                config["BlockPublicAcls"]
                and config["IgnorePublicAcls"]
                and config["BlockPublicPolicy"]
                and config["RestrictPublicBuckets"]
            )

            if not protections_enabled:
                findings.append(
                    Finding(
                        id="S3-001",
                        severity="CRITICAL",
                        service="S3",
                        resource=bucket_name,
                        title="S3 Public Access Block is not fully enabled",
                        description="One or more S3 public access protections are disabled",
                        remediation="Enable all S3 Public Access Block settings",
                    )
                )

        except ClientError as error:
            error_code = error.response["Error"]["Code"]

            if error_code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(
                    Finding(
                        id="S3-001",
                        severity="CRITICAL",
                        service="S3",
                        resource=bucket_name,
                        title="S3 Public Access Block is missing",
                        description="Bucket has no Public Access Block configuration",
                        remediation="Enable all S3 Public Access Block settings",
                    )
                )
            else:
                raise

    return findings