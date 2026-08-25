import logging

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoRegionError,
    ProfileNotFound,
)

from cloudguard.checks.cloudtrail import check_cloudtrail
from cloudguard.checks.iam import check_iam_roles
from cloudguard.checks.s3 import check_s3_buckets
from cloudguard.checks.security_groups import check_security_groups


logger = logging.getLogger(__name__)


def run_scan(service=None):
    checks = {
        "ec2": check_security_groups,
        "s3": check_s3_buckets,
        "iam": check_iam_roles,
        "cloudtrail": check_cloudtrail,
    }

    findings = []
    had_errors = False

    selected_checks = (
        {service: checks[service]}
        if service
        else checks
    )

    for service_name, check in selected_checks.items():
        try:
            findings.extend(check())

        except ClientError as error:
            had_errors = True
            error_code = error.response["Error"]["Code"]

            logger.error(
                "Unable to scan %s: %s",
                service_name,
                error_code,
            )

        except (BotoCoreError, NoRegionError, ProfileNotFound) as error:
            had_errors = True

            logger.error(
                "Unable to scan %s: %s",
                service_name,
                error,
            )

    return findings, had_errors