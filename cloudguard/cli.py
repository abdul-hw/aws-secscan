import argparse
import json
import logging
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from cloudguard.remediation import remediate_sg_001
from cloudguard.scanner import run_scan

def print_results(findings):
    print("AWS SecScan")
    print()

    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print(
            f"[{finding.severity:<8}] "
            f"{finding.id:<7} "
            f"{finding.title} "
            f"({finding.resource})"
        )

    counts = Counter(finding.severity for finding in findings)

    print()
    print(f"{len(findings)} findings")
    print(f"Critical: {counts['CRITICAL']}")
    print(f"High:     {counts['HIGH']}")
    print(f"Medium:   {counts['MEDIUM']}")
    print(f"Low:      {counts['LOW']}")


def write_json_report(findings, output_path):
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "findings": [asdict(finding) for finding in findings],
    }

    with open(output_path, "w") as file:
        json.dump(report, file, indent=2)


def main():
    logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s: %(message)s",
    )
    
    parser = argparse.ArgumentParser(
        description="Scan AWS for common security misconfigurations"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan AWS for security issues",
    )

    scan_parser.add_argument(
        "--output",
        help="Write findings to a JSON file",
    )

    scan_parser.add_argument(
        "--service",
        choices=["ec2", "s3", "iam", "cloudtrail"],
        help="Scan only one AWS service",
    )

    remediate_parser = subparsers.add_parser(
        "remediate",
        help="Remediate a supported security finding",
    )

    remediate_parser.add_argument(
        "finding_id",
        help="Finding ID to remediate",
    )

    remediate_parser.add_argument(
        "--resource",
        required=True,
        help="AWS resource associated with the finding",
    )

    mode = remediate_parser.add_mutually_exclusive_group(
        required=True
    )

    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Show proposed remediation without changing AWS",
    )

    mode.add_argument(
        "--apply",
        action="store_true",
        help="Apply the remediation to AWS",
    )

    args = parser.parse_args()

    if args.command == "scan":
        findings, had_errors = run_scan(args.service)
        print_results(findings)

        if had_errors:
            print()
            print("Scan completed with errors.")

        if args.output:
            write_json_report(findings, args.output)
            print()
            print(f"JSON report written to {args.output}")

    elif args.command == "remediate":
        if args.finding_id == "SG-001":
            remediate_sg_001(
                resource=args.resource,
                apply=args.apply,
            )
        else:
            print(
                f"Automatic remediation is not supported "
                f"for {args.finding_id}."
            )