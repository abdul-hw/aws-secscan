# AWS SecScan

AWS SecScan is a Python based AWS security scanner that checks for common cloud misconfigurations in EC2, S3, IAM, and CloudTrail.
It uses boto3 to scan AWS configurations, report risky settings, export findings to JSON, and safely remediate supported issues.

## Architecture
<img width="446" height="743" alt="Screenshot 2026-08-31 at 7 50 18 AM" src="https://github.com/user-attachments/assets/efe765c9-bd19-4c52-9695-dec8e6ab866e" />

## Security Checks

AWS SecScan currently checks for:
<img width="1272" height="608" alt="image" src="https://github.com/user-attachments/assets/f1145577-6105-403f-bf7e-e2854ffd8243" />

0.0.0.0/0 means any IPv4 address on the internet can reach the rule.

## Example Scan

To run a full scan perform the following steps in order:

```bash
python -m aws_secscan scan
```

Scan only one supported service:

```bash
python -m aws_secscan scan --service ec2
```
<img width="1227" height="254" alt="image" src="https://github.com/user-attachments/assets/53b390d4-df3c-40c5-80ca-e8f1fc2a9754" />


## Finding Format

Every finding contains: ID, Severity, Service, Resource, Title, Description, Remediation
By using one structure findings remain consistent across AWS services and are easier to display, export, and process.
<img width="1398" height="259" alt="image" src="https://github.com/user-attachments/assets/8324acda-6740-4227-98a5-76584ece3f9b" />
