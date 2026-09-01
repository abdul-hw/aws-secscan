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

Run a full scan:

```bash
python -m aws_secscan scan
```

Scan only one supported service:

```bash
python -m aws_secscan scan --service ec2
```
<img width="1227" height="254" alt="image" src="https://github.com/user-attachments/assets/53b390d4-df3c-40c5-80ca-e8f1fc2a9754" />


## Finding Format

Every finding contains: ID, Severity, Service, Resource, Title, Description, and Remediation

By using one structure findings remain consistent across AWS services and are easier to display, export, and process.

<img width="1398" height="259" alt="image" src="https://github.com/user-attachments/assets/8324acda-6740-4227-98a5-76584ece3f9b" />

## JSON Report

Findings can be exported to JSON:

```bash
python -m aws_secscan scan --output findings.json
```

This allows scan results to be saved or processed by other scripts and tools.

<img width="791" height="344" alt="image" src="https://github.com/user-attachments/assets/0c3146d0-dab2-411d-b8a6-a687c393c503" />
<img width="634" height="156" alt="image" src="https://github.com/user-attachments/assets/a4fbc537-8970-40ed-b07f-f24661cffac6" />

## Remediation

AWS SecScan supports automated remediation for `SG-001`, which detects SSH exposed to the internet.

Preview the remediation without changing AWS:

```bash
python -m aws_secscan remediate SG-001 \
  --resource sg-xxxxxxxx \
  --dry-run
```

Apply the remediation:

```bash
python -m aws_secscan remediate SG-001 \
  --resource sg-xxxxxxxx \
  --apply
```

The dry run shows what will change before AWS is modified.

IAM and S3 findings provide remediation guidance instead of automatically making higher-impact changes.

<img width="1644" height="752" alt="image" src="https://github.com/user-attachments/assets/a1192133-1832-43f3-a9ba-a0ccbd449ec9" />

## Testing

AWS SecScan uses pytest and mocked AWS responses to test security logic without creating real AWS resources.

Run the tests:

```bash
python -m pytest
```
<img width="2048" height="332" alt="image" src="https://github.com/user-attachments/assets/a34a03b7-b2f8-4eef-a3b5-800192f3df4a" />

GitHub Actions automatically runs the test suite on every push and pull request.

<img width="2048" height="480" alt="image" src="https://github.com/user-attachments/assets/5394d335-8452-49bf-a673-7b1e8a500a98" />

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Run a full scan:

```bash
python -m aws_secscan scan
```

Scan one service:

```bash
python -m aws_secscan scan --service ec2
```

Export findings:

```bash
python -m aws_secscan scan --output findings.json
```

Only use AWS SecScan on AWS accounts and resources you are authorized to access.
AWS credentials must be configured before running scans.

