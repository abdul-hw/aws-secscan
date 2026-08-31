from dataclasses import dataclass

@dataclass
class Finding:
    id: str
    severity: str
    service: str
    resource: str
    title: str
    description: str
    remediation: str

def print_finding(finding):
    print(f"ID: {finding.id}")
    print(f"Severity: {finding.severity}")
    print(f"Service: {finding.service}")
    print(f"Resource: {finding.resource}")
    print(f"Title: {finding.title}")
    print(f"Description: {finding.description}")
    print(f"Remediation: {finding.remediation}")