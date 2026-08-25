import boto3
from cloudguard.findings import Finding

def check_security_groups():
    ec2 = boto3.client("ec2")

    response = ec2.describe_security_groups()

    findings = []

    for security_group in response["SecurityGroups"]:
        group_id = security_group["GroupId"]

        for permission in security_group["IpPermissions"]:
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            protocol = permission.get("IpProtocol")

            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")

                if (protocol == "tcp" and cidr == "0.0.0.0/0" and from_port == 22 and to_port == 22):
                    findings.append(
                        Finding(
                            id="SG-001",
                            severity="HIGH",
                            service="EC2",
                            resource=group_id,
                            title="SSH exposed to the internet",
                            description=f"TCP/22 is reachable from {cidr}",
                            remediation="Restrict ingress to trusted CIDRs",
                        )
                    )

    return findings