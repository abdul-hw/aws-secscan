import boto3

def remediate_sg_001(resource, apply=False):
    print("Proposed remediation:")
    print(f"Remove ingress TCP/22 from 0.0.0.0/0 on {resource}")
    print()

    if not apply:
        print("No changes made.")
        return

    ec2 = boto3.client("ec2")

    ec2.revoke_security_group_ingress(
        GroupId=resource,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
            }
        ],
    )

    print("Remediation applied.")