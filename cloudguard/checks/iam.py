import boto3

from cloudguard.findings import Finding


def check_iam_roles():
    iam = boto3.client("iam")

    findings = []

    roles_response = iam.list_roles()

    for role in roles_response["Roles"]:
        role_name = role["RoleName"]

        policies_response = iam.list_role_policies(
            RoleName=role_name
        )

        for policy_name in policies_response["PolicyNames"]:
            policy_response = iam.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )

            policy_document = policy_response["PolicyDocument"]

            statements = policy_document.get("Statement", [])

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])

                if isinstance(actions, str):
                    actions = [actions]

                if isinstance(resources, str):
                    resources = [resources]

                has_full_wildcard = "*" in actions
                has_s3_wildcard = "s3:*" in actions
                has_all_resources = "*" in resources

                if has_full_wildcard and has_all_resources:
                    findings.append(
                        Finding(
                            id="IAM-001",
                            severity="CRITICAL",
                            service="IAM",
                            resource=role_name,
                            title="IAM role grants unrestricted permissions",
                            description=(
                                f"Inline policy {policy_name} allows "
                                "Action '*' on Resource '*'"
                            ),
                            remediation=(
                                "Replace wildcard permissions with "
                                "least-privilege actions and resources"
                            ),
                        )
                    )

                elif has_s3_wildcard and has_all_resources:
                    findings.append(
                        Finding(
                            id="IAM-002",
                            severity="HIGH",
                            service="IAM",
                            resource=role_name,
                            title="IAM role grants wildcard S3 permissions",
                            description=(
                                f"Inline policy {policy_name} allows "
                                "s3:* on Resource '*'"
                            ),
                            remediation=(
                                "Restrict S3 actions and resources to "
                                "what the role actually requires"
                            ),
                        )
                    )

    return findings