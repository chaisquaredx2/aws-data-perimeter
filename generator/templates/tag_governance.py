"""Layer 6: Tag Governance SCP — protect classification tags on KMS keys and principals."""


def generate(config) -> dict:
    """Generate Layer 6 tag governance SCP."""
    allowed_mutator_values = []
    for mutator in config.tag_governance.allowed_mutator_tags:
        allowed_mutator_values.append(mutator.get("value", ""))

    if not allowed_mutator_values:
        allowed_mutator_values = ["security-admin", "platform-engineering"]

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ProtectDataPerimeterTags",
                "Effect": "Deny",
                "Action": [
                    "kms:TagResource",
                    "kms:UntagResource",
                    "iam:TagRole",
                    "iam:UntagRole",
                    "iam:TagUser",
                    "iam:UntagUser",
                ],
                "Resource": "*",
                "Condition": {
                    "ForAnyValue:StringLike": {
                        "aws:TagKeys": [
                            "dp:exception:*",
                            "dp:*:enforcement",
                            "dp:data-zone",
                            "dp:environment",
                            "dp:project",
                            "dp:data-classification",
                            "dp:compliance-scope",
                        ],
                    },
                    "StringNotEquals": {
                        "aws:PrincipalTag/team": allowed_mutator_values,
                    },
                    # Allow service-linked roles (AWS Organizations tag
                    # policies, Service Catalog, etc.) to manage tags
                    "ArnNotLikeIfExists": {
                        "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
                    },
                },
            },
            {
                "Sid": "RequireKMSKeyDataZoneTag",
                "Effect": "Deny",
                "Action": "kms:CreateKey",
                "Resource": "*",
                "Condition": {
                    "Null": {
                        "aws:RequestTag/dp:data-zone": "true",
                    },
                },
            },
            {
                "Sid": "RequireKMSKeyEnvironmentTag",
                "Effect": "Deny",
                "Action": "kms:CreateKey",
                "Resource": "*",
                "Condition": {
                    "Null": {
                        "aws:RequestTag/dp:environment": "true",
                    },
                },
            },
            {
                "Sid": "RequireKMSKeyProjectTag",
                "Effect": "Deny",
                "Action": "kms:CreateKey",
                "Resource": "*",
                "Condition": {
                    "Null": {
                        "aws:RequestTag/dp:project": "true",
                    },
                },
            },
        ],
    }
