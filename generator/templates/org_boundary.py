"""Layer 3a: Org-Boundary SCP — prevent principals from accessing resources outside the org.

Covers metadata/list operations that don't touch KMS. No ABAC tags needed —
just an org ID check. AWS-managed resources (e.g., S3 buckets used by services),
service-linked roles, and AWS service-to-service calls are excluded.
"""


def generate(config) -> dict:
    """Generate Layer 3a org-boundary SCP."""
    aws_managed_patterns = config.resource_perimeter.aws_managed_patterns
    if not aws_managed_patterns:
        aws_managed_patterns = [
            "arn:aws:s3:::aws-*",
            "arn:aws:s3:::amazon-*",
        ]

    condition = {
        "StringNotEquals": {
            "aws:ResourceOrgID": config.org_id,
        },
        "StringNotEqualsIfExists": {
            "aws:PrincipalTag/dp:resource:enforcement": [
                "excluded",
                "monitoring",
            ],
        },
        "Null": {
            "aws:PrincipalTag/dp:exception:id": "true",
        },
        # Allow AWS service-to-service calls (S3 replication, CloudFormation
        # StackSets, Config delivery, etc.)
        "BoolIfExists": {
            "aws:ViaAWSService": "false",
        },
        "ArnNotLikeIfExists": {
            "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
            "aws:ResourceArn": aws_managed_patterns,
        },
    }

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnforceResourcePerimeterOrgBoundary",
                "Effect": "Deny",
                "Action": [
                    "s3:*",
                    "sqs:*",
                    "sns:*",
                    "kms:*",
                    "lambda:*",
                    "secretsmanager:*",
                    "ssm:*",
                ],
                "Resource": "*",
                "Condition": condition,
            }
        ],
    }
