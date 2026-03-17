"""Layer 2: KMS ABAC SCP — primary data access gate via tag matching.

This is a STATIC policy. Uses IAM policy variables (${aws:PrincipalTag/...})
to match principal tags against KMS key tags at runtime. Never needs
redeployment when access relationships change — just tag both sides.
"""


def generate(config) -> dict:
    """Generate Layer 2 KMS ABAC SCP."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnforceKMSABACTagMatch",
                "Effect": "Deny",
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:GenerateDataKeyPair",
                    "kms:GenerateDataKeyPairWithoutPlaintext",
                    "kms:ReEncryptFrom",
                    "kms:ReEncryptTo",
                    "kms:CreateGrant",
                ],
                "Resource": "*",
                "Condition": {
                    "StringNotEqualsIfExists": {
                        "aws:ResourceTag/dp:data-zone": "${aws:PrincipalTag/dp:data-zone}",
                        "aws:ResourceTag/dp:environment": "${aws:PrincipalTag/dp:environment}",
                        "aws:ResourceTag/dp:project": "${aws:PrincipalTag/dp:project}",
                        "aws:PrincipalTag/dp:kms:enforcement": [
                            "excluded",
                            "monitoring",
                        ],
                    },
                    "Null": {
                        "aws:PrincipalTag/dp:exception:id": "true",
                    },
                    "BoolIfExists": {
                        "aws:ViaAWSService": "false",
                    },
                    "ArnNotLikeIfExists": {
                        "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
                    },
                },
            }
        ],
    }
