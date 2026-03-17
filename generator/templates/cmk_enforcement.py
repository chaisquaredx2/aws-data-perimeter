"""Layer 1: CMK Enforcement SCP — prevent resource creation without CMK encryption."""


def generate(config) -> dict:
    """Generate Layer 1 CMK enforcement SCP."""
    statements = []

    statements.append({
        "Sid": "DenyS3WithoutCMK",
        "Effect": "Deny",
        "Action": "s3:PutObject",
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "s3:x-amz-server-side-encryption": "aws:kms",
                "aws:PrincipalTag/dp:kms:enforcement": ["excluded"],
            },
            "ArnNotLikeIfExists": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
            },
        },
    })

    statements.append({
        "Sid": "DenyS3BucketWithoutDefaultCMK",
        "Effect": "Deny",
        "Action": "s3:PutEncryptionConfiguration",
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "s3:x-amz-server-side-encryption": "aws:kms",
            },
        },
    })

    statements.append({
        "Sid": "DenyDynamoDBWithoutCMK",
        "Effect": "Deny",
        "Action": "dynamodb:CreateTable",
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "dynamodb:encryptionType": "CUSTOMER_MANAGED_CMK",
            },
        },
    })

    statements.append({
        "Sid": "DenySQSWithoutCMK",
        "Effect": "Deny",
        "Action": "sqs:CreateQueue",
        "Resource": "*",
        "Condition": {
            "Null": {
                "sqs:KmsMasterKeyId": "true",
            },
        },
    })

    statements.append({
        "Sid": "DenySNSWithoutCMK",
        "Effect": "Deny",
        "Action": "sns:CreateTopic",
        "Resource": "*",
        "Condition": {
            "Null": {
                "sns:KmsMasterKeyId": "true",
            },
        },
    })

    statements.append({
        "Sid": "DenyEBSWithoutEncryption",
        "Effect": "Deny",
        "Action": "ec2:CreateVolume",
        "Resource": "*",
        "Condition": {
            "Bool": {
                "ec2:Encrypted": "false",
            },
        },
    })

    statements.append({
        "Sid": "DenyRDSWithoutEncryption",
        "Effect": "Deny",
        "Action": [
            "rds:CreateDBInstance",
            "rds:CreateDBCluster",
        ],
        "Resource": "*",
        "Condition": {
            "Bool": {
                "rds:StorageEncrypted": "false",
            },
        },
    })

    statements.append({
        "Sid": "DenyKMSKeyWithoutClassificationTags",
        "Effect": "Deny",
        "Action": "kms:CreateKey",
        "Resource": "*",
        "Condition": {
            "Null": {
                "aws:RequestTag/dp:data-zone": "true",
            },
        },
    })

    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }
