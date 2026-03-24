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
            # Allow AWS services writing to S3 on your behalf
            # (ALB access logs with SSE-S3, Redshift UNLOAD, Athena results, etc.)
            "BoolIfExists": {
                "aws:ViaAWSService": "false",
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
        "Action": [
            "dynamodb:CreateTable",
            "dynamodb:UpdateTable",
            "dynamodb:RestoreTableFromBackup",
            "dynamodb:RestoreTableToPointInTime",
        ],
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
            "rds:CreateDBInstanceReadReplica",
        ],
        "Resource": "*",
        "Condition": {
            "Bool": {
                "rds:StorageEncrypted": "false",
            },
        },
    })

    statements.append({
        "Sid": "DenyEFSWithoutCMK",
        "Effect": "Deny",
        "Action": "elasticfilesystem:CreateFileSystem",
        "Resource": "*",
        "Condition": {
            "Bool": {
                "elasticfilesystem:Encrypted": "false",
            },
        },
    })

    statements.append({
        "Sid": "DenySecretsManagerWithoutCMK",
        "Effect": "Deny",
        "Action": "secretsmanager:CreateSecret",
        "Resource": "*",
        "Condition": {
            "Null": {
                "secretsmanager:KmsKeyId": "true",
            },
        },
    })

    statements.append({
        "Sid": "DenyKinesisWithoutCMK",
        "Effect": "Deny",
        "Action": [
            "kinesis:CreateStream",
            "kinesis:UpdateStreamMode",
        ],
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "kinesis:EncryptionType": "KMS",
            },
        },
    })

    statements.append({
        "Sid": "DenyRedshiftWithoutCMK",
        "Effect": "Deny",
        "Action": [
            "redshift:CreateCluster",
            "redshift:RestoreFromClusterSnapshot",
        ],
        "Resource": "*",
        "Condition": {
            "Bool": {
                "redshift:Encrypted": "false",
            },
        },
    })

    # CloudWatch Logs: no SCP condition key for KMS at CreateLogGroup time.
    # Enforce by: (1) denying removal of KMS association, and (2) requiring
    # the enforcement-exclusion tag to create log groups — only automation
    # that sets KMS should have this tag.
    statements.append({
        "Sid": "DenyCloudWatchLogsRemoveCMK",
        "Effect": "Deny",
        "Action": "logs:DisassociateKmsKey",
        "Resource": "*",
    })

    statements.append({
        "Sid": "DenyCloudWatchLogsCreateWithoutCMK",
        "Effect": "Deny",
        "Action": "logs:CreateLogGroup",
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "aws:PrincipalTag/dp:logs:cmk-automation": ["allowed"],
            },
            # Allow AWS services that auto-create log groups
            # (Lambda, API Gateway, ECS, VPC Flow Logs, etc.)
            "BoolIfExists": {
                "aws:ViaAWSService": "false",
            },
            "ArnNotLikeIfExists": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
            },
        },
    })

    # Deny use of any KMS key that lacks our dp:data-zone tag (i.e., not one
    # of our CMKs — catches aws/s3, aws/ebs, aws/rds, etc.).
    # Allow AWS service-to-service calls (e.g., ALB → S3 with aws/s3 key)
    # and service-linked roles, since those are AWS-initiated.
    statements.append({
        "Sid": "DenyNonCMKKeyUsage",
        "Effect": "Deny",
        "Action": [
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
            "kms:GenerateDataKeyPair",
            "kms:GenerateDataKeyPairWithoutPlaintext",
            "kms:ReEncryptFrom",
            "kms:ReEncryptTo",
            "kms:Encrypt",
            "kms:CreateGrant",
        ],
        "Resource": "*",
        "Condition": {
            "Null": {
                "aws:ResourceTag/dp:data-zone": "true",
            },
            "BoolIfExists": {
                "aws:ViaAWSService": "false",
            },
            "ArnNotLikeIfExists": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
            },
            "StringNotEqualsIfExists": {
                "aws:PrincipalTag/dp:kms:enforcement": ["excluded"],
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
