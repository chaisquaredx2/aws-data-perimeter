# Exception Expiry Enforcer — Layer 5
#
# Deploys: Lambda function, EventBridge schedule, DynamoDB audit table,
# SNS notification topic, and required IAM role.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  function_name = "${var.name_prefix}-exception-expiry-enforcer"
  account_id    = data.aws_caller_identity.current.account_id
  region        = data.aws_region.current.name
}

# ---------------------------------------------------------------------------
# SNS Topic — exception expiry alerts
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "exception_alerts" {
  name              = "${var.name_prefix}-exception-expiry-alerts"
  kms_master_key_id = var.sns_kms_key_id

  tags = var.tags
}

# ---------------------------------------------------------------------------
# DynamoDB Audit Table
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "audit" {
  name         = "${var.name_prefix}-exception-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "exception_id"
  range_key    = "timestamp"

  attribute {
    name = "exception_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# IAM Role for Lambda
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda" {
  name = "${local.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "lambda" {
  name = "${local.function_name}-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.function_name}:*"
      },
      {
        Sid    = "TaggingAPIRead"
        Effect = "Allow"
        Action = [
          "tag:GetResources",
          "tag:GetTagKeys",
          "tag:GetTagValues",
        ]
        Resource = "*"
      },
      {
        Sid    = "TaggingAPIWrite"
        Effect = "Allow"
        Action = [
          "tag:TagResources",
          "tag:UntagResources",
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMTagOperations"
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:ListRoleTags",
          "iam:ListUsers",
          "iam:ListUserTags",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:TagUser",
          "iam:UntagUser",
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSTagOperations"
        Effect = "Allow"
        Action = [
          "kms:ListResourceTags",
          "kms:TagResource",
          "kms:UntagResource",
        ]
        Resource = "*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.exception_alerts.arn
      },
      {
        Sid      = "DynamoDBAudit"
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.audit.arn
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "DataPerimeter/Exceptions"
          }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda Function
# ---------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/.build/exception_expiry_enforcer.zip"
}

resource "aws_lambda_function" "enforcer" {
  function_name    = local.function_name
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = var.timeout_seconds
  memory_size      = var.memory_mb
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      GRACE_PERIOD_HOURS      = tostring(var.grace_period_hours)
      NOTIFICATION_THRESHOLDS = jsonencode(var.notification_thresholds)
      SNS_TOPIC_ARN           = aws_sns_topic.exception_alerts.arn
      AUDIT_TABLE             = aws_dynamodb_table.audit.name
      ENFORCE_REMOVAL         = tostring(var.enforce_removal)
      LOG_LEVEL               = var.log_level
    }
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# EventBridge Schedule
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.function_name}-schedule"
  description         = "Trigger exception expiry enforcer"
  schedule_expression = var.schedule_expression

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.enforcer.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enforcer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group (explicit for retention control)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}
