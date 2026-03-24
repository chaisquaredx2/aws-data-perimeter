# Data Perimeter — Compliance Reporter
#
# Scheduled Lambda that queries IAM Access Analyzer findings, categorizes
# them (unresolved vs exception-covered), and publishes compliance metrics
# to CloudWatch. Follows the same patterns as the exception-enforcer module.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# Lambda source packaging
# ---------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/.build/compliance_reporter.zip"
}

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-compliance-reporter"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "${var.name_prefix}-compliance-reporter"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.this.arn}:*"
      },
      {
        Sid      = "AccessAnalyzerRead"
        Effect   = "Allow"
        Action   = [
          "access-analyzer:ListFindings",
          "access-analyzer:ListFindingsV2",
          "access-analyzer:GetFinding",
          "access-analyzer:GetFindingV2",
        ]
        Resource = var.analyzer_arn
      },
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "DataPerimeter/Compliance"
          }
        }
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = var.sns_topic_arn != "" ? var.sns_topic_arn : "arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:nonexistent"
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "this" {
  function_name    = "${var.name_prefix}-compliance-reporter"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = var.timeout_seconds
  memory_size      = var.memory_mb
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  tags             = var.tags

  environment {
    variables = {
      ANALYZER_ARN  = var.analyzer_arn
      SNS_TOPIC_ARN = var.sns_topic_arn
      LOG_LEVEL     = var.log_level
    }
  }
}

# ---------------------------------------------------------------------------
# CloudWatch log group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name_prefix}-compliance-reporter"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# ---------------------------------------------------------------------------
# EventBridge schedule
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-compliance-reporter"
  description         = "Trigger compliance reporter Lambda on schedule"
  schedule_expression = var.schedule_expression
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "lambda"
  arn       = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
