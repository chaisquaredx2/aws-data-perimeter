# Data Perimeter — KMS Tag Remediation
#
# Wiz webhook → API Gateway → Lambda → tags untagged KMS keys with
# dp:* tags fetched from the Tag Lookup API.
#
# API Gateway uses API key authentication. Configure the API key value
# in Wiz Automation as the x-api-key header.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# Lambda source packaging
# ---------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/.build/tag_remediation.zip"
}

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-tag-remediation"
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
  name = "${var.name_prefix}-tag-remediation"
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
        Resource = "${aws_cloudwatch_log_group.this.arn}:*"
      },
      {
        Sid    = "KMSTagging"
        Effect = "Allow"
        Action = [
          "kms:TagResource",
          "kms:ListResourceTags",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "DataPerimeter/Remediation"
          }
        }
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.remediation.arn
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "this" {
  function_name    = "${var.name_prefix}-tag-remediation"
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
      TAG_LOOKUP_URL = var.tag_lookup_url
      SNS_TOPIC_ARN  = aws_sns_topic.remediation.arn
      LOG_LEVEL      = var.log_level
    }
  }
}

# ---------------------------------------------------------------------------
# CloudWatch log group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name_prefix}-tag-remediation"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# ---------------------------------------------------------------------------
# SNS topic for remediation notifications
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "remediation" {
  name              = "${var.name_prefix}-tag-remediation-alerts"
  kms_master_key_id = var.sns_kms_key_id
  tags              = var.tags
}

# ---------------------------------------------------------------------------
# API Gateway — POST /webhook with API key auth
# ---------------------------------------------------------------------------

resource "aws_api_gateway_rest_api" "this" {
  name        = "${var.name_prefix}-tag-remediation"
  description = "Wiz webhook endpoint for KMS tag remediation"
  tags        = var.tags

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "webhook"
}

resource "aws_api_gateway_method" "post" {
  rest_api_id      = aws_api_gateway_rest_api.this.id
  resource_id      = aws_api_gateway_resource.webhook.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = aws_api_gateway_resource.webhook.id
  http_method             = aws_api_gateway_method.post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.this.invoke_arn
}

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id

  depends_on = [aws_api_gateway_integration.lambda]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "this" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = "v1"
  tags          = var.tags
}

# API key + usage plan for Wiz webhook authentication
resource "aws_api_gateway_api_key" "wiz" {
  name    = "${var.name_prefix}-wiz-webhook"
  enabled = true
  tags    = var.tags
}

resource "aws_api_gateway_usage_plan" "this" {
  name = "${var.name_prefix}-tag-remediation"
  tags = var.tags

  api_stages {
    api_id = aws_api_gateway_rest_api.this.id
    stage  = aws_api_gateway_stage.this.stage_name
  }

  throttle_settings {
    burst_limit = 10
    rate_limit  = 5
  }
}

resource "aws_api_gateway_usage_plan_key" "this" {
  key_id        = aws_api_gateway_api_key.wiz.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.this.id
}

# Allow API Gateway to invoke Lambda
resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.this.execution_arn}/*/${aws_api_gateway_method.post.http_method}${aws_api_gateway_resource.webhook.path}"
}
