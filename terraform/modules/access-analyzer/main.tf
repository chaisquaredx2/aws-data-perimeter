# Data Perimeter — IAM Access Analyzer
#
# Provisions an org/account-level analyzer that continuously detects
# external access to resources. Findings for resources with approved
# exception tags are auto-archived. New ACTIVE findings route to SNS.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${var.name_prefix}-data-perimeter"
  type          = var.analyzer_type
  tags          = var.tags
}

# ---------------------------------------------------------------------------
# Archive rule — auto-archive findings for exception-tagged resources
# ---------------------------------------------------------------------------

resource "aws_accessanalyzer_archive_rule" "exception_tagged" {
  analyzer_name = aws_accessanalyzer_analyzer.this.analyzer_name
  rule_name     = "${var.name_prefix}-exception-approved"

  filter {
    criteria = "resourceTag/dp:exception:id"
    exists   = true
  }
}

# ---------------------------------------------------------------------------
# SNS topic for new findings
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "findings" {
  name              = "${var.name_prefix}-access-analyzer-findings"
  kms_master_key_id = var.sns_kms_key_id
  tags              = var.tags
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.findings.arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# EventBridge rule — route new ACTIVE findings to SNS
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "new_findings" {
  name        = "${var.name_prefix}-access-analyzer-findings"
  description = "Route new IAM Access Analyzer findings to SNS"
  tags        = var.tags

  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
    detail = {
      status = ["ACTIVE"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.new_findings.name
  target_id = "sns"
  arn       = aws_sns_topic.findings.arn
}
