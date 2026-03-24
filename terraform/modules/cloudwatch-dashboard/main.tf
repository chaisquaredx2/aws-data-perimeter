# Data Perimeter — CloudWatch Dashboard
#
# Surfaces exception lifecycle metrics, Lambda health, and (optionally)
# Access Analyzer compliance metrics on a single pane of glass.

locals {
  dashboard_name = "${var.name_prefix}-data-perimeter"

  # Exception lifecycle widgets (always present)
  exception_widgets = [
    {
      type   = "metric"
      x      = 0
      y      = 0
      width  = 12
      height = 6
      properties = {
        title   = "Exception Lifecycle"
        region  = var.aws_region
        view    = "timeSeries"
        stacked = false
        period  = 300
        stat    = "Average"
        metrics = [
          ["DataPerimeter/Exceptions", "active"],
          ["DataPerimeter/Exceptions", "expiring_soon"],
          ["DataPerimeter/Exceptions", "expired"],
          ["DataPerimeter/Exceptions", "revoked"],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 0
      width  = 6
      height = 6
      properties = {
        title   = "Exceptions Revoked (24h)"
        region  = var.aws_region
        view    = "singleValue"
        period  = 86400
        stat    = "Sum"
        metrics = [
          ["DataPerimeter/Exceptions", "revoked"],
        ]
      }
    },
    {
      type   = "metric"
      x      = 18
      y      = 0
      width  = 6
      height = 6
      properties = {
        title   = "Expiring Soon"
        region  = var.aws_region
        view    = "singleValue"
        period  = 300
        stat    = "Maximum"
        metrics = [
          ["DataPerimeter/Exceptions", "expiring_soon"],
        ]
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 6
      width  = 12
      height = 6
      properties = {
        title   = "Exception Enforcer Lambda Errors"
        region  = var.aws_region
        view    = "timeSeries"
        stacked = false
        period  = 300
        stat    = "Sum"
        metrics = [
          ["AWS/Lambda", "Errors", "FunctionName", var.exception_enforcer_function_name],
          ["AWS/Lambda", "Invocations", "FunctionName", var.exception_enforcer_function_name],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 6
      width  = 12
      height = 6
      properties = {
        title   = "Exception Enforcer Duration"
        region  = var.aws_region
        view    = "timeSeries"
        stacked = false
        period  = 300
        stat    = "Average"
        metrics = [
          ["AWS/Lambda", "Duration", "FunctionName", var.exception_enforcer_function_name],
        ]
      }
    },
  ]

  # Access Analyzer / compliance reporter widgets (conditional)
  compliance_widgets = var.access_analyzer_enabled ? [
    {
      type   = "metric"
      x      = 0
      y      = 12
      width  = 12
      height = 6
      properties = {
        title   = "Access Analyzer Findings"
        region  = var.aws_region
        view    = "timeSeries"
        stacked = true
        period  = 3600
        stat    = "Maximum"
        metrics = [
          ["DataPerimeter/Compliance", "UnresolvedFindings"],
          ["DataPerimeter/Compliance", "ExceptionCoveredFindings"],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 12
      width  = 6
      height = 6
      properties = {
        title   = "Unresolved Findings"
        region  = var.aws_region
        view    = "singleValue"
        period  = 3600
        stat    = "Maximum"
        metrics = [
          ["DataPerimeter/Compliance", "UnresolvedFindings"],
        ]
      }
    },
    {
      type   = "metric"
      x      = 18
      y      = 12
      width  = 6
      height = 6
      properties = {
        title   = "External Access (Total)"
        region  = var.aws_region
        view    = "singleValue"
        period  = 3600
        stat    = "Maximum"
        metrics = [
          ["DataPerimeter/Compliance", "ExternalAccessFindings"],
        ]
      }
    },
  ] : []
}

resource "aws_cloudwatch_dashboard" "data_perimeter" {
  dashboard_name = local.dashboard_name
  dashboard_body = jsonencode({
    widgets = concat(local.exception_widgets, local.compliance_widgets)
  })
}
