variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "dp"
}

variable "lambda_source_dir" {
  description = "Path to the compliance_reporter Lambda source directory."
  type        = string
}

variable "analyzer_arn" {
  description = "ARN of the IAM Access Analyzer to query."
  type        = string
}

variable "sns_topic_arn" {
  description = "Optional SNS topic ARN for unresolved-finding alerts."
  type        = string
  default     = ""
}

variable "schedule_expression" {
  description = "EventBridge schedule (less frequent than exception enforcer since AA updates asynchronously)."
  type        = string
  default     = "rate(6 hours)"
}

variable "timeout_seconds" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 300
}

variable "memory_mb" {
  description = "Lambda memory in MB."
  type        = number
  default     = 256
}

variable "log_level" {
  description = "Python log level for the Lambda."
  type        = string
  default     = "INFO"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}
