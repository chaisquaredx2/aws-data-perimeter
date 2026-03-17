variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "dp"
}

variable "lambda_source_dir" {
  description = "Path to the Lambda function source directory"
  type        = string
}

variable "schedule_expression" {
  description = "EventBridge schedule expression (e.g., 'rate(1 hour)')"
  type        = string
  default     = "rate(1 hour)"
}

variable "grace_period_hours" {
  description = "Hours after expiry before tags are removed (0 = immediate)"
  type        = number
  default     = 0
}

variable "notification_thresholds" {
  description = "Days before expiry to send notifications"
  type        = list(number)
  default     = [30, 14, 7, 1]
}

variable "enforce_removal" {
  description = "Whether to actually remove expired tags (false = dry-run)"
  type        = bool
  default     = true
}

variable "timeout_seconds" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 900
}

variable "memory_mb" {
  description = "Lambda memory in MB"
  type        = number
  default     = 512
}

variable "log_level" {
  description = "Lambda log level"
  type        = string
  default     = "INFO"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 90
}

variable "sns_kms_key_id" {
  description = "KMS key ID for SNS topic encryption (optional)"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
