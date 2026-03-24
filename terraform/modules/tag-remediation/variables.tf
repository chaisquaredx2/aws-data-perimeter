variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "dp"
}

variable "lambda_source_dir" {
  description = "Path to the tag_remediation Lambda source directory."
  type        = string
}

variable "tag_lookup_url" {
  description = "Base URL of the Tag Lookup API (e.g. https://api.example.com)."
  type        = string
}

variable "sns_kms_key_id" {
  description = "Optional KMS key ID to encrypt the SNS topic."
  type        = string
  default     = null
}

variable "timeout_seconds" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 60
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
