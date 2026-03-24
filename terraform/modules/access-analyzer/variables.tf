variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "dp"
}

variable "analyzer_type" {
  description = "Type of analyzer: ORGANIZATION (org-wide) or ACCOUNT (single account)."
  type        = string
  default     = "ORGANIZATION"

  validation {
    condition     = contains(["ORGANIZATION", "ACCOUNT"], var.analyzer_type)
    error_message = "analyzer_type must be ORGANIZATION or ACCOUNT."
  }
}

variable "sns_kms_key_id" {
  description = "Optional KMS key ID to encrypt the SNS topic."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}
