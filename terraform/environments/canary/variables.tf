variable "aws_region" {
  description = "AWS region for provider"
  type        = string
  default     = "us-east-1"
}

variable "canary_ou_id" {
  description = "OU ID for canary testing"
  type        = string
}

variable "kms_keys" {
  description = "KMS keys to create in canary environment"
  type = map(object({
    data_zone           = string
    environment         = string
    project             = string
    description         = optional(string, "")
    deletion_window     = optional(number, 30)
    enable_key_rotation = optional(bool, true)
    additional_tags     = optional(map(string), {})
  }))
  default = {}
}

variable "exception_enforcer_enforce_removal" {
  description = "Whether the exception enforcer Lambda removes expired tags (false = dry-run)"
  type        = bool
  default     = false
}

variable "exception_enforcer_grace_period_hours" {
  description = "Hours after expiry before exception tags are removed"
  type        = number
  default     = 0
}
