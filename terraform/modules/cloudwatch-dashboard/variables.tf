variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "dp"
}

variable "aws_region" {
  description = "AWS region for metric widgets."
  type        = string
  default     = "us-east-1"
}

variable "exception_enforcer_function_name" {
  description = "Name of the exception enforcer Lambda function (for error widget)."
  type        = string
}

variable "access_analyzer_enabled" {
  description = "Whether to include Access Analyzer / compliance reporter widgets."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}
