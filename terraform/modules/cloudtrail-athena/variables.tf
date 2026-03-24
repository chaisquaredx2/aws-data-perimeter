variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "dp"
}

variable "cloudtrail_s3_bucket" {
  description = "Name of the S3 bucket containing CloudTrail logs."
  type        = string
}

variable "cloudtrail_s3_prefix" {
  description = "S3 key prefix for CloudTrail logs (typically 'AWSLogs')."
  type        = string
  default     = "AWSLogs"
}

variable "org_id" {
  description = "AWS Organization ID (used in query templates)."
  type        = string
}

variable "result_retention_days" {
  description = "Days to retain Athena query results in S3."
  type        = number
  default     = 30
}

variable "bytes_scanned_cutoff" {
  description = "Maximum bytes a single query can scan (cost guardrail)."
  type        = number
  default     = 10737418240 # 10 GB
}

variable "tags" {
  description = "Tags to apply to resources."
  type        = map(string)
  default     = {}
}
