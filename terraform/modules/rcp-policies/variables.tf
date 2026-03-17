variable "target_ou_ids" {
  description = "List of OU IDs to attach RCPs to"
  type        = list(string)
}

variable "policy_dir" {
  description = "Directory containing generated JSON policy files"
  type        = string
  default     = "../../policies"
}

variable "name_prefix" {
  description = "Prefix for RCP names"
  type        = string
  default     = "dp"
}
