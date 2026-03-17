variable "keys" {
  description = "Map of KMS key configurations. Key = alias suffix (e.g., 'analytics/production/data-lake')"
  type = map(object({
    data_zone           = string
    environment         = string
    project             = string
    description         = optional(string, "")
    deletion_window     = optional(number, 30)
    enable_key_rotation = optional(bool, true)
    additional_tags     = optional(map(string), {})
  }))
}

variable "alias_prefix" {
  description = "Prefix for KMS key aliases"
  type        = string
  default     = "alias/dp"
}
