data "aws_caller_identity" "current" {}

resource "aws_kms_key" "this" {
  for_each = var.keys

  description             = coalesce(each.value.description, "Data perimeter key: ${each.key}")
  deletion_window_in_days = each.value.deletion_window
  enable_key_rotation     = each.value.enable_key_rotation
  is_enabled              = true

  tags = merge(
    {
      "dp:data-zone"    = each.value.data_zone
      "dp:environment"  = each.value.environment
      "dp:project"      = each.value.project
      "managed-by"      = "terraform"
      "component"       = "data-perimeter"
    },
    each.value.additional_tags,
  )
}

resource "aws_kms_alias" "this" {
  for_each = var.keys

  name          = "${var.alias_prefix}/${each.value.data_zone}/${each.value.environment}/${each.value.project}"
  target_key_id = aws_kms_key.this[each.key].key_id
}
