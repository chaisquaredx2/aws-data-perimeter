locals {
  # Read all generated RCP JSON files from the policies directory
  policy_files = fileset(var.policy_dir, "rcp-*.json")

  policies = {
    for f in local.policy_files :
    trimsuffix(f, ".json") => file("${var.policy_dir}/${f}")
  }
}

resource "aws_organizations_policy" "rcp" {
  for_each = local.policies

  name        = "${var.name_prefix}-${each.key}"
  description = "Data perimeter ${each.key} - managed by Terraform"
  type        = "RESOURCE_CONTROL_POLICY"
  content     = each.value

  tags = {
    "managed-by" = "terraform"
    "component"  = "data-perimeter"
    "policy"     = each.key
  }
}

resource "aws_organizations_policy_attachment" "rcp" {
  for_each = {
    for pair in setproduct(keys(local.policies), var.target_ou_ids) :
    "${pair[0]}-${pair[1]}" => {
      policy_key = pair[0]
      target_id  = pair[1]
    }
  }

  policy_id = aws_organizations_policy.rcp[each.value.policy_key].id
  target_id = each.value.target_id
}
