# Data Perimeter — Canary Environment
#
# Deploy and validate policies here before promoting to other OUs.
# Rollout order: canary → shared_services → business_unit → internet_facing

module "scp_policies" {
  source = "../../modules/scp-policies"

  target_ou_ids = [var.canary_ou_id]
  policy_dir    = "${path.module}/../../policies"
  name_prefix   = "dp"
}

module "rcp_policies" {
  source = "../../modules/rcp-policies"

  target_ou_ids = [var.canary_ou_id]
  policy_dir    = "${path.module}/../../policies"
  name_prefix   = "dp"
}

module "kms_keys" {
  source = "../../modules/kms-keys"

  keys = var.kms_keys
}

module "exception_enforcer" {
  source = "../../modules/exception-enforcer"

  lambda_source_dir = "${path.module}/../../../lambda/exception_expiry_enforcer"
  name_prefix       = "dp-canary"
  enforce_removal   = var.exception_enforcer_enforce_removal
  grace_period_hours = var.exception_enforcer_grace_period_hours

  tags = {
    Environment = "canary"
    ManagedBy   = "terraform"
  }
}
