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

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

module "cloudwatch_dashboard" {
  source = "../../modules/cloudwatch-dashboard"

  name_prefix                      = "dp-canary"
  aws_region                       = var.aws_region
  exception_enforcer_function_name = module.exception_enforcer.lambda_function_name
  access_analyzer_enabled          = var.enable_access_analyzer

  tags = {
    Environment = "canary"
    ManagedBy   = "terraform"
  }
}

module "access_analyzer" {
  source = "../../modules/access-analyzer"
  count  = var.enable_access_analyzer ? 1 : 0

  name_prefix   = "dp-canary"
  analyzer_type = "ACCOUNT" # Use ACCOUNT for canary; ORGANIZATION for prod

  tags = {
    Environment = "canary"
    ManagedBy   = "terraform"
  }
}

module "compliance_reporter" {
  source = "../../modules/compliance-reporter"
  count  = var.enable_access_analyzer ? 1 : 0

  lambda_source_dir = "${path.module}/../../../lambda/compliance_reporter"
  name_prefix       = "dp-canary"
  analyzer_arn      = module.access_analyzer[0].analyzer_arn
  sns_topic_arn     = module.access_analyzer[0].findings_sns_topic_arn

  tags = {
    Environment = "canary"
    ManagedBy   = "terraform"
  }
}

module "cloudtrail_athena" {
  source = "../../modules/cloudtrail-athena"
  count  = var.enable_cloudtrail_athena ? 1 : 0

  name_prefix          = "dp-canary"
  cloudtrail_s3_bucket = var.cloudtrail_s3_bucket
  org_id               = "o-abc123xyz"

  tags = {
    Environment = "canary"
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

module "tag_remediation" {
  source = "../../modules/tag-remediation"
  count  = var.enable_tag_remediation ? 1 : 0

  lambda_source_dir = "${path.module}/../../../lambda/tag_remediation"
  name_prefix       = "dp-canary"
  tag_lookup_url    = var.tag_lookup_url

  tags = {
    Environment = "canary"
    ManagedBy   = "terraform"
  }
}
