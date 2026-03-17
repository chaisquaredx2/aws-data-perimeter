output "policy_ids" {
  description = "Map of policy name to policy ID"
  value = {
    for k, v in aws_organizations_policy.scp : k => v.id
  }
}

output "policy_arns" {
  description = "Map of policy name to policy ARN"
  value = {
    for k, v in aws_organizations_policy.scp : k => v.arn
  }
}

output "policy_names" {
  description = "List of generated policy names"
  value       = keys(aws_organizations_policy.scp)
}
