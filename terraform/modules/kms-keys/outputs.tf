output "key_arns" {
  description = "Map of key name to KMS key ARN"
  value = {
    for k, v in aws_kms_key.this : k => v.arn
  }
}

output "key_ids" {
  description = "Map of key name to KMS key ID"
  value = {
    for k, v in aws_kms_key.this : k => v.key_id
  }
}

output "key_aliases" {
  description = "Map of key name to KMS alias name"
  value = {
    for k, v in aws_kms_alias.this : k => v.name
  }
}
