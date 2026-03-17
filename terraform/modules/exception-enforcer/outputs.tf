output "lambda_function_name" {
  description = "Name of the exception enforcer Lambda function"
  value       = aws_lambda_function.enforcer.function_name
}

output "lambda_function_arn" {
  description = "ARN of the exception enforcer Lambda function"
  value       = aws_lambda_function.enforcer.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda.arn
}

output "sns_topic_arn" {
  description = "ARN of the exception alerts SNS topic"
  value       = aws_sns_topic.exception_alerts.arn
}

output "audit_table_name" {
  description = "Name of the DynamoDB audit table"
  value       = aws_dynamodb_table.audit.name
}

output "audit_table_arn" {
  description = "ARN of the DynamoDB audit table"
  value       = aws_dynamodb_table.audit.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge schedule rule"
  value       = aws_cloudwatch_event_rule.schedule.arn
}
