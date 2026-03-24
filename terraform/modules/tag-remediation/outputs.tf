output "lambda_function_name" {
  description = "Name of the tag remediation Lambda function."
  value       = aws_lambda_function.this.function_name
}

output "lambda_function_arn" {
  description = "ARN of the tag remediation Lambda function."
  value       = aws_lambda_function.this.arn
}

output "api_gateway_url" {
  description = "Invoke URL for the Wiz webhook endpoint."
  value       = "${aws_api_gateway_deployment.this.invoke_url}${aws_api_gateway_stage.this.stage_name}/webhook"
}

output "api_key_id" {
  description = "ID of the API key (retrieve value from console or aws apigateway get-api-key --include-value)."
  value       = aws_api_gateway_api_key.wiz.id
}

output "sns_topic_arn" {
  description = "ARN of the remediation notifications SNS topic."
  value       = aws_sns_topic.remediation.arn
}
