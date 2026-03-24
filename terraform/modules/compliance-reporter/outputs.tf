output "lambda_function_name" {
  description = "Name of the compliance reporter Lambda function."
  value       = aws_lambda_function.this.function_name
}

output "lambda_function_arn" {
  description = "ARN of the compliance reporter Lambda function."
  value       = aws_lambda_function.this.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role."
  value       = aws_iam_role.lambda.arn
}
