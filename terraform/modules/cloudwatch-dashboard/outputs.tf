output "dashboard_name" {
  description = "Name of the CloudWatch dashboard."
  value       = aws_cloudwatch_dashboard.data_perimeter.dashboard_name
}

output "dashboard_arn" {
  description = "ARN of the CloudWatch dashboard."
  value       = aws_cloudwatch_dashboard.data_perimeter.dashboard_arn
}
