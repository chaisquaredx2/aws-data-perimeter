output "analyzer_name" {
  description = "Name of the IAM Access Analyzer."
  value       = aws_accessanalyzer_analyzer.this.analyzer_name
}

output "analyzer_arn" {
  description = "ARN of the IAM Access Analyzer."
  value       = aws_accessanalyzer_analyzer.this.arn
}

output "findings_sns_topic_arn" {
  description = "ARN of the SNS topic for Access Analyzer findings."
  value       = aws_sns_topic.findings.arn
}
