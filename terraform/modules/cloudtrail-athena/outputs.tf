output "workgroup_name" {
  description = "Name of the Athena workgroup."
  value       = aws_athena_workgroup.this.name
}

output "database_name" {
  description = "Name of the Glue catalog database."
  value       = aws_glue_catalog_database.this.name
}

output "named_query_ids" {
  description = "Map of query name to Athena named query ID."
  value       = { for k, v in aws_athena_named_query.this : k => v.id }
}

output "results_bucket_name" {
  description = "Name of the S3 bucket for query results."
  value       = aws_s3_bucket.results.id
}
