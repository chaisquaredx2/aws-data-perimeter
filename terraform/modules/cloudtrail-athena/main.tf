# Data Perimeter — CloudTrail Athena Queries
#
# Pre-built named queries for investigating data perimeter policy denials,
# cross-account access patterns, network violations, and exception usage.
# Uses existing CloudTrail data — no new log collection required.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  database_name = replace("${var.name_prefix}_cloudtrail", "-", "_")
}

# ---------------------------------------------------------------------------
# S3 bucket for Athena query results
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "results" {
  bucket_prefix = "${var.name_prefix}-athena-results-"
  tags          = var.tags
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    id     = "expire-results"
    status = "Enabled"

    expiration {
      days = var.result_retention_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket = aws_s3_bucket.results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Athena workgroup with cost guardrails
# ---------------------------------------------------------------------------

resource "aws_athena_workgroup" "this" {
  name = "${var.name_prefix}-data-perimeter"
  tags = var.tags

  configuration {
    enforce_workgroup_configuration = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.results.id}/results/"
    }

    bytes_scanned_cutoff_per_query = var.bytes_scanned_cutoff
  }
}

# ---------------------------------------------------------------------------
# Glue catalog database and table for CloudTrail logs
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_database" "this" {
  name = local.database_name
}

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.this.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"                  = "cloudtrail"
    "projection.enabled"              = "true"
    "projection.date_partition.type"  = "date"
    "projection.date_partition.range" = "2020/01/01,NOW"
    "projection.date_partition.format" = "yyyy/MM/dd"
    "projection.date_partition.interval" = "1"
    "projection.date_partition.interval.unit" = "DAYS"
    "projection.region.type"          = "enum"
    "projection.region.values"        = "us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1,ap-northeast-1"
    "storage.location.template"       = "s3://${var.cloudtrail_s3_bucket}/${var.cloudtrail_s3_prefix}/$${region}/$${date_partition}"
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_s3_bucket}/${var.cloudtrail_s3_prefix}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
  }

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "date_partition"
    type = "string"
  }
}

# ---------------------------------------------------------------------------
# Named queries — one per .sql file in queries/
# ---------------------------------------------------------------------------

resource "aws_athena_named_query" "this" {
  for_each = fileset("${path.module}/queries", "*.sql")

  name      = "${var.name_prefix}-${trimsuffix(each.value, ".sql")}"
  workgroup = aws_athena_workgroup.this.name
  database  = aws_glue_catalog_database.this.name
  query     = templatefile("${path.module}/queries/${each.value}", {
    database = aws_glue_catalog_database.this.name
    org_id   = var.org_id
  })
}
