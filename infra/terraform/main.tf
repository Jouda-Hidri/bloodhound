terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# LocalStack emulates the AWS APIs well enough to validate that this configuration is coherent —
# resources, references and IAM documents all resolve. It does not emulate cost, quotas, IAM
# evaluation, or the ways real AWS says no.
#
# So: `terraform apply` here proves the configuration is *valid*. It does not prove it works.
# That distinction is stated plainly rather than glossed, because "it applied against LocalStack"
# is exactly the kind of claim that sounds like verification and is not.
provider "aws" {
  region                      = var.region
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  # Real S3 addresses a bucket as a subdomain (bucket.s3.amazonaws.com). LocalStack serves
  # bucket-in-path, and without this the provider tries to resolve
  # `bloodhound-lab-cloudtrail.localstack` and fails DNS. Exactly the same problem MinIO has,
  # and the same fix — worth recognising, because the error names DNS and not addressing.
  s3_use_path_style = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      s3       = var.localstack_endpoint
      iam      = var.localstack_endpoint
      sts      = var.localstack_endpoint
      kms      = var.localstack_endpoint
      sqs      = var.localstack_endpoint
      sns      = var.localstack_endpoint
      logs     = var.localstack_endpoint
      events   = var.localstack_endpoint
      firehose = var.localstack_endpoint
    }
  }

  default_tags {
    tags = {
      Project     = "bloodhound"
      ManagedBy   = "terraform"
      Environment = var.environment
    }
  }
}

locals {
  name = "bloodhound-${var.environment}"

  # Alarms default to on for real AWS, off for LocalStack, unless explicitly set.
  cloudwatch_alarms = var.enable_cloudwatch_alarms != null ? var.enable_cloudwatch_alarms : !var.use_localstack
  cloudtrail        = var.enable_cloudtrail != null ? var.enable_cloudtrail : !var.use_localstack
  s3_lifecycle      = var.enable_s3_lifecycle != null ? var.enable_s3_lifecycle : !var.use_localstack
}
