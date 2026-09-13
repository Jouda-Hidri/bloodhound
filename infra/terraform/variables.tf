variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "environment" {
  description = "Environment name, used as a suffix on every resource"
  type        = string
  default     = "lab"
}

variable "use_localstack" {
  description = "Point the provider at LocalStack instead of real AWS"
  type        = bool
  default     = true
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:4566"
}

variable "log_retention_days" {
  description = "CloudWatch log retention. Separate from trail retention on purpose."
  type        = number
  default     = 90
}

variable "trail_retention_days" {
  description = <<-EOT
    How long raw CloudTrail objects are kept in S3.

    365 days rather than the 90 that feels sufficient. The interval between an intrusion and its
    discovery is routinely measured in months, and an investigation that starts in month seven
    against ninety days of logs finds nothing. This is the cheapest tier of storage in the whole
    architecture; keeping it short saves very little and costs the thing the logs are for.
  EOT
  type        = number
  default     = 365
}

variable "alert_email" {
  description = "Where high-severity notifications go. Empty disables the subscription."
  type        = string
  default     = ""
}

variable "enable_cloudwatch_alarms" {
  description = <<-EOT
    Create the CloudWatch metric alarms.

    Defaults off under LocalStack because the community edition does not implement
    cloudwatch:PutMetricAlarm — it is a Pro feature. The alarm resources are still type-checked
    by `terraform validate` and appear in `terraform plan`; they are simply never applied here.

    That is a real limit on what this verification proves, and is stated rather than worked
    around. "It applied against LocalStack" is not the same claim as "it works".
  EOT
  type        = bool
  default     = null
}

variable "enable_cloudtrail" {
  description = <<-EOT
    Create the CloudTrail trail itself.

    Defaults off under LocalStack: the community edition does not implement the CloudTrail API
    at all, and returns `UnrecognizedClientException` for CreateTrail. The resource is still
    validated and planned; it is simply never applied here.

    So what `terraform apply` against LocalStack actually proves is narrower than it looks:
    the S3 buckets, bucket policies, KMS key, IAM roles and inline policies are really created
    and really resolve against each other. The trail, the metric filters and the alarms are
    type-checked and plan-checked only.
  EOT
  type        = bool
  default     = null
}

variable "infrastructure_principal_arns" {
  description = <<-EOT
    Principals exempt from the audit-bucket Deny statement — whatever deploys this.

    Empty by default, which narrows the Deny to data deletion only. Set it to the deployment
    role's ARN in a real account to also protect versioning and lifecycle configuration from
    being turned off, which is how an attacker makes the evidence expire rather than deleting it.
  EOT
  type        = list(string)
  default     = []
}

variable "enable_s3_lifecycle" {
  description = <<-EOT
    Create the S3 lifecycle configuration (tiering and expiry).

    Defaults off under LocalStack. The configuration is valid — the identical rule applies
    cleanly through `awslocal s3api put-bucket-lifecycle-configuration` against the same
    container — but the AWS Terraform provider fails on it with an empty error body, which is a
    provider/emulator incompatibility rather than a problem with the rule.

    Verified by hand rather than by apply, and listed as such in infra/README.md. Pretending
    `terraform apply` covered it would be the dishonest option.
  EOT
  type        = bool
  default     = null
}
