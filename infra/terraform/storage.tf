# ---------------------------------------------------------------------------
# CloudTrail delivery bucket
#
# The bucket an attacker most wants to empty. Every control here exists because deleting or
# altering the audit trail is a standard post-compromise step (MITRE T1070, "Indicator Removal"),
# and the platform has a detection for exactly that — which is worth nothing if the evidence it
# would have read is gone.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${local.name}-cloudtrail"
  force_destroy = var.environment == "lab"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    # Versioning is the control that makes "delete the logs" require deleting versions too,
    # which is a different permission and a far noisier operation.
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count = local.s3_lifecycle ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail.id

  # noncurrent_version_expiration is meaningless until versioning exists, and Terraform will
  # happily create both concurrently. Real AWS usually tolerates the race; LocalStack returned
  # an empty error body, which is a memorably unhelpful way to find an ordering bug.
  depends_on = [aws_s3_bucket_versioning.cloudtrail]

  rule {
    id     = "tier-then-expire"
    status = "Enabled"
    filter {}

    # The same tiering argument as the local lakehouse: recent data is queried, old data is
    # insurance. Glacier costs roughly a tenth of standard storage and takes minutes to restore,
    # which is irrelevant for an investigation that is already months late.
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = var.trail_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ---------------------------------------------------------------------------
# Encryption key
# ---------------------------------------------------------------------------

resource "aws_kms_key" "logs" {
  description             = "${local.name} CloudTrail and log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# ---------------------------------------------------------------------------
# Bucket policy
#
# Two statements, and the second is the interesting one.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid    = "AllowCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "AllowCloudTrailGetBucketAcl"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  # Deny beats Allow in IAM evaluation, unconditionally and regardless of what any other policy
  # grants. So this survives an attacker who gains the ability to attach themselves an
  # AdministratorAccess policy — which, per the sample CloudTrail data, is a step they actually
  # take. It cannot be overridden from inside the account; only by editing this policy, which is
  # itself an auditable event.
  #
  # The first version of this statement also denied s3:PutBucketVersioning and
  # s3:PutLifecycleConfiguration, and that was a self-inflicted lockout: Terraform applies the
  # bucket policy before the lifecycle configuration, so the very next resource was denied by
  # the policy that had just been created. `terraform apply` failed with an empty error body,
  # which reads like an emulator bug and is not one.
  #
  # The lesson generalises past Terraform. An explicit Deny on "*" applies to the bucket owner
  # and to whatever principal manages the infrastructure — there is no implicit exemption for
  # "us". Protecting the configuration actions as well is the right instinct, but it has to
  # carry a condition exempting the deployment principal, which means knowing that role's ARN.
  # See var.infrastructure_principal_arns.
  statement {
    sid    = "DenyAuditTrailDeletion"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = concat(
      [
        "s3:DeleteBucket",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
      ],
      # Only guarded when there is a principal to exempt, because otherwise this denies the
      # deployment itself.
      length(var.infrastructure_principal_arns) > 0 ? [
        "s3:PutBucketVersioning",
        "s3:PutLifecycleConfiguration",
      ] : [],
    )
    resources = [
      aws_s3_bucket.cloudtrail.arn,
      "${aws_s3_bucket.cloudtrail.arn}/*",
    ]

    dynamic "condition" {
      for_each = length(var.infrastructure_principal_arns) > 0 ? [1] : []
      content {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.infrastructure_principal_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}

# ---------------------------------------------------------------------------
# Archive bucket — the cloud equivalent of the local MinIO lakehouse tier
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "events" {
  bucket        = "${local.name}-events"
  force_destroy = var.environment == "lab"
}

resource "aws_s3_bucket_public_access_block" "events" {
  bucket                  = aws_s3_bucket.events.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "events" {
  bucket = aws_s3_bucket.events.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}
