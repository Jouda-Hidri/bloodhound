# ---------------------------------------------------------------------------
# Roles
#
# Two principals, each scoped to exactly what it does. The ingestion role can read the trail and
# nothing else; the response role can disable a user and nothing else. Neither can do the other's
# job, which is the point.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_to_logs" {
  name               = "${local.name}-cloudtrail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

data "aws_iam_policy_document" "cloudtrail_to_logs" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_logs" {
  name   = "write-logs"
  role   = aws_iam_role.cloudtrail_to_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_to_logs.json
}

# ---------------------------------------------------------------------------
# Ingestion role — what bloodhound-cloudtrail runs as
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ingest_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ingest" {
  name               = "${local.name}-ingest"
  assume_role_policy = data.aws_iam_policy_document.ingest_assume.json
}

data "aws_iam_policy_document" "ingest" {
  # Read-only on the trail. An ingestion component that can delete what it reads is an
  # ingestion component that an attacker uses to delete what it reads.
  statement {
    sid       = "ReadTrailObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.cloudtrail.arn, "${aws_s3_bucket.cloudtrail.arn}/*"]
  }

  statement {
    sid       = "WriteArchive"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.events.arn, "${aws_s3_bucket.events.arn}/*"]
  }

  statement {
    sid       = "UseEncryptionKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.logs.arn]
  }
}

resource "aws_iam_role_policy" "ingest" {
  name   = "read-trail-write-archive"
  role   = aws_iam_role.ingest.id
  policy = data.aws_iam_policy_document.ingest.json
}

# ---------------------------------------------------------------------------
# Response role — what containment runs as
# ---------------------------------------------------------------------------

resource "aws_iam_role" "responder" {
  name               = "${local.name}-responder"
  assume_role_policy = data.aws_iam_policy_document.ingest_assume.json
}

data "aws_iam_policy_document" "responder" {
  # The narrowest set of actions that can actually contain a compromised principal.
  #
  # Note what is absent: no iam:DeleteUser, no iam:PutUserPolicy, no iam:AttachUserPolicy. The
  # response role can *stop* a principal and cannot *grant* anything — so compromising the
  # containment system yields a denial-of-service capability, not a privilege-escalation one.
  # That asymmetry is the whole design.
  statement {
    sid    = "ContainCompromisedPrincipals"
    effect = "Allow"
    actions = [
      "iam:UpdateLoginProfile",
      "iam:DeleteLoginProfile",
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys",
      "iam:GetUser",
    ]
    resources = ["arn:aws:iam::*:user/*"]
  }

  statement {
    sid       = "PublishFindings"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  # Explicitly denied even though it was never granted. Belt and braces against a future edit
  # that widens the allow statement above without noticing what it lets in.
  statement {
    sid    = "NeverEscalate"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:AttachUserPolicy",
      "iam:PutUserPolicy",
      "iam:AttachRolePolicy",
      "iam:CreateAccessKey",
      "iam:CreatePolicyVersion",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "responder" {
  name   = "contain-only"
  role   = aws_iam_role.responder.id
  policy = data.aws_iam_policy_document.responder.json
}
