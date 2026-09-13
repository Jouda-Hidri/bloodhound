# ---------------------------------------------------------------------------
# The trail itself
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_cloudtrail" "main" {
  count = local.cloudtrail ? 1 : 0

  name                       = local.name
  s3_bucket_name             = aws_s3_bucket.cloudtrail.id
  kms_key_id                 = aws_kms_key.logs.arn
  enable_log_file_validation = true

  # Without this, a trail records only the region it was created in — and an attacker operating
  # in a region nobody uses is invisible. Enabling it is one line and closes an entire blind spot.
  is_multi_region_trail = true

  # Global service events (IAM, STS, CloudFront) are emitted in us-east-1 regardless of where
  # anything else runs. A trail without this misses every IAM change, which is most of what is
  # worth detecting.
  include_global_service_events = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_logs.arn

  event_selector {
    read_write_type = "All"

    # Management events only. Data events (every S3 GetObject, every Lambda invoke) are
    # enormously higher volume and charged per event — enabling them across all buckets is a
    # well-known way to turn a logging bill into a budget incident. They are worth enabling
    # selectively, on the buckets that hold something worth stealing.
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ---------------------------------------------------------------------------
# Notification path for high-severity findings
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.logs.arn
}

resource "aws_sns_topic_subscription" "alerts_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# A CloudWatch metric filter for root usage, as defence in depth.
#
# The platform already detects this (aws-root-account-used, T1078.004). Doing it here as well is
# deliberate: the platform's detection depends on ingestion working, and the failure mode of a
# detection pipeline is silence. A filter inside AWS keeps firing when the pipeline is the thing
# that is broken.
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  count = local.cloudwatch_alarms ? 1 : 0

  name           = "${local.name}-root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "Bloodhound/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  count = local.cloudwatch_alarms ? 1 : 0

  alarm_name          = "${local.name}-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.root_usage[0].metric_transformation[0].name
  namespace           = "Bloodhound/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Root account activity. There is no normal volume of this."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# The trail being switched off is itself the alert. An attacker who disables logging has told
# you more than the logs would have.
resource "aws_cloudwatch_log_metric_filter" "trail_tampering" {
  count = local.cloudwatch_alarms ? 1 : 0

  name           = "${local.name}-trail-tampering"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") }"

  metric_transformation {
    name      = "TrailTampering"
    namespace = "Bloodhound/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "trail_tampering" {
  count = local.cloudwatch_alarms ? 1 : 0

  alarm_name          = "${local.name}-trail-tampering"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.trail_tampering[0].metric_transformation[0].name
  namespace           = "Bloodhound/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CloudTrail was stopped, deleted or reconfigured."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}
