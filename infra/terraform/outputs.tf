output "cloudtrail_bucket" {
  description = "Where CloudTrail delivers. The ingestion role reads from here."
  value       = aws_s3_bucket.cloudtrail.id
}

output "events_bucket" {
  description = "Archive bucket — the cloud equivalent of the local MinIO tier."
  value       = aws_s3_bucket.events.id
}

output "trail_name" {
  description = "Empty when the trail is not created (LocalStack)."
  value       = local.cloudtrail ? aws_cloudtrail.main[0].name : ""
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "ingest_role_arn" {
  description = "Assume this from bloodhound-cloudtrail. Read-only on the trail."
  value       = aws_iam_role.ingest.arn
}

output "responder_role_arn" {
  description = "Assume this for containment. Can stop principals, cannot grant anything."
  value       = aws_iam_role.responder.arn
}

output "kms_key_arn" {
  value = aws_kms_key.logs.arn
}
