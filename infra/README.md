# Infrastructure

Terraform for the cloud side, validated and applied against LocalStack.

```bash
make tf-validate     # fmt + init + validate
make tf-plan         # plan against LocalStack
make tf-apply        # apply against LocalStack
make tf-verify       # list what actually exists, and prove the IAM policies
make tf-destroy
```

Terraform runs in a container (`hashicorp/terraform:1.9`) on the compose network, so nothing is
installed on the host and the provider can reach `localstack:4566` by name.

## What `terraform apply` here does and does not prove

This is the part that matters, because "it applied against LocalStack" sounds like verification
and is only partly one.

**Really created, and verified afterwards:**

| resource | verified how |
|---|---|
| S3 buckets (trail + archive) | `awslocal s3 ls` |
| Public access blocks | applied |
| Bucket versioning | applied |
| SSE-KMS encryption | applied |
| KMS key + alias + rotation | applied |
| Bucket policy, incl. the Deny | `awslocal s3api get-bucket-policy` |
| IAM roles (3) | `awslocal iam list-roles` |
| Inline role policies | `awslocal iam get-role-policy` — the responder's Deny is read back |
| SNS topic | applied |
| CloudWatch log group | applied |

**Type-checked and planned, never applied:**

| resource | why |
|---|---|
| `aws_cloudtrail` | LocalStack community has no CloudTrail API — `CreateTrail` returns `UnrecognizedClientException` |
| `aws_cloudwatch_metric_alarm` ×2 | `cloudwatch` is `disabled` in LocalStack community; alarms are Pro |
| `aws_cloudwatch_log_metric_filter` ×2 | gated with the alarms they feed |
| `aws_s3_bucket_lifecycle_configuration` | the AWS provider fails against LocalStack with an empty error body — the identical rule applies cleanly via `awslocal s3api put-bucket-lifecycle-configuration`, so the configuration is right and the provider/emulator pairing is not |

Each is behind a variable defaulting to `!use_localstack`, so a real `terraform apply` creates
everything.

**Not proven by any of this:** that it works in AWS. LocalStack does not emulate IAM policy
evaluation, service quotas, cost, or eventual consistency. A `Deny` statement that LocalStack
stores happily may behave differently when AWS actually evaluates it.

## Two bugs worth keeping

**The bucket policy locked Terraform out of its own bucket.** The `DenyAuditTrailDeletion`
statement originally included `s3:PutLifecycleConfiguration` and `s3:PutBucketVersioning`.
Terraform applies the bucket policy before the lifecycle configuration, so the next resource was
refused by the policy just created.

The lesson generalises well past Terraform: **an explicit `Deny` on `Principal: "*"` applies to
the bucket owner and to whatever manages the infrastructure.** There is no implicit exemption for
"us". Protecting those actions is still the right instinct — it needs a condition exempting the
deployment principal, which is what `var.infrastructure_principal_arns` is for. Set it in a real
account and the configuration actions are protected too.

**S3 path-style addressing.** The provider resolves `bucket.host` by default, so it tried to look
up `bloodhound-lab-cloudtrail.localstack` and failed DNS. `s3_use_path_style` fixes it — the same
problem MinIO has, and the error names DNS rather than addressing, which sends you the wrong way.

## Design notes

**`is_multi_region_trail` and `include_global_service_events`.** Both are one line and both close
an entire blind spot. Without the first, a trail records only its own region and an attacker
working in an unused region is invisible. Without the second, IAM and STS events — most of what
is worth detecting — are missed entirely, because they are only ever emitted in `us-east-1`.

**Management events only.** Data events (every `GetObject`, every Lambda invoke) are orders of
magnitude higher volume and charged per event. Enabling them account-wide is a well-known way to
turn a logging bill into a budget incident; they are worth enabling selectively, on the buckets
holding something worth stealing.

**The responder role can stop but not grant.** `iam:UpdateLoginProfile` and `iam:UpdateAccessKey`
are enough to contain a compromised principal. `iam:CreateUser`, `iam:AttachUserPolicy` and
friends are explicitly denied even though they were never allowed. Compromising the containment
system therefore yields a denial-of-service capability, not privilege escalation — and that
asymmetry is the whole design.

**Trail retention is 365 days, log retention 90.** The interval between an intrusion and its
discovery is routinely measured in months. An investigation that begins in month seven against 90
days of logs finds nothing, and S3 is the cheapest tier in the architecture.

**Defence in depth on root usage.** The platform already detects root activity
(`aws-root-account-used`, T1078.004) and there is a CloudWatch alarm for it too. That duplication
is deliberate: the platform's detection depends on ingestion working, and the failure mode of a
detection pipeline is *silence*. An alarm inside AWS keeps firing when the pipeline is the thing
that broke.
