# 0008 — Cloud ingestion, and the cost of a mapping layer

Status: accepted
Date: 2026-09-13

## Context

Everything so far detected attacks against one simulated application, using events that
application emitted in exactly the shape the platform wanted. That is not what real security
engineering looks like. Real sources are someone else's data model, and getting them into a form
detections can reason about is most of the work.

CloudTrail is the honest test: a widely deployed, well documented, genuinely awkward source.

## Decision

### CloudTrail events join the existing stream, they do not get their own pipeline

`bloodhound-cloudtrail` translates records into ECS at the edge and publishes to
`security.events.raw`. Every detection, the risk model, incidents and response then apply to them
without modification — the `aws-root-account-used` alert flows into the same risk score as a
brute-force alert.

The alternative — a pipeline per source — is how SIEM deployments end up with rules that work on
one log source and not another, and why "we have CloudTrail" so often means "we store
CloudTrail".

### Mapping decisions, each of which is a trap

**Identity is modelled five different ways.** `user.id` has to mean the same thing across all of
them or per-user detection silently splits one actor into many.

| CloudTrail `userIdentity.type` | what is actually useful |
|---|---|
| `IAMUser` | `userName` — the obvious case, and the only obvious one |
| `AssumedRole` | `sessionContext.sessionIssuer.userName`, **not** `principalId` |
| `Root` | nothing is present; named explicitly because root usage is the highest-signal event AWS produces |
| `AWSService` | `invokedBy`; there is no user |
| federated / cross-account | the ARN |

`AssumedRole` is the one that bites. `principalId` is `AROAEXAMPLE:session-name`, so keying on it
gives the same role a **different `user.id` every session** — and a threshold rule counting per
user would never reach its threshold, while appearing to work. The role is the actor; the session
is evidence, kept in `labels`.

**A failed console login has no `errorCode`.** The result is in
`responseElements.ConsoleLogin`, the string `"Success"` or `"Failure"`. A mapper that checks only
`errorCode` records every failed console login as a **success** — exactly backwards, on the one
event type most worth alerting on.

**`sourceIPAddress` is not always an address.** For AWS-initiated calls it contains a service
principal: literally `"config.amazonaws.com"` where an IP belongs. Passed through, it reaches a
Postgres `inet` column, the insert fails, and the whole batch dead-letters — on events that are
not malformed at all. It is routed to `service.name` instead.

**Unmapped API names stay `UNKNOWN`.** AWS has thousands of API names and this platform's action
vocabulary has ten. Only the ones that genuinely mean the same thing are mapped; the rest keep
their exact name in `labels.cloud_event_name`, and the ingest endpoint reports which ones fell
through so coverage does not silently decay as AWS adds services.

The temptation is to force a mapping so nothing looks unhandled. That is worse: a rule matching
`permission-check` would start firing on unrelated AWS calls with no way to tell which. **Unmapped
and labelled is honest; mis-mapped is a detection that lies.**

**`eventID` is the dedupe key.** CloudTrail delivery is at-least-once, so an S3 object processed
twice must be absorbed by the primary key rather than double-counted by a threshold rule.

### Verified end to end

Nine sample records — real CloudTrail shapes, fake account ids — mapped and published:

```
user_id                      | action       | outcome | src           | aws_api
alice                        | user-login   | failure | 203.0.113.45  | ConsoleLogin
alice                        | user-login   | success | 203.0.113.45  | ConsoleLogin
root:123456789012            | user-login   | success | 198.51.100.77 | ConsoleLogin
role:platform-deploy         | token-issued | success | 198.51.100.77 | AssumeRole
role:platform-deploy         | role-change  | success | 198.51.100.77 | PutUserPolicy
role:platform-deploy         | api-key-used | success | 198.51.100.77 | CreateAccessKey
role:platform-deploy         | unknown      | failure | 198.51.100.77 | GetObject
service:config.amazonaws.com | unknown      | success | (null)        | PutEvaluations
role:platform-deploy         | unknown      | success | 198.51.100.77 | DeleteTrail
```

and two detections fired on them:

```
critical  aws-root-account-used     root:123456789012
medium    aws-iam-privilege-grant   role:platform-deploy
```

Eleven tests pin each mapping trap so a refactor cannot quietly undo one.

## Infrastructure

Terraform, applied against LocalStack. `infra/README.md` states precisely which resources were
really created and which were only type-checked, because "it applied against LocalStack" sounds
like verification and is only partly one.

The bug worth carrying forward: the audit bucket's `Deny` statement originally included
`s3:PutLifecycleConfiguration`, and Terraform applies the bucket policy before the lifecycle
rule — **the deployment locked itself out with the policy it had just written.** An explicit
`Deny` on `Principal: "*"` applies to the bucket owner and to whatever manages the
infrastructure; there is no implicit exemption for "us".

## Known gaps

- **The interesting IAM detection is not expressible.** A policy document granting `Action: "*"`
  on `Resource: "*"` is a JSON string inside `requestParameters`, and the rule format matches
  field equality, not structure. Catching it properly means the mapper extracting a
  `policy_grants_wildcard` field at ingest — which is the general shape of the answer:
  **enrichment at ingest, not cleverness in the rule.**
- **Delivery is HTTP, not S3.** Real CloudTrail lands in S3 and would be driven by an event
  notification or SQS. The mapping is identical; only the trigger differs.
- **Future-dated records advance stream time.** These samples are stamped ahead of the local
  clock, and Kafka Streams takes stream time from the data — so a source with a skewed clock can
  push windows forward and make legitimate events look late. Not yet handled, and a genuine
  evasion primitive.
- **No cross-account support.** One account id is assumed throughout.
- Nothing has been applied to real AWS.
