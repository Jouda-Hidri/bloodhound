# 0005 — Risk, incidents, and response automation

Status: accepted
Date: 2026-09-12

## Context

Detections produce alerts. Alerts are not decisions. This ADR covers what happens between an alert
firing and an account being locked — and why most of that distance is deliberately made hard to
cross quickly.

## The governing principle

**Response automation is a weapon pointed at your own users.**

An attacker who works out that twelve failed logins disables an account has been handed a way to
lock out anyone they can name. Every automatic containment decision has to be justified against
that, and for account lockout the honest answer is "not without a human".

So: **propose freely, execute reluctantly.** Every action is written down before anything happens,
destructive ones wait for approval, and the reversal path exists before the action does.

## Decisions

### Alerts deduplicate on (rule, entity) while the condition is open

A partial unique index — `unique (dedupe_key) where active` — is the deduplication. Repeat firings
increment `occurrences` on one row instead of creating hundreds.

Alert fatigue is the most common way a real detection programme dies, and it dies at this index.

A sweeper closes alerts with no activity in the suppression window, which is what lets the
condition alert again later. Suppression that never expires is not suppression, it is deafness.

### Risk is per entity, accumulates across rules, and decays

Individual alerts are a poor basis for decisions: most are individually unconvincing, and the
interesting entities are the ones setting off several different weak signals at once. A decaying
score turns "seven separate medium alerts" into one ranked question.

- **Severity weights are non-linear** (info 1, low 5, medium 15, high 40, critical 100). Ten low
  alerts should not equal one critical: "lots of small things" and "one very bad thing" are
  different situations, and a linear scale conflates them.
- **Repeat occurrences add sub-linearly** (`weight / sqrt(occurrence)`). The tenth firing of one
  rule is far less informative than the first, and linear accumulation would let a single chatty
  rule drive an entity to maximum risk alone — defeating the point of a multi-signal score.
- **Decay is exponential, applied on read**, not by a sweeper. On-read decay means the score is
  correct whenever anyone looks, including right after a restart, and there is no background job
  to fall behind.
- **Scores are capped**, so one noisy rule cannot push an entity permanently off the scale.

Decay is what stops risk being a permanent mark. An account that looked bad last Tuesday and has
been quiet since should not still rank as suspicious, or every score converges on maximum and the
ranking stops distinguishing anything.

### The entity type decides what response is even appropriate

A brute-force alert is about an **account under attack**. A credential-stuffing alert is about
**hostile infrastructure**. Responding to them identically would mean locking the victim in one
case and the attacker in the other.

Credential stuffing is therefore attributed to `source_ip`, not to the thirty accounts it touched
— locking those would mean denying service to thirty innocent users on the attacker's behalf.

### One open incident per entity

A partial unique index again: `unique (entity_type, entity_id) where status not in (resolved,
false_positive)`. A sustained attack produces one investigation that accumulates evidence, not a
ticket every five minutes.

The index is also what settles the race: two alerts for one entity arriving concurrently would
both see "no incident" and both insert. The database is the only place that can be resolved.

### The incident state machine is enforced, not conventional

`new → triaged → investigating → contained → resolved`, with `false_positive` as an alternative
terminal state. Illegal transitions are rejected.

An incident that can jump from `new` straight to `resolved` is a ticket, not an investigation. The
value of the intermediate states is that they force somebody to have actually looked.

Resolved and false-positive are terminal with no reopen path: if it comes back, it is a new
incident with a new timeline, and the old one stays as the record of what was concluded and when.

### Containment is tiered by blast radius

| action | approval | reversible | when |
|---|---|---|---|
| `revoke_sessions` | not required | partially | session-compromise signals (T1078/T1539/T1098) |
| `disable_account` | **always** | yes | risk ≥ containment threshold, or CRITICAL |
| `block_source_ip` | required | yes | HIGH severity on a source entity |

Session revocation is the right first move for suspected token theft: it evicts an attacker
holding a stolen session while leaving the legitimate owner able to log straight back in. Account
lockout contains the attacker by also denying the user, which is why it is gated.

`auto-execute` is off by default, and `disable_account` is on an `always-require-approval` list
that a misconfiguration cannot override.

### Every action has a reversal path, written before it ships

Response automation without an undo is a one-way door, and the first false positive that locks out
a real user at 3am is not the moment to be writing one.

Where reversal is not literally possible it says so rather than claiming an effect: revoked
sessions cannot be un-revoked, so reverting records the decision and notes that the user may
re-authenticate.

### Containment acts on a real system, through HTTP

The producer exposes a lab IAM API, and disabling an account there actually changes its behaviour:
that account's logins start failing with `account disabled`, visible in the event stream within
seconds, and the `contained-account-persistence` rule fires on continued attempts.

Without a real target, "response automation" is a row written to a table. Keeping it behind an
HTTP boundary rather than an in-process call is also deliberate — it forces the responder to deal
with the failure modes real containment has: timeouts, partial success, an IAM system that is down
exactly when it is needed.

**Safety:** `LabIamService` refuses to act on anything outside the simulated `bloodhound.lab`
population. There is no code path from an alert to anything outside that JVM.

### The audit log is append-only

No update path, no delete path. On a platform that can disable accounts, the audit log is the only
way to answer "why was this user locked out at 3am", and the only defence if the automation itself
is ever abused. An audit log that can be edited answers no question worth asking.

A failed audit write is logged loudly but does not fail the action that already happened — that
would leave the world changed and no record either way.

### RBAC: three roles, API keys

`VIEWER` reads, `ANALYST` triages and moves incidents, `RESPONDER` approves containment.

This is lab-grade and says so: keys live in configuration, never expire, cannot be rotated without
a restart, and a shared key means the audit trail can only say "someone holding the responder key".
Proper OIDC against Keycloak is the remaining Week 19 work.

What it does get right is least privilege — and the response role is the one an attacker most
wants, because it turns your own security tooling into their denial of service.

## Known gaps

- `block_source_ip` has no enforcement point. It is recorded, not performed, and says so in the
  result rather than pretending.
- Approval is a single click by a single role. Real containment of a privileged account should
  need two people.
- Risk weights and both thresholds were chosen by judgement, not measured. `analytics/score_detections.py`
  measures detection quality; nothing yet measures whether the risk model ranks the right entities.
- Nothing expires an incident. A `new` incident nobody touches stays `new` forever.
