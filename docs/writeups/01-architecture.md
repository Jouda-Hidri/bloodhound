# Building a security detection platform: the architecture, and why

The first of three write-ups on Bloodhound, a security event detection and response platform
built from scratch. This one covers the shape of the system and the decisions that determined it.
The [second](02-detection-quality.md) covers measuring whether the detections actually work; the
[third](03-postmortems.md) is a list of things that broke.

---

## What it does

Simulated applications emit security events. A stream processor detects attacks in them. Alerts
accumulate into a risk score per entity, risk opens incidents, incidents propose containment, and
an approved containment actually disables the account — after which that account's next login
fails in the live event stream, which trips a rule measuring whether the containment worked.

```
  producer ──▶ Redpanda ──▶ consumer ──▶ Postgres / OpenSearch / Parquet on S3
     ▲                          │
     │              detector (Kafka Streams)
     │                 ├─ 10 YAML rules, event-time windows
     │                 └─ 3 sequence processors
     │                          │
     │                   responder
     │                 ├─ deduplicate ──▶ decaying risk score
     │                 ├─ incident state machine
     │                 └─ response playbooks
     │                          │
     └────── containment ───────┘   approval-gated, reversible, audited
```

Six Java services, a Python analytics layer, and about a dozen containers.

## Five decisions that shaped everything else

### 1. Use somebody else's schema

Events are shaped to the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current):
`@timestamp`, `event.action`, `source.ip`, `user.id`.

Inventing `eventType` and `sourceIp` would have been marginally more natural to write and would
have cost a translation layer against OpenSearch, against published Sigma rules, and against
every future log source. The verbosity — `source.geo.country_iso_code` rather than `country` — is
the price, and it is small.

The payoff arrived in Week 20. CloudTrail ingestion needed a mapping layer, but everything
downstream of that mapping — every rule, the risk model, the incident workflow — worked on AWS
events without modification.

### 2. At-least-once delivery, with the database as the deduplicator

Offsets are committed by hand after the write succeeds. If the write fails, the offset is not
committed and Kafka redelivers. That guarantees no loss and guarantees some duplicates, and the
primary key `(event_id, ts)` with `ON CONFLICT DO NOTHING` makes the duplicate a no-op.

Exactly-once was rejected: it needs a transactional sink and roughly doubles the moving parts for
a guarantee that at-least-once plus an idempotent write already provides.

The consequence to notice is that the partition key has to be *in* the primary key — Postgres
requires it — which is why the dedupe key is composite rather than just `event_id`. That detail
turned out to matter for performance three months later.

### 3. Detections are data, up to a clearly drawn line

A rule is YAML: what to match, what to group by, a window, a threshold. Adding a detection is
adding a file.

The line is drawn at **aggregate over a window**. Anything stateful across events — impossible
travel, session hijack, baseline comparison — is a hand-written processor. Bending the rule
format to express sequences would have meant inventing a sequence language, and a DSL that grows
until it is a worse programming language is a well-known way for a project like this to fail.

Field paths are a closed set, validated at startup. A rule naming `user.emial` fails to load
rather than matching nothing forever. **A silently blind detection is worse than no detection,
because you believe you are covered.**

### 4. Three storage tiers, because they answer different questions

| tier | answers | cost per row |
|---|---|---|
| Postgres | "how many failures for this user in this window" | 1344 B |
| OpenSearch | "show me everything mentioning this address" | — |
| Parquet on object storage | "what happened in March" | 88 B |

15.3× cheaper per row, measured. The lake cannot answer a point lookup and does not need to.

Partitioning is by day, as directories. Measured over 60 day-partitions, a query filtered on the
partition columns is 10.4× faster than a full scan — while the same filter expressed on a *data*
column opens every file. A field in the partition key is nearly free to filter on; the same field
in a column is not.

### 5. Response proposes freely and executes reluctantly

**Response automation is a weapon pointed at your own users.** An attacker who works out that
twelve failed logins disables an account has been handed a way to lock out anyone they can name.

So: every action is written down before anything happens, destructive ones wait for a human,
unattended execution is off by default, account lockout is on a list that configuration cannot
override, and every action has a reversal path written before it shipped.

The role that can lock accounts out is deliberately the hardest to hold — it is the one an
attacker most wants, because it turns your own security tooling into their denial of service.

## Two things I would do differently

**Enrichment at ingest, not cleverness in the rule.** This came up three separate times and I
only recognised the pattern the third time.

- An IAM policy granting `Action: "*"` is a JSON string inside `requestParameters`; the rule
  format matches field equality, not structure.
- "Did the session move networks" is approximated with a `/24` comparison because the events do
  not carry an ASN.
- Baseline comparison needed a whole Kafka `GlobalKTable` to put per-account context next to each
  event.

All three want the same answer: compute the derived field once, at the edge, and let the rules
stay simple. Rules that reach for data they do not have are rules that will be subtly wrong.

**Measure before optimising, including the things that look obvious.** Consumer concurrency was 3
against a 6-partition topic — plainly wrong, and raising it to 6 was plainly right. I expected 2×
and got 1.24×, because the binding constraint was Postgres and the extra threads mostly queued
against each other. The fix was correct and the reasoning behind expecting it to help was not.

## What it is not

One machine, one realm, no MFA, no federation. Alarms and infrastructure validated against
LocalStack, never applied to real AWS. Response acts on a lab IAM service that refuses to touch
anything outside its own simulated population.

The gaps are listed in the README, each with the week that would close it. Naming them is
deliberate: silent gaps read as not knowing, named gaps read as having decided.

---

*Next: [how to tell whether any of it works](02-detection-quality.md).*
