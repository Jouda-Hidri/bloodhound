# Bloodhound — 6-month roadmap

A week-by-week plan for building this platform, from ingestion through detection to response.

The project is the curriculum. Each week adds one capability the system does not yet have, and
the technology to learn that week is whatever that capability needs — not a syllabus worked
through in advance.

Start date: 2026-09-11.

---

## Status

Weeks 1–23 are built. This document stays written as a plan rather than a changelog: the
reasoning for each week is the point, and the headings carry what is done.

| | weeks | state |
|---|---|---|
| Month 1 — ingestion | 1–4 | built |
| Month 2 — data platform | 5–8 | built |
| Month 3 — detection engineering | 9–12 | built, and measured |
| Month 4 — scale and storage | 13–16 | built; bottleneck found and documented |
| Month 5 — response and cloud | 17–20 | built; Terraform validated but never applied to real AWS |
| Month 6 — depth and packaging | 21–24 | 21–23 built; Week 24 is not code |

The measured results live in [`performance.md`](performance.md) and
[ADR 0009](decisions/0009-detection-depth.md); the narrative is in
[`writeups/`](writeups/).

**Week 24 — packaging and applying — is the remaining work, and it is yours rather than the
codebase's.** The CV framing, the applications, the conversations. The repo is the evidence for
those, not a substitute.

✅ built  ⚠️ half built — see each week below.

---

## Ground rules

- **One repo, growing every week.** No restarts, no rewrites from scratch. The git history is
  half the portfolio — it shows how you think, not just what you produced.
- **Every week ends with something running.** `make up` plus the week's new piece, working.
- **Every week ends with a decision doc.** A short `docs/decisions/NNNN-*.md` naming the choice
  made and the tradeoff accepted. Writing it is what turns "it works" into "I understand it".
- **Learn the technology because the system needs it that week.** Not before.
- **Name your gaps.** When you defer something, record it in the README's gaps table with the
  week that closes it. Silent gaps read as ignorance; named gaps read as judgment.

### Weekly cadence — roughly 10–12 hours

| Hours | Activity |
|---|---|
| 2 | Learn the specific thing this week needs |
| 6 | Build |
| 2 | Break it deliberately, then fix it |
| 1 | Write the decision doc, commit |

### How to use AI on this project

Not as a code generator. As a senior engineer and an adversary:

> "Here's my architecture. Identify design problems. Don't write the solution."

> "Here's my implementation. Find race conditions, reliability problems, and data-quality bugs."

> "Give me three failure scenarios I should test." → then write the tests yourself.

> "Act as a security engineer. Threat-model this. Assume an attacker controls HTTP requests but
> has no server access. Rank attack paths by severity. Don't fix them."

> "Give me hints for fixing finding #2 without the implementation."

**At the end of each month**, paste the month's diff and ask what a staff engineer at a security
company would object to. Fix the top two objections yourself. That monthly review is where the
compounding happens.

---

## Month 1 — Ingestion

### Week 1 — Event model + producer ✅ done

**Build.** Spring Boot service emitting auth and API events. Docker Compose with Redpanda and
Postgres.

**Key decision made:** ECS field names (`@timestamp`, `user.id`, `source.ip`, `event.action`)
rather than invented ones, so the events work with OpenSearch and public Sigma rules later without
a translation layer. See `docs/decisions/0001-event-schema-and-transport.md`.

**Done when:** events land in a Kafka topic and `make tail-events` shows them.

### Week 2 — Consumer + storage ✅ code done

**Build.** Java consumer → Postgres, manual offset commits, daily range partitions, indexes on
`(user_id, ts)` and `(source_ip, ts)`. See `docs/decisions/0002-storage-and-delivery.md`.

**Still to do — this is the highest-ROI work in the whole plan:**

Learn SQL properly. Not "can write a SELECT" — actually properly:

- Window functions (`lag`, `lead`, `row_number`, `count() over`). The impossible-travel query in
  `sql/queries.sql` is built on `lag`; you should be able to write it from scratch.
- `EXPLAIN ANALYZE`. Read one. Understand Seq Scan vs Index Scan vs Bitmap Heap Scan, and what
  `Subplans Removed` means on a partitioned table.
- Index types: B-tree vs GIN (for `jsonb`) vs BRIN (for append-only time-series — relevant here).
- `filter (where ...)`, `distinct on`, CTEs, lateral joins.

Work through every query in `sql/queries.sql`. Then delete an index and watch the plan change.

**Done when:** you can answer "which accounts had more than 10 failed logins from more than
2 distinct IPs in any 5-minute window yesterday" without looking anything up.

### Week 3 — Schema contracts ✅ built

**Built.** JSON Schema registered and compatibility-checked at producer startup; the producer
refuses to boot on a breaking change. Avro was considered and rejected for debuggability. Redpanda's
registry turned out to reject any property named `id`, so Confluent's runs against Redpanda's
broker. See `docs/decisions/0003-schema-contracts.md` — the JSON Schema compatibility trap
documented there is the real lesson of this week.

**Still worth doing.** Nothing enforces that the schema file and the Java records agree. A test
that serialises a `SecurityEvent` and validates it against the schema would close that gap.

**Worth doing by hand anyway**, because reading about compatibility is not the same as watching it
refuse you: add a field, remove one, rename one, change a type, and see which the registry accepts.
`SchemaContract` will fail the producer's startup on the breaking ones.

### Week 4 — A continuous adversary ✅ built

**Build.** `AttackSimulator` fires scenarios on demand. Turn it into a background
adversary that runs continuously at a configurable intensity, mixing scenarios unpredictably.

Add scenarios: password spraying (one password, many accounts, slow enough to stay under
thresholds), session hijack (same session, new IP and user agent), dormant account reactivation,
privilege escalation attempt.

This is your test harness for the next five months. It deserves real effort.

**Done when:** you can run the platform for an hour unattended and afterwards ask the `labels`
ground-truth query what attacks happened.

---

## Month 2 — Making it a real data platform

### Week 5 — Correctness under failure ✅ built

**Build.** The dead-letter topic. Route unparseable and
unpersistable events to it with the failure reason attached, instead of dropping them.

Then deliberately inject, one at a time:

| Input | What should happen |
|---|---|
| Duplicate events | Absorbed by the dedupe key, counted as duplicates |
| Malformed JSON | DLQ with a reason, pipeline keeps running |
| Null required fields | DLQ, not a silent null row |
| Timestamps 3 days old | Correct partition, visible as high lag |
| Timestamps 3 days in the future | Something sensible — decide what |
| 10,000-event burst | Absorbed or backpressured, not lost |
| Postgres killed mid-batch | No data loss on restart, no duplicates |

**Done when:** every one of those is a test, not a manual experiment.

### Week 6 — Stream processing ✅ built

**Build.** Kafka Streams — stay in Java, you get windowing, state stores, and exactly-once
semantics without leaving your strength. Tumbling and sliding windows counting failed logins per
user and per source IP.

**Learn.** Event time vs processing time, watermarks, grace periods, late-arriving data. This
concept separates real data engineers from people who have "used Kafka". You already have the raw
material: `ts` and `ingested_at` are both stored precisely so you can reason about this.

**Done when:** an event arriving 60 seconds late still lands in the correct window, and you can
explain what happens to one arriving 60 minutes late.

### Week 7 — Python enters ✅ built

**Build.** Python for analytics: `psycopg`, `polars`, a notebook for exploring your own data.

Write a baseline job: per-account normal login hours, normal countries, normal user agents,
normal request volume. Store it in a `user_baseline` table.

**Done when:** you can plot the activity distribution across your 200 accounts and explain why a
threshold tuned on the median account fires constantly on the busiest one.

### Week 8 — Observability ✅ built

**Build.** Prometheus and Grafana. The consumer already exposes `bloodhound.events.ingested`,
`bloodhound.events.rejected`, and `bloodhound.ingest.batch` via Actuator — wire them up.

Dashboard: consumer lag, events/sec, processing latency p50/p95/p99, DLQ rate, duplicate rate,
default-partition row count.

**Done when:** you can point at a dashboard and say "throughput is X, lag is Y, and here is where
it breaks" — and the numbers are real, not estimated.

---

## Month 3 — Detection engineering

### Week 9 — Rule engine ✅ built

**Build.** Detections as data, not code. YAML rule files — threshold, window, group-by, filter,
severity — loaded at runtime.

Implement five: brute force, credential stuffing, impossible travel, privilege escalation
attempt, dormant account reactivation.

**Done when:** adding a detection is writing a YAML file, not a deploy.

### Week 10 — ATT&CK and Sigma ✅ built

**Build.** Map every rule to a MITRE ATT&CK technique ID. The simulator already emits them
(`T1110.001`, `T1110.004`, `T1078`); make the detections claim them too.

Convert two rules to Sigma format. Now you are speaking the industry's language, and public Sigma
rule libraries become usable against your data.

**Read.** *Practical Threat Detection Engineering* (Roberts & Brown), or Palantir's and Google's
published detection engineering writeups.

**Done when:** a security engineer reading your rules recognises the format.

### Week 11 — Alert quality ⚠️ half built — the week that matters most

**Build.** Alert deduplication, suppression windows, and a `false_positive` feedback table.

Then **measure your own rules** against the `labels` ground truth: precision, recall, false
positive rate per rule. You already know this is needed — the impossible-travel rule has known
false positives caused by the credential-stuffing scenario (see the README).

Tune. Record the tuning history.

**Why this week matters:** almost no portfolio project has this. *"My brute-force rule runs at 94%
precision and 3% false-positive rate against labelled attack traffic, and here's the tuning
history"* is an interview-winning sentence. "I built a SIEM" is not.

**Done when:** every rule has a number attached, and you can defend it.

### Week 12 — Risk scoring ✅ built

**Build.** Combine signals into a per-account risk score that decays over time. Alert on the score
crossing a threshold rather than on individual rule hits.

**Done when:** ten low-severity signals on one account produce one alert, not ten.

---

## Month 4 — Scale, search, and storage

### Week 13 — Search tier ✅ built

**Build.** OpenSearch for investigation queries. Split responsibilities: Postgres holds structured
state (alerts, incidents, baselines), OpenSearch holds raw events for free-text search.

**Learn.** Index lifecycle management, hot/warm tiers, why you would use each store. ECS field
names pay off here — the events go in unmodified.

### Week 14 — Object storage and lakehouse basics ✅ built

**Build.** MinIO (S3-compatible) + Parquet + Iceberg or Delta. Archive raw events to object
storage, query them with DuckDB or Trino.

**Learn.** Columnar formats, partitioning strategy, file sizing. Why 10,000 small files is a
disaster and how compaction fixes it.

### Week 15 — Orchestration ✅ built

**Built.** An Airflow DAG whose whole reason for existing is one edge: `tier_down` is reachable
only through `verify`, so retention cannot delete a day from Postgres until the archive has been
read back and checked. As independent `@Scheduled` timers, nothing stopped retention running
after a failed archive — silent, total data loss.

**Build.** Airflow or Dagster for the batch side: daily baseline rebuild, **retention enforcement
(drop partitions older than N days — currently they accumulate forever)**, data quality checks.

Quality checks: null rates, cardinality drift, freshness SLA, row-count anomalies.

### Week 16 — Load test ✅ built

**Build.** Push to 50,000 events/sec on your laptop. Find where it breaks. Profile it (async-profiler
or JFR). Fix one bottleneck. Measure again.

Handle backpressure properly — right now a slow Postgres just grows consumer lag forever.

**Done when:** `docs/performance.md` exists with numbers, flame graphs, and the fix. Java engineers
who can profile are valuable in every industry, not just this one.

---

## Month 5 — Response, IAM, and cloud

### Week 17 — Incident model ✅ built

**Build.** Alerts group into incidents. State machine: `new → triaged → investigating → contained
→ resolved`. Assignment, notes, timeline.

REST API plus a minimal UI — or just a Grafana/Metabase view. Do not sink a month into frontend.

### Week 18 — Response automation ✅ built

**Build.** Actions against **your own test systems only**: disable a test account, revoke a test
API key, force re-authentication, block an IP in your own service.

Every action needs an approval gate for anything destructive, a full audit log, and a reversal
path.

**Learn.** Why "automatically lock the account" is dangerous in production — an attacker who knows
your automation can weaponise it into a denial of service against real users. That nuance is what
security engineers are paid for.

### Week 19 — Secure your own platform ✅ built

**Built.** OIDC against Keycloak, with the API-key mode retained as a fallback. Audience is
validated, not just issuer. 401 and 403 mean different things. See
[ADR 0007](decisions/0007-identity.md) — including the `nobody` user, who authenticates perfectly
and is authorised for nothing.

**Build.** OIDC on both APIs (Keycloak locally), RBAC, secrets out of config into Vault or SOPS,
TLS everywhere, mTLS to Kafka. Both APIs currently have no authentication at all.

Threat-model the platform yourself. STRIDE is fine. Write it down.

### Week 20 — Cloud and infrastructure as code ⚠️ built, not applied to real AWS

**Build.** Terraform the whole thing onto AWS — MSK or self-managed Kafka, RDS, S3, ECS or EKS.
Use LocalStack if cost is a concern.

Then ingest **real** security logs: CloudTrail. Your detections now run on genuine cloud audit
data, not only synthetic traffic. Write the ECS mapping layer for it — that mapping is where most
real SIEM engineering effort actually goes.

**Learn.** IAM policies deeply. Write a detection for "IAM policy granted `*:*`".

---

## Month 6 — Depth, proof, and packaging

### Weeks 21–22 — Go deep on one axis ✅ built (detection depth)

Pick one. Depth in one area beats breadth across three.

- **Detection depth** — behavioural analytics, sequence detection, an ML anomaly model with
  honest evaluation against the labelled ground truth.
- **Scale depth** — Flink, exactly-once end to end, multi-region, backpressure under sustained
  overload.
- **Security depth** — attack the platform yourself: log injection, detection evasion, spoofed
  source IPs, timestamp manipulation to slip between windows. Then defend it.

### Week 23 — Prove it ✅ built

Three technical write-ups: the architecture, the detection-tuning results with real numbers, and
the failure-mode postmortems from Weeks 5 and 16.

Record a five-minute demo: attack fires → detection triggers → alert → incident → automated
containment → audit trail.

### Week 24 — Package for hiring

README with architecture diagram, quickstart, and an honest "what this does not do". The gaps
table already models this.

Map the work to job descriptions: Detection Engineer, Security Data Engineer, Security Platform
Engineer, Cloud Security Engineer. Rewrite your CV in those terms.

Start applying.

---

## What to deliberately skip

- **Certifications, for now.** Security+ is worth two weeks *after* Month 6 if you need to pass HR
  filters. OSCP is a different career — offensive, not defensive. Don't detour.
- **Scala and Spark.** Kafka Streams plus Python covers this. Add Spark only if job ads in your
  market demand it.
- **Building a real SIEM UI.** Grafana is enough. Frontend work here signals nothing about the
  skills you are selling.
- **Kubernetes before Month 5.** ECS or plain Compose is fine until then.
- **Six months of courses before writing code.** The order in this document is deliberate.

---

## Framing

Do not aim for "learn cybersecurity" — it is enormous and the goal is unfalsifiable.

Aim for:

> **"I build systems that collect, process, detect and respond to security events."**

That is a concrete technical identity. It pulls you into data engineering and security
simultaneously, and it is a role that exists and is hired for.
