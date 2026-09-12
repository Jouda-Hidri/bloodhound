# Bloodhound

A security event detection and response platform, built from scratch as a learning vehicle for
data engineering and detection engineering.

The whole loop runs: simulated attacks produce events, a stream processor detects them, alerts
accumulate into risk, risk opens incidents, incidents propose containment, an approved containment
actually disables the account — and the account's next login attempt fails in the live event
stream, which trips a rule measuring whether the containment worked.

```
  bloodhound-producer ──▶ Redpanda ──▶ bloodhound-consumer ──▶ Postgres (raw_events)
   ├─ normal traffic       security      ├─ validate               daily partitions
   ├─ attack scenarios     .events.raw   ├─ dedupe             └──▶ OpenSearch (investigation)
   └─ lab IAM API                        └─ dead-letter
          ▲                                   │
          │                     bloodhound-detector (Kafka Streams)
          │                       ├─ 8 YAML rules, event-time windows
          │                       └─ impossible-travel processor
          │                                   │
          │                            security.alerts
          │                                   ▼
          │                     bloodhound-responder
          │                       ├─ deduplicate ──▶ risk score (decaying)
          │                       ├─ incident state machine
          │                       └─ response playbooks
          │                                   │
          └───────── containment ─────────────┘   (approval-gated, reversible, audited)
```

## Quick start

Needs Java 21, Docker, and Python 3 for the analytics.

```bash
make up          # Redpanda, Schema Registry, Postgres, Prometheus, Grafana
make build       # compile and test

# four terminals:
make consumer    # Kafka -> Postgres        (8102)
make detector    # detection engine         (8103)
make responder   # alerts, risk, response   (8104)
make producer    # traffic + lab IAM        (8101)
```

Then drive it:

```bash
make attack-all          # fire every scenario once
make alerts              # what fired
make risk                # who is most suspicious right now
make incidents           # what was opened
make pending             # containment waiting for a human
make approve ID=1        # execute it  (needs the responder key)
make contained           # the account is now disabled
make audit               # who did what, when
make revert ID=1         # undo
```

`make help` lists all 59 targets. `make adversary-on` runs attacks continuously in the background,
which is the only way to see what the platform looks like after a few hours of mixed traffic.

> **`make build` runs `clean`**, which deletes `target/` out from under any service you have
> running and kills it. When you have only touched one module, `make install-common` plus a
> restart of that service is enough.

### Ports

This machine has a lot bound already, so almost nothing uses its conventional port. Every one is
overridable by environment variable.

| | | why not the default |
|---|---|---|
| Producer + lab IAM | http://localhost:8101 | 8081 taken by another container |
| Consumer | http://localhost:8102 | |
| Detector | http://localhost:8103 | |
| Responder | http://localhost:8104 | |
| Redpanda console | http://localhost:8090 | 8080 taken |
| Grafana | http://localhost:3000 | |
| Prometheus | http://localhost:9091 | 9090 taken |
| Postgres | `localhost:5433` | 5432 taken |
| Kafka | `localhost:19092` | |
| Schema Registry | http://localhost:18085 | a `kubectl port-forward` binds 18081 |
| OpenSearch | http://localhost:9200 | `make up-search` |

Credentials are `bloodhound` / `bloodhound` for Postgres, and `bh-viewer-key` /
`bh-analyst-key` / `bh-responder-key` for the responder API.

## What each piece does

```
bloodhound-common/     ECS event schema, alert model, shared JSON config, topic names
bloodhound-producer/   simulated application: traffic, labelled attacks, lab IAM target
bloodhound-consumer/   ingest to Postgres + OpenSearch, DLQ, retention, data quality
bloodhound-detector/   Kafka Streams: YAML rules, windowing, Sigma export
bloodhound-responder/  alert dedup, risk scoring, incidents, response, audit, RBAC
analytics/             Python: behavioural baselines, detection scoring
ops/                   Prometheus rules, Grafana dashboards
docs/roadmap.md        the 24-week plan this is built against
docs/decisions/        why things are the way they are — read these
sql/queries.sql        analyst queries to run by hand
```

## The event schema

Elastic Common Schema field names, so the events work with OpenSearch and public Sigma rules
without a translation layer.

```json
{
  "@timestamp": "2026-09-12T14:48:33.363Z",
  "event":      { "id": "…", "category": "authentication",
                  "action": "user-login", "outcome": "failure",
                  "reason": "invalid password" },
  "user":       { "id": "u-00177", "name": "anna.beck", "domain": "bloodhound.lab" },
  "source":     { "ip": "198.51.100.195", "port": 51234,
                  "geo": { "country_iso_code": "RU", "city_name": "Moscow" } },
  "service":    { "name": "payment-api", "version": "0.1.0", "environment": "lab" },
  "user_agent": { "original": "python-requests/2.32.3" },
  "labels":     { "scenario": "brute_force", "run_id": "bf-1",
                  "attack_technique": "T1110.001" }
}
```

The schema is registered and compatibility-checked on startup. Rename a required field and the
producer refuses to boot — see [ADR 0003](docs/decisions/0003-schema-contracts.md), which also
documents the JSON Schema compatibility trap that makes the intuitive answer the wrong one.

`labels` is simulation ground truth. It exists so detections can be *scored*, not eyeballed.
**Detection logic must never read it** — only `analytics/score_detections.py` does.

## Detections

Eight rules in YAML plus one hand-written processor, covering seven ATT&CK techniques.

```bash
make rules       # what is loaded
make coverage    # ATT&CK coverage
make sigma       # export the rule set as Sigma
```

| rule | technique | entity | asks |
|---|---|---|---|
| `brute-force-single-account` | T1110.001 | user | many failures, one account |
| `distributed-brute-force` | T1110.001 | user | many *sources*, one account |
| `credential-stuffing-source` | T1110.004 | source_ip | many accounts, one source, fast |
| `password-spray-source` | T1110.003 | source_ip | many accounts, one source, slow |
| `privilege-escalation-probing` | T1068 | user | repeated authorization denials |
| `api-key-burst` | T1552.001 | user | key used at machine speed |
| `suspicious-password-change` | T1098 | user | credential change from a scripted agent |
| `contained-account-persistence` | T1078 | user | still trying after containment |
| `impossible-travel` (processor) | T1078 | user | two logins, two countries, minutes apart |

Rules are data; adding one is adding a file. The boundary — and what the format deliberately
cannot express — is in [ADR 0004](docs/decisions/0004-detection-as-data.md).

### Tests

`make build` runs 35 tests. Seven of them drive the real Kafka Streams topology through
`TopologyTestDriver`, which is where the detection logic is actually proven — the unit tests check
the pieces, but windowing, repartitioning, serdes and event-time extraction only misbehave in
combination. They cover threshold firing, distinct-count rules, attribution to the right entity,
attacks spread beyond the window, and a malformed record failing to kill the topology.

## Measuring whether any of it works

This is the part most portfolio projects skip.

```bash
make baseline    # rebuild per-account behavioural baselines
make score       # precision and recall against labelled ground truth
```

A representative run, seven scenarios fired against live background traffic:

```
Per rule                              alerts    TP    FP  precision
  brute-force-single-account               2     2     0     100.0%
  credential-stuffing-source               3     3     0     100.0%
  ...
Per attack scenario             runs  detected  missed    recall
  session_hijack                   2         1       1     50.0%
  ...
Overall
  precision  100.0%   (25 of 25 alerts landed on an entity under attack)
  recall      91.7%   (11 of 12 attack runs produced at least one alert)
  f1          95.7%
```

Read those numbers sceptically, and read the docstring in `score_detections.py` before quoting
them. Precision is flattered by entity-level attribution, and background traffic is not labelled
as benign ground truth — so real false positives need a human verdict, which is what
`make triage ID=<alert> VERDICT=false_positive` and the `triage` column are for.

`session_hijack` is genuinely undetected: nothing here catches a stolen token used from a new
address with no failed logins. That is a gap, not a rounding error.

## Deliberately unfinished

| gap | currently | planned |
|---|---|---|
| Auth | API keys in config, no expiry or rotation | OIDC + Keycloak (Week 19) |
| `block_source_ip` | recorded, no enforcement point | — |
| Approval | one click, one role | two-person rule for privileged accounts |
| Risk weights | chosen by judgement | measured |
| Baselines | computed, nothing reads them | baseline-relative rules |
| Wire format | JSON | Avro, if the size ever matters |
| Cloud | all local | Terraform + CloudTrail (Week 20) |
| Orchestration | Spring `@Scheduled` | Airflow/Dagster (Week 15) |
| Lakehouse | none | MinIO + Parquet + Iceberg (Week 14) |
| Load testing | none | 50k events/sec, profiled (Week 16) |

## Things that broke, and what they taught

Kept because the failures were the useful part:

- **A detection found a bug in the data generator.** `distributed-brute-force` flooded with false
  positives on ordinary users — the simulator drew a fresh random IP for *every event*, so any
  account with five failures looked attacked from five addresses. Source-diversity detection is
  untestable when the baseline already looks like an attack.
- **JSON Schema compatibility is inverted for open content models.** With
  `additionalProperties: true`, adding an optional field is "breaking" and removing a required one
  is "compatible" — the gate would wave through exactly the change that blinds your detections.
  ([ADR 0003](docs/decisions/0003-schema-contracts.md))
- **Redpanda's schema registry rejects any property named `id`.** ECS mandates `event.id` and
  `user.id`. Minimal repro in ADR 0003; the fix was Confluent's registry against Redpanda's broker.
- **Index templates only apply at index creation.** The indexer installed the template *after* its
  first successful write, so `source.ip` was typed `text` and CIDR queries silently returned zero.
  Dynamic mapping is sticky — the only fix is delete and reindex.
- **The scoring script under-reported recall by 3x.** It stopped at the first matching attack run,
  so when several scenarios hit one account the rest were reported undetected. A scoring bug that
  understates recall is more dangerous than a crash: it sends you tuning rules that were fine.
- **Kafka Streams processor names must be unique.** Naming repartitions after the `group_by` field
  on the assumption that rules would share them fails topology construction outright.
- **Broker auto-topic-creation silently broke the detector.** Redpanda created Streams' internal
  repartition topics with one partition before Streams could create them with six, and the client
  shut itself down: `invalid partitions: expected: 6; actual: 1`. Auto-creation is now off and all
  four topics are declared explicitly — which also means a typo in a topic name fails loudly
  instead of quietly publishing into a new topic nobody reads.
- **A data quality check that cried wolf.** `max_lag_seconds` failed on every attack, because the
  simulator back-dates a burst across the minutes it would really have taken — indistinguishable
  from pipeline lag. It now measures organic traffic only. A red light that means nothing is worse
  than no light, because people stop looking at it.

## Roadmap

Weeks 1–18 of [`docs/roadmap.md`](docs/roadmap.md) are substantially built. What remains is
Week 14 (lakehouse), Week 15's orchestrator, Week 16 (load testing), Week 19's real auth, Week 20
(cloud + CloudTrail), and Weeks 21–24 — depth, write-ups, packaging.
# bloodhound
# bloodhound
