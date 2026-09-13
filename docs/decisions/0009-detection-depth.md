# 0009 — Detection depth: baselines, sequences, and four bugs

Status: accepted
Date: 2026-09-14

## Context

Every detection through Week 12 was a windowed count against an absolute threshold. That leaves
two things permanently out of reach:

1. **Anything relative.** The population is skewed — the 95th-percentile account here is 4.2× the
   median — so one fixed threshold is either blind for the busy accounts or noisy for the quiet
   ones. Service accounts, which an attacker most wants, sit at the top of that distribution.
2. **Anything sequential.** `make score` had been reporting `session_hijack` at 50% recall for
   weeks and naming it as a gap. The attack never touches the login endpoint — the attacker starts
   with a stolen token — so there are no failed logins and no threshold to cross.

## Decisions

### Baselines reach the detector as a GlobalKTable, not a database query

`analytics/baseline.py` computes them into Postgres; `publish_baselines.py` publishes to a
compacted topic; the detector consumes that into a `GlobalKTable`.

- **Compacted, not retained.** This is a *table*. Compaction keeps the latest value per key
  forever, so a detector starting cold rebuilds the full set. Under a retention policy the
  quieter accounts would age out and the detector would come up silently knowing nothing about
  them.
- **Global, not a regular KTable.** The data is small, every task needs all of it, and a
  GlobalKTable needs no co-partitioning — so the event stream is not repartitioned to match it.
  Every instance holds a full copy, which is the right trade for reference data this size.
- **Not a Postgres lookup.** A per-event database call on a stream processor's hot path is how
  you acquire a latency problem that is very hard to see.

### Weak signals, scored rather than alerted

`baseline-deviation` fires on new country, new user agent, unusual hour, dormant reactivation.
None alone justifies waking anyone — a new country is a holiday, a new agent is a browser update.
Severity rises with how many are true at once (1 → LOW, 2 → MEDIUM, 3+ → HIGH) and the alerts
feed risk scoring. An account that is simultaneously in a new country, on a new device, at an
unusual hour, after ninety days of silence is a different proposition from any one of those.

### Sequence detection stays in code

`SessionHijackProcessor` compares a token issuance against later API activity. That is not
expressible in a format that asks "how many things happened in a window", and bending the DSL to
cover it would mean inventing a sequence language. Same boundary as impossible travel, drawn for
the same reason (ADR 0004).

## Result

Measured over a window the detector was demonstrably up for, all seven scenarios fired:

```
                        before        after
precision                92.6%        100.0%
recall                   91.7%        100.0%
session_hijack recall     50.0%       100.0%
```

## Four bugs, each of which produced confident nonsense

**1. Alert flood — 97% false positives.** The first session-hijack version fired on any address
change. 130 alerts, of which 126 were a user moving between two addresses in their own /24 — a
phone dropping to wifi, a DHCP lease. Precision about 3%.

Fix: compare the *network*, not the address. Removed all 126 without touching any of the 4 real
hijacks — an attacker with a stolen token is not on the victim's subnet.

**2. One attack manufacturing false positives in an unrelated rule.** A failed login is not
"succeeded", so it fell through to the session-use branch. A credential-stuffing run against 150
accounts then produced a session-hijack alert for every victim who happened to have a live
session: **52 alerts from one attack**, all describing something a different rule had already
reported correctly.

The general shape — one attack generating noise in a rule aimed at something else — is the same
failure impossible travel has with credential stuffing, and it is **invisible unless scenarios
are run together.** Testing rules one at a time would never have found it.

**3. A baseline computed over too short a window is not weak, it is misleading.** The baselines
had 7.7 hours of history, so `active_hours` was not "when this person works" but "when the
pipeline happened to be running". Every event outside it looked anomalous: **197 alerts, 197 of
them noise.**

Fix: the hour signal is ignored until the account has been observed across at least 12 distinct
hours. A short-window baseline fires hardest exactly when you have least reason to trust it.

**4. Deduplication silently downgraded severity.** Alerts dedupe on (rule, entity) while open, and
the update did not touch severity — so a HIGH firing was absorbed into an open LOW alert with the
occurrence count going up and the label unchanged. A genuinely worse situation sat in the console
still marked LOW.

Fix: severity escalates on merge, never downgrades. Observed live, on a three-deviation baseline
alert folded into a one-deviation one.

## Two traps that cost real time

**The HTTP proxy JSON-encodes the key.** Publishing with `vnd.kafka.json.v2+json` put
`"u-00000"` on the topic — quotes included — while the detector looked up `u-00000`. The
GlobalKTable was fully populated, every lookup missed, and the rule produced nothing with no
error anywhere. Fixed by using the binary format with base64, which hands over exact bytes.

**A GlobalKTable's store is timestamped.** `Materialized.as(...)` yields
`ReadOnlyKeyValueStore<K, ValueAndTimestamp<V>>`. Declaring it as `ReadOnlyKeyValueStore<K, V>`
compiles cleanly — generics are erased — and throws `ClassCastException` on the first lookup,
taking the stream thread down. Also: a global store must **not** be named in `process(...)`,
which is the opposite of the rule for ordinary stores.

## Known gaps

- **The scorer cannot distinguish "no rule covers this" from "no detector was running".** An
  attack fired during a restart is reported identically to one nothing detects. `--minutes` is a
  workaround; properly this wants detector uptime as an input, because "how much of last week
  were we actually watching" is a question a SOC has to answer.
- **No anomaly model.** The deviation signals are rule-based, not learned. A model would need far
  more history than this simulation has produced, and fitting one to 8 hours of data would
  reproduce bug 3 with more mathematics attached.
- **Baselines are only as fresh as the batch job.** Nothing recomputes them on a schedule yet
  outside the Airflow DAG, and `publish_baselines.py` is not in that DAG.
- `/24` is a crude proxy for "same network". The better version enriches each event with its ASN
  at ingest — the same conclusion as the wildcard-policy gap in ADR 0008: **enrichment at ingest
  beats cleverness in the rule.**
