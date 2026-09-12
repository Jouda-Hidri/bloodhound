# 0002 — Storage layout and delivery semantics

Status: accepted
Date: 2026-09-11

## Context

The consumer moves events from Kafka into Postgres. Two questions decide how it behaves under
failure: what happens to an offset when a write fails, and what the table looks like when it has
a billion rows in it.

## Decisions

### At-least-once delivery, with the database as the deduplicator

Offsets are committed by hand after the batch is written (`AckMode.MANUAL_IMMEDIATE`), not on a
timer. If the write fails, the offset is never committed and Kafka redelivers the batch.

That guarantees no event is lost, and guarantees some events arrive twice. The primary key
`(event_id, ts)` with `ON CONFLICT DO NOTHING` makes the second arrival a no-op.

Exactly-once was rejected: it requires a transactional sink and roughly doubles the moving parts,
for a guarantee that at-least-once + an idempotent write already provides in practice. Revisit
if a detection ever needs to count something the dedupe key cannot make idempotent.

### Both extracted columns and the full raw document

Hot fields become typed columns (indexed, fast to aggregate). The complete original ECS document
is kept in a `jsonb` column alongside them.

Columns are what detections query. `raw` is what an investigator reads at 3am when it turns out
the extraction dropped the field that mattered. Storing both roughly doubles the footprint, which
is the cheapest insurance in the system.

### Daily range partitions

Retention becomes `DROP TABLE partition` — instant, no bloat — instead of a `DELETE` that
rewrites the heap and leaves the table needing a vacuum. Time-bounded queries, which is nearly
all of them, prune to the days they touch.

Two consequences worth internalising:

1. **The partition key must be in the primary key.** That is why the dedupe key is
   `(event_id, ts)` rather than `event_id`. Postgres has no way to enforce global uniqueness
   across partitions otherwise. An event replayed with a *different* timestamp would therefore
   insert twice — acceptable here because `event_id` is generated with the timestamp and never
   regenerated.
2. **Partitions must exist before the data arrives.** An insert with no matching partition fails.
   `PartitionMaintenance` runs at startup and hourly to stay 7 days ahead.

### A default partition, reluctantly

`raw_events_default` catches events whose timestamp falls outside every existing partition, so a
badly-timestamped event fails one row rather than a whole batch.

The trap: once a row for day D sits in the default partition, day D's own partition can no longer
be attached. The maintenance job logs a warning when the default partition is non-empty, which is
the signal to move those rows out before it becomes a real problem.

### Event time and processing time are both stored

`ts` is when it happened, `ingested_at` is when we saw it. `ingested_at - ts` is pipeline lag.

Keeping both is what makes late and out-of-order data visible rather than silently wrong — and it
is the distinction Kafka Streams windowing (Week 6) is built around, so it is worth having the
data to reason about before then.

## Known gaps, deliberately left for later

- ~~**Unparseable events are dropped**, counted in `bloodhound.events.rejected` and logged. A
  dead-letter topic already exists (`security.events.raw.dlq`) but is unused. Week 5.~~
  **Closed 2026-09-12.** Parse, validation and persist failures are routed to the DLQ with the
  reason attached, archived to `dead_letters`, and replayable via `POST /dlq/replay`. A failing
  batch is retried once, then split so one poison record cannot take 499 healthy events with it.
- ~~**No retention job.** Partitions accumulate forever. Week 15.~~
  **Closed 2026-09-12.** `drop_old_event_partitions(retain_days, dry_run)` plus a daily scheduled
  job, off by default. `raw_events_default` is never dropped automatically — rows land there
  because something was wrong with them, and deleting the evidence is the opposite of the job.
- **No backpressure handling.** A slow Postgres just grows consumer lag. Still open — Week 16.
