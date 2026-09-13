# Performance

Week 16. Measured on a MacBook with Docker limited to 7.7 GB, everything on one machine —
Redpanda, Postgres and four JVMs competing for the same cores. Treat the absolute numbers as
specific to that, and the *shape* of the results as the point.

Reproduce with:

```bash
make load-ramp                    # step through rates until it stops keeping up
make load-sustain RATE=5000       # hold a rate and watch whether lag grows
make load-report                  # previous runs
```

## Where it gives out

| offered | achieved | keeping up | max lag | batch latency |
|---:|---:|---:|---:|---:|
| 20/s | 20/s | 100% | 0.06s | 4.5ms |
| 200/s | 200/s | 100% | 0.07s | 4.6ms |
| 1,000/s | 1,001/s | 100% | 0.07s | 5.0ms |
| 2,500/s | 2,506/s | 100% | 0.32s | 6.4ms |
| 5,000/s | 4,999/s | 100% | 0.32s | 8.3ms |
| **10,000/s** | **5,090/s** | **51%** | 12.6s | 15.1ms |
| 20,000/s | 2,672/s | 13% | 67.9s | 24.6ms |

**Clean to 5,000 events/sec.** Above that it falls behind, and at 20,000 it achieves *less* than
at 10,000 — throughput going backwards under increasing load is congestion collapse, not a
plateau.

## Am I measuring the pipeline or the load generator?

The first question to ask of any of those numbers, and the one most easily skipped.

At 20,000/s offered:

```
producer actually emitted:   20,583/s
consumer actually ingested:   2,533/s
```

The generator is fine. The pipeline is the constraint. Had these been close, every number above
would have been a measurement of my own test harness.

This is also why `loadtest.py` reads the pipeline's own Micrometer counters rather than counting
what it sent. A generator reporting its own throughput while the consumer silently falls behind
is measuring nothing at all.

## Which part of the pipeline

Isolated by disabling one component at a time:

| configuration | ingest rate | batch latency |
|---|---:|---:|
| search indexing on | 2,533/s | 24.6ms |
| search indexing off | 3,650/s | 474ms |
| search off, concurrency 3 → 6 | 4,517/s | 744ms |

Two things worth reading carefully.

**OpenSearch indexing costs about 30%**, and it degrades the right way: the indexer drops batches
rather than slowing ingestion, so search coverage is lost before the pipeline of record is. That
was the design intent (ADR 0006) and the load test confirms it behaves that way under pressure.

**Batch latency rises as concurrency rises.** 474ms at 3 threads, 744ms at 6. The threads are not
waiting on Kafka; they are queueing behind each other at Postgres.

Throughput tracks `concurrency × (batch size / batch latency)` almost exactly:

```
3 threads: 3 × (500 / 0.474) = 3,165/s   observed 3,650/s
6 threads: 6 × (500 / 0.744) = 4,032/s   observed 4,517/s
```

## The fix, and why it under-delivered

Consumer concurrency was 3 against a 6-partition topic — half the partitions unserved for no
reason. Raising it to 6 was obviously right and I expected roughly 2×.

**It gave 1.24×.** 3,650/s → 4,517/s.

That is the useful result. The thread count was never the binding constraint; Postgres was.
Doubling the consumers mostly moved the queue from inside Kafka to inside the database. Adding
capacity upstream of a bottleneck buys very little, and the only way to know which side of it you
are on is to measure before and after.

## What Postgres is actually doing

Today's partition, 2.37M rows total:

| index | size |
|---|---:|
| `raw_events_..._pkey` on `(event_id, ts)` | **173 MB** |
| `(event_action, event_outcome, ts)` | 148 MB |
| `(user_id, ts)` | 110 MB |
| `(source_ip, ts)` | 109 MB |

Four indexes maintained on every insert, and the primary key is the largest of them — which it
has to be probed on for every row, because `ON CONFLICT (event_id, ts) DO NOTHING` is what makes
the pipeline idempotent (ADR 0002).

**The primary key is oversized by a decision made in Week 2.** `event_id` is `text`, so a UUID
occupies 37 bytes where the native `uuid` type would take 16. ADR 0002 chose `text` deliberately,
to tolerate producers whose ids are not UUIDs, and recorded the trade as "16 bytes vs 36". The
load test turns that from a footnote into a number: on this table it is roughly 100 MB of extra
index per day, probed on every insert.

That does not make the original decision wrong — CloudTrail ids happen to be UUIDs, but a future
source's may not be. It makes it *costed*, which it was not before.

## What I would do next, in order

1. **`event_id` as `uuid`, with a text fallback column.** Smaller PK, faster probe. The tolerance
   ADR 0002 wanted can be kept by validating at the edge and dead-lettering non-UUID ids, which
   the DLQ already does for everything else.
2. **Drop `(event_action, event_outcome, ts)`.** 148 MB maintained on every insert to serve
   queries the detector no longer runs — it works from Kafka Streams state, not from Postgres.
   This index is paying rent for a tenant that moved out.
3. **`COPY` instead of batched `INSERT`.** Bypasses per-row parse and plan overhead. Complicates
   `ON CONFLICT`, so it needs a staging table and a merge — worth measuring before committing.
4. **Then, and only then, more threads.** They are free capacity once the constraint moves.

## Honest limits of this exercise

- One machine. Kafka, Postgres and four JVMs contending for the same cores, so every number is
  lower than a real deployment and the *ratios* are more trustworthy than the absolutes.
- No profiler attached. The bottleneck was identified by isolating components and by arithmetic
  that matched observation, not by a flame graph. A JFR recording would say which part of the
  insert path dominates, and would likely change the ordering of the list above.
- Ingest only. The detector kept up throughout (alerts continued firing at every rate), but its
  own ceiling was never found — at 5,000/s it was not stressed.
- Nothing was tested to destruction: no broker kill under load, no Postgres restart mid-batch at
  rate. Week 5 covered those at low volume, and they behave differently at high volume.
