# 0006 — Three storage tiers, and why

Status: accepted
Date: 2026-09-13

## Context

By Week 13 the same events lived in Postgres and OpenSearch. Neither is where you keep three
years of security data so that an investigation in 2029 can look at 2026 — Postgres because the
cost per byte is high and the table would never stop growing, OpenSearch because it is worse.

Retention (ADR 0002) currently *deletes*. For a security platform that is the wrong default: the
investigations that matter most are the ones that start months after the intrusion.

## Decision

Three tiers, each answering a different question:

| tier | answers | latency | cost per row (measured) |
|---|---|---|---|
| Postgres | "how many failures for this user in this window" | ms | 1344 B |
| OpenSearch | "show me everything mentioning this address" | ms | — |
| Object storage (Parquet) | "what happened in March 2026" | seconds | 88 B |

**15.3× cheaper per row**, measured on 77,064 real events. Postgres carries indexes, the full
`jsonb` document, and per-row MVCC visibility overhead. The lake carries none of that, which is
exactly why it cannot answer a point lookup and does not need to.

### Hive-style directory partitioning

```
s3://bloodhound-events/raw_events/year=2026/month=09/day=12/part-0000.parquet
```

Partition keys are *directories*, so a day-filtered query never opens the other 364. This is the
same pruning Postgres does with range partitions, implemented with key prefixes instead of a
catalogue, and every engine understands it without one.

Measured over 60 synthetic day-partitions (1.2M rows, 102 MB):

```
full scan, all partitions      1,200,000 rows    51 ms
filtered on partition columns     20,000 rows     5 ms   <- 10.4x faster
filtered on a data column                 0 rows     7 ms   <- opens every file
```

The third row is the one worth internalising. Both filters return almost nothing; only the
partition-column filter avoids the I/O. **A field in the partition key is nearly free to filter
on; the same field in a column means every object gets opened.** That is the whole of partition
design.

### File sizing, and the small-files problem

Target 128 MB per file. Measured, same 50,000 rows:

```
many small files    200 files   6.7 MB   239 ms
one compacted file    1 file    4.2 MB    21 ms
```

**11× slower and 60% larger.** Every object costs its own request, footer read and decompression
setup, and dictionaries cannot be shared across files so compression suffers too. At 10,000 files
the per-file overhead dominates the scan entirely.

This is why the compaction step exists rather than being a nicety. A pipeline that writes a file
per batch — the obvious implementation — produces exactly this failure within days.

### Compaction writes before it deletes

Object storage has no transactions. Delete-then-write leaves a window in which the data does not
exist, and a crash inside that window loses the day. Write-then-delete can briefly duplicate,
which readers tolerate. **Prefer the failure mode that duplicates over the one that loses.**

### Iceberg on top, for the things a pile of files cannot do

Raw Parquet in a directory tree is a pile of files, not a table. It has no commit, so:

- a reader can observe a half-finished write — "the files that exist right now" is the only
  definition of the table;
- compaction is inherently unsafe, per the previous section;
- "what did this look like on Tuesday" is unanswerable;
- adding a column means every reader must cope with files that lack it.

A manifest between reader and files fixes all four. Verified working:

```
append 20,000 rows  -> snapshot 8636689257345152818
append 20,000 rows  -> snapshot 2346015387111629552
current table: 40,000 rows
as of snapshot 1: 20,000 rows          <- time travel, no restore
added column enrichment_asn without rewriting a single file
```

Schema evolution works because Iceberg tracks field *ids*, not names or positions — old files are
read back with the new column as null.

The catalogue lives in Postgres and the data in MinIO, mirroring what a real deployment does with
Glue or Nessie plus S3. **Losing the catalogue loses the table**, even though every byte is still
in object storage — which is why it belongs in the database that gets backed up.

### MinIO, and therefore S3

MinIO speaks the S3 API, so everything here works unchanged against real S3 — only the endpoint
and credentials change. That is the point of developing against it rather than a mock.

## Consequences

- Retention can finally mean *tier down* rather than *delete*: drop the Postgres partition once
  the day is archived and verified.
- The archive is only trustworthy if it is read back. `archive.py --verify` re-reads with DuckDB
  and compares row counts; an archive nobody has restored is a backup nobody has restored.
- Columns are listed explicitly rather than `select *`. The archive is a long-lived format, and a
  column silently appearing or disappearing is what makes a five-year-old archive unreadable.
- DuckDB's session timezone is forced to UTC. It otherwise renders in local time, and an
  investigator comparing a CET log line against a UTC alert without noticing is a real analysis
  failure — an hour is exactly the size of error nobody catches. Iceberg rejects non-UTC zones
  outright, which is how this was found.

## Known gaps

- Nothing drops a Postgres partition after archiving it, so the two tiers hold the same data.
  The dependency (archive must succeed before retention runs) is what Week 15's orchestrator is
  for.
- No compaction schedule — `lake-compact` is manual.
- Iceberg holds a demonstration table, not the production path. `archive.py` still writes plain
  Parquet; moving it onto Iceberg would make the archive atomic but adds a catalogue dependency
  to the ingest path.
