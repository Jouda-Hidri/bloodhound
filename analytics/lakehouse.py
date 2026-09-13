#!/usr/bin/env python3
"""
Query and maintain the object-storage tier.

    python analytics/lakehouse.py stats          # what the three tiers cost
    python analytics/lakehouse.py query          # analyst queries over the archive
    python analytics/lakehouse.py pruning        # prove partition pruning works
    python analytics/lakehouse.py small-files    # demonstrate the classic failure, then fix it
    python analytics/lakehouse.py compact --date 2026-09-12

The lessons this exists to make visible, rather than assert:

  * columnar beats row storage by roughly an order of magnitude on this data
  * partition pruning means a day-filtered query never opens the other 364 days
  * 10,000 small files is a disaster, and compaction is the fix
"""

# PEP 604 unions (`X | None`) are 3.10+; this machine runs 3.9. The future import makes
# annotations lazy strings so the syntax parses everywhere.
from __future__ import annotations

import argparse
import datetime as dt
import io
import sys
import time

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from db import connect
from lake import BUCKET, ROW_GROUP_SIZE, duckdb_s3_setup, s3_filesystem


def con():
    c = duckdb.connect()
    duckdb_s3_setup(c)
    return c


def archive_glob(day: dt.date | None = None) -> str:
    if day:
        return (f"s3://{BUCKET}/raw_events/year={day.year:04d}"
                f"/month={day.month:02d}/day={day.day:02d}/*.parquet")
    return f"s3://{BUCKET}/raw_events/*/*/*/*.parquet"


# ----------------------------------------------------------------------
# stats
# ----------------------------------------------------------------------

def cmd_stats(args) -> int:
    fs = s3_filesystem()

    print("Storage tiers")
    print("-" * 72)

    with connect() as conn, conn.cursor() as cur:
        cur.execute("""
            select
                pg_size_pretty(sum(pg_total_relation_size(c.oid)))     as total,
                sum(pg_total_relation_size(c.oid))                     as bytes,
                sum(c.reltuples)::bigint                               as approx_rows
            from pg_class c
            join pg_inherits i on i.inhrelid = c.oid
            join pg_class p on p.oid = i.inhparent
            where p.relname = 'raw_events'
        """)
        pg_pretty, pg_bytes, pg_rows = cur.fetchone()

    print(f"  Postgres (indexed, queryable in ms)      {pg_pretty:>12}  ~{pg_rows:,} rows")

    files = [f for f in fs.get_file_info(
        pa.fs.FileSelector(f"{BUCKET}/raw_events", recursive=True))
        if f.type == pa.fs.FileType.File and f.path.endswith(".parquet")]
    lake_bytes = sum(f.size for f in files)

    if not files:
        print("  Object storage                            (empty — run archive.py first)")
        return 1

    lake_rows = con().execute(
        f"select count(*) from read_parquet('{archive_glob()}')").fetchone()[0]

    print(f"  Object storage (Parquet+zstd, seconds)   {lake_bytes / 1024 / 1024:>9.1f} MB"
          f"  {lake_rows:,} rows  in {len(files)} file(s)")
    print()

    if pg_bytes and lake_bytes:
        # Per-row is the honest comparison: the two tiers rarely hold the same rows.
        # Postgres sum() returns Decimal, which will not divide against a float.
        pg_per_row = float(pg_bytes) / max(int(pg_rows), 1)
        lake_per_row = float(lake_bytes) / max(int(lake_rows), 1)
        print(f"  per row: postgres {pg_per_row:.0f} B   lake {lake_per_row:.0f} B"
              f"   -> {pg_per_row / lake_per_row:.1f}x cheaper")
        print()
        print("  Postgres carries indexes, the full jsonb document, and per-row visibility")
        print("  overhead for MVCC. The lake carries none of that — which is exactly why it")
        print("  cannot answer a point lookup and does not need to.")
    return 0


# ----------------------------------------------------------------------
# query
# ----------------------------------------------------------------------

def cmd_query(args) -> int:
    c = con()
    glob = archive_glob()

    print("Analyst queries over the archive")
    print("-" * 72)

    queries = [
        ("Events by action", f"""
            select event_action, count(*) as events,
                   count(*) filter (where event_outcome = 'failure') as failures
            from read_parquet('{glob}')
            group by 1 order by events desc limit 8
        """),
        ("Busiest source addresses", f"""
            select source_ip, source_country, count(*) as events,
                   count(distinct user_id) as distinct_users
            from read_parquet('{glob}')
            group by 1, 2 order by events desc limit 5
        """),
        ("Simulated attacks preserved in the archive", f"""
            select json_extract_string(labels, '$.scenario') as scenario,
                   count(*) as events, count(distinct user_id) as users
            from read_parquet('{glob}')
            where labels is not null and labels != 'null'
            group by 1 having scenario is not null
            order by events desc
        """),
    ]

    for title, sql in queries:
        started = time.perf_counter()
        rows = c.execute(sql).fetchall()
        names = [d[0] for d in c.description]
        elapsed = (time.perf_counter() - started) * 1000

        print(f"\n  {title}  ({elapsed:.0f} ms)")
        print("  " + "  ".join(f"{n:<18}" for n in names))
        for row in rows:
            print("  " + "  ".join(f"{str(v):<18}" for v in row))
    return 0


# ----------------------------------------------------------------------
# pruning
# ----------------------------------------------------------------------

def cmd_pruning(args) -> int:
    """
    Measure partition pruning by building a multi-day dataset and querying one day of it.

    The archive usually holds a single day on a laptop, and "the other partitions were never
    opened" is an empty claim when there are no other partitions. So this writes N synthetic
    day-partitions into a scratch prefix and times a filtered query against a full scan.

    It is the same idea as Postgres range partitioning, implemented with key prefixes instead
    of a catalogue — and the reason the date is in the *path* rather than only in a column.
    """
    c = con()
    fs = s3_filesystem()
    scratch = f"{BUCKET}/_pruning_demo"

    source = archive_glob()
    table = c.execute(
        f"select * from read_parquet('{source}') limit {args.rows}").fetch_arrow_table()
    if table.num_rows == 0:
        print("Nothing archived yet — run archive.py first.")
        return 1

    for f in fs.get_file_info(pa.fs.FileSelector(scratch, recursive=True, allow_not_found=True)):
        if f.type == pa.fs.FileType.File:
            fs.delete_file(f.path)

    base_day = dt.date(2026, 1, 1)
    print(f"Partition pruning  ({args.days} day-partitions x {table.num_rows:,} rows)")
    print("-" * 72)

    buf = io.BytesIO()
    pq.write_table(table, buf, compression="zstd", row_group_size=ROW_GROUP_SIZE)
    payload = buf.getvalue()

    for i in range(args.days):
        day = base_day + dt.timedelta(days=i)
        path = (f"{scratch}/year={day.year:04d}/month={day.month:02d}"
                f"/day={day.day:02d}/part-0000.parquet")
        with fs.open_output_stream(path) as sink:
            sink.write(payload)

    total_bytes = len(payload) * args.days
    print(f"  wrote {args.days} partitions, {total_bytes / 1024 / 1024:.1f} MB total")

    glob = f"s3://{scratch}/**/*.parquet"
    target = base_day + dt.timedelta(days=args.days // 2)

    def timed(sql: str):
        started = time.perf_counter()
        rows = c.execute(sql).fetchone()[0]
        return rows, (time.perf_counter() - started) * 1000

    full_rows, full_ms = timed(
        f"select count(*) from read_parquet('{glob}', hive_partitioning=true)")

    # The filter is on the partition columns, which exist only as path segments. DuckDB
    # resolves it against the paths and never opens the non-matching objects.
    pruned_rows, pruned_ms = timed(f"""
        select count(*) from read_parquet('{glob}', hive_partitioning=true)
        where year = {target.year} and month = {target.month} and day = {target.day}
    """)

    # The same filter expressed on a *data* column instead of the partition columns. Every
    # file must be opened and its statistics consulted, because the pruning information is
    # not in the path.
    data_rows, data_ms = timed(f"""
        select count(*) from read_parquet('{glob}', hive_partitioning=true)
        where source_country = 'ZZ-no-such-country'
    """)

    print(f"\n  full scan, all partitions      {full_rows:>9,} rows  {full_ms:>7.0f} ms")
    print(f"  filtered on partition columns  {pruned_rows:>9,} rows  {pruned_ms:>7.0f} ms"
          f"   <- {full_ms / max(pruned_ms, 0.01):.1f}x faster")
    print(f"  filtered on a data column      {data_rows:>9,} rows  {data_ms:>7.0f} ms"
          f"   <- opens every file")

    for f in fs.get_file_info(pa.fs.FileSelector(scratch, recursive=True, allow_not_found=True)):
        if f.type == pa.fs.FileType.File:
            fs.delete_file(f.path)

    print()
    print("  Both filters return a tiny answer. Only the first one avoids the I/O, because")
    print("  the date is in the path. Put a field in the partition key and it is nearly free")
    print("  to filter on; leave it in a column and every object gets opened.")
    return 0


# ----------------------------------------------------------------------
# small files
# ----------------------------------------------------------------------

def cmd_small_files(args) -> int:
    """
    Write the same data as many tiny files, measure the damage, then compact it.

    Everyone is told "small files are bad on object storage". This measures it, because the
    number is far larger than people expect — every file costs a separate HTTP request with
    its own round trip, and at a few thousand files the overhead dwarfs the scan entirely.
    """
    c = con()
    fs = s3_filesystem()
    scratch = f"{BUCKET}/_smallfiles_demo"

    source = archive_glob()
    # fetch_arrow_table(), not arrow(): the latter returns a RecordBatchReader in DuckDB 1.4+,
    # which streams once and has no num_rows.
    table = c.execute(f"select * from read_parquet('{source}') limit {args.rows}").fetch_arrow_table()
    if table.num_rows == 0:
        print("Nothing archived yet — run archive.py first.")
        return 1

    print(f"Small-files demonstration  ({table.num_rows:,} rows)")
    print("-" * 72)

    for label, chunks in (("many small files", args.files), ("one compacted file", 1)):
        # Clear the scratch prefix between runs.
        for f in fs.get_file_info(pa.fs.FileSelector(scratch, recursive=True, allow_not_found=True)):
            if f.type == pa.fs.FileType.File:
                fs.delete_file(f.path)

        rows_per = -(-table.num_rows // chunks)
        written = 0
        for i in range(chunks):
            chunk = table.slice(i * rows_per, rows_per)
            if chunk.num_rows == 0:
                continue
            buf = io.BytesIO()
            pq.write_table(chunk, buf, compression="zstd", row_group_size=ROW_GROUP_SIZE)
            data = buf.getvalue()
            with fs.open_output_stream(f"{scratch}/part-{i:05d}.parquet") as sink:
                sink.write(data)
            written += len(data)

        glob = f"s3://{scratch}/*.parquet"
        started = time.perf_counter()
        count = c.execute(f"select count(*) from read_parquet('{glob}')").fetchone()[0]
        scan = c.execute(f"""
            select event_action, count(*) from read_parquet('{glob}') group by 1
        """).fetchall()
        elapsed = (time.perf_counter() - started) * 1000

        n_files = len([f for f in fs.get_file_info(pa.fs.FileSelector(scratch, recursive=True))
                       if f.type == pa.fs.FileType.File])
        print(f"  {label:<22} {n_files:>5} file(s)  {written / 1024 / 1024:>6.1f} MB  "
              f"{elapsed:>7.0f} ms  ({count:,} rows, {len(scan)} groups)")

    # Clean up so the demo does not pollute the archive.
    for f in fs.get_file_info(pa.fs.FileSelector(scratch, recursive=True, allow_not_found=True)):
        if f.type == pa.fs.FileType.File:
            fs.delete_file(f.path)

    print()
    print("  Same rows, same query. The difference is per-file overhead: each object needs its")
    print("  own request, footer read and decompression setup. Compression also suffers, because")
    print("  dictionaries cannot be shared across files.")
    return 0


# ----------------------------------------------------------------------
# compact
# ----------------------------------------------------------------------

def cmd_compact(args) -> int:
    """Rewrite a day's partition into one file per target size."""
    day = dt.date.fromisoformat(args.date)
    fs = s3_filesystem()
    prefix = (f"{BUCKET}/raw_events/year={day.year:04d}"
              f"/month={day.month:02d}/day={day.day:02d}")

    existing = [f for f in fs.get_file_info(
        pa.fs.FileSelector(prefix, recursive=True, allow_not_found=True))
        if f.type == pa.fs.FileType.File and f.path.endswith(".parquet")]

    if len(existing) <= 1:
        print(f"{day}: {len(existing)} file(s), nothing to compact")
        return 0

    before_bytes = sum(f.size for f in existing)
    table = pq.read_table(prefix, filesystem=fs)

    buf = io.BytesIO()
    pq.write_table(table, buf, compression="zstd", row_group_size=ROW_GROUP_SIZE,
                   write_statistics=True, use_dictionary=True, version="2.6")
    data = buf.getvalue()

    # Write the replacement before deleting the originals. Object storage has no transactions:
    # delete-then-write leaves a window where the data does not exist, and a crash inside that
    # window loses the day. This ordering can duplicate, which the readers tolerate; the other
    # ordering can lose, which they do not.
    new_path = f"{prefix}/compacted-0000.parquet"
    with fs.open_output_stream(new_path) as sink:
        sink.write(data)
    for f in existing:
        if f.path != new_path:
            fs.delete_file(f.path)

    print(f"{day}: {len(existing)} files ({before_bytes / 1024 / 1024:.1f} MB) "
          f"-> 1 file ({len(data) / 1024 / 1024:.1f} MB), "
          f"{table.num_rows:,} rows preserved")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("stats", help="compare the storage tiers")
    sub.add_parser("query", help="run analyst queries over the archive")
    pr = sub.add_parser("pruning", help="demonstrate partition pruning")
    pr.add_argument("--days", type=int, default=60, help="synthetic day-partitions to write")
    pr.add_argument("--rows", type=int, default=20_000, help="rows per partition")

    sf = sub.add_parser("small-files", help="demonstrate the small-files problem")
    sf.add_argument("--rows", type=int, default=50_000)
    sf.add_argument("--files", type=int, default=200)

    cp = sub.add_parser("compact", help="rewrite a day into one file")
    cp.add_argument("--date", required=True)

    args = parser.parse_args()
    return {
        "stats": cmd_stats, "query": cmd_query, "pruning": cmd_pruning,
        "small-files": cmd_small_files, "compact": cmd_compact,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
