#!/usr/bin/env python3
"""
Archive a day of raw events from Postgres to object storage as Parquet.

    python analytics/archive.py --date 2026-09-12
    python analytics/archive.py --date 2026-09-12 --verify
    python analytics/archive.py --backfill 7

Why a third storage tier exists at all. Postgres answers "count failures per user per window"
well and costs a lot per byte. OpenSearch answers "show me everything mentioning this IP" and
costs even more. Neither is where you keep three years of events so that an investigation in 2029
can look at 2026 — that is what object storage is for, at roughly a twentieth of the price.

The tradeoff being bought: queries go from milliseconds to seconds, and there are no indexes,
only partition pruning and column statistics. That is an entirely acceptable trade for data
nobody reads until they urgently need to.

Layout
------
Hive-style partitioning, which every engine understands without a catalogue:

    s3://bloodhound-events/raw_events/year=2026/month=09/day=12/part-0.parquet

The partition keys are *directories*, so a query filtered to one day never opens the other 364.
That is the same pruning Postgres does with range partitions, done with prefixes instead.
"""

import argparse
import datetime as dt
import io
import sys

import psycopg
import pyarrow as pa
import pyarrow.parquet as pq

from db import connect
from lake import BUCKET, ROW_GROUP_SIZE, TARGET_FILE_BYTES, s3_filesystem

# Columns are selected explicitly rather than `select *`: the archive is a long-lived format, and
# a column silently appearing or disappearing because someone altered the table is exactly the
# kind of drift that makes a five-year-old archive unreadable.
EXPORT_SQL = """
select
    event_id,
    ts,
    ingested_at,
    event_category,
    event_action,
    event_outcome,
    event_reason,
    user_id,
    user_name,
    user_domain,
    host(source_ip) as source_ip,
    source_port,
    source_country,
    source_city,
    service_name,
    service_environment,
    user_agent,
    labels::text as labels,
    raw::text as raw
from raw_events
where ts >= %(start)s and ts < %(end)s
order by ts
"""

# An explicit schema, for the same reason as the explicit column list. Arrow would infer types
# from the first batch, which is fine until a day arrives where some column is entirely null and
# gets inferred as null-typed — producing files that will not merge with the others.
SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("ts", pa.timestamp("us", tz="UTC")),
    ("ingested_at", pa.timestamp("us", tz="UTC")),
    ("event_category", pa.string()),
    ("event_action", pa.string()),
    ("event_outcome", pa.string()),
    ("event_reason", pa.string()),
    ("user_id", pa.string()),
    ("user_name", pa.string()),
    ("user_domain", pa.string()),
    ("source_ip", pa.string()),
    ("source_port", pa.int32()),
    ("source_country", pa.string()),
    ("source_city", pa.string()),
    ("service_name", pa.string()),
    ("service_environment", pa.string()),
    ("user_agent", pa.string()),
    ("labels", pa.string()),
    ("raw", pa.string()),
])

BATCH_ROWS = 50_000


def partition_path(day: dt.date) -> str:
    return (f"{BUCKET}/raw_events/year={day.year:04d}"
            f"/month={day.month:02d}/day={day.day:02d}")


def fetch_day(conn: psycopg.Connection, day: dt.date):
    """Stream a day out of Postgres in batches rather than materialising it all in memory."""
    start = dt.datetime.combine(day, dt.time.min, tzinfo=dt.timezone.utc)
    end = start + dt.timedelta(days=1)

    # A server-side cursor. Without one, psycopg buffers the entire result set client-side, which
    # is fine for a laptop day and fatal for a real one.
    with conn.cursor(name=f"archive_{day:%Y%m%d}") as cur:
        cur.itersize = BATCH_ROWS
        cur.execute(EXPORT_SQL, {"start": start, "end": end})
        columns = None
        batch = []
        for row in cur:
            if columns is None:
                columns = [d.name for d in cur.description]
            batch.append(row)
            if len(batch) >= BATCH_ROWS:
                yield to_table(batch, columns)
                batch = []
        if batch:
            yield to_table(batch, columns)


def to_table(rows, columns) -> pa.Table:
    cols = {name: [r[i] for r in rows] for i, name in enumerate(columns)}
    return pa.Table.from_pydict(cols, schema=SCHEMA)


def archive_day(conn, fs, day: dt.date, compression: str = "zstd") -> dict:
    prefix = partition_path(day)

    tables = list(fetch_day(conn, day))
    if not tables:
        return {"day": str(day), "rows": 0, "files": 0, "bytes": 0, "skipped": "no rows"}

    table = pa.concat_tables(tables)
    rows = table.num_rows

    # Write one file per TARGET_FILE_BYTES worth of data. Estimating from the in-memory size
    # over-counts (Parquet compresses 5-10x on this data), which errs toward more, smaller files
    # — and then the compaction pass fixes it. Guessing low in the other direction would produce
    # multi-gigabyte objects that cannot be re-written cheaply.
    approx_uncompressed = table.nbytes
    files_needed = max(1, -(-approx_uncompressed // (TARGET_FILE_BYTES * 6)))
    rows_per_file = -(-rows // files_needed)

    written = []
    for index in range(files_needed):
        chunk = table.slice(index * rows_per_file, rows_per_file)
        if chunk.num_rows == 0:
            continue
        path = f"{prefix}/part-{index:04d}.parquet"

        buffer = io.BytesIO()
        pq.write_table(
            chunk, buffer,
            compression=compression,
            row_group_size=ROW_GROUP_SIZE,
            # Column statistics are what let a reader skip row groups without decoding them.
            # Without these, partition pruning is the only filtering available.
            write_statistics=True,
            # Dictionary encoding collapses the low-cardinality columns — action, outcome,
            # country, user agent — which is most of the width of this table.
            use_dictionary=True,
            version="2.6",
        )
        data = buffer.getvalue()
        with fs.open_output_stream(path) as sink:
            sink.write(data)
        written.append((path, len(data)))

    total_bytes = sum(size for _, size in written)
    return {
        "day": str(day),
        "rows": rows,
        "files": len(written),
        "bytes": total_bytes,
        "bytes_per_row": round(total_bytes / rows, 1) if rows else 0,
        "compression_ratio": round(approx_uncompressed / total_bytes, 1) if total_bytes else 0,
        "paths": [p for p, _ in written],
    }


def verify(day: dt.date, expected_rows: int) -> bool:
    """Read the archive back with DuckDB and check it against Postgres."""
    import duckdb
    from lake import duckdb_s3_setup

    con = duckdb.connect()
    duckdb_s3_setup(con)
    glob = f"s3://{partition_path(day)}/*.parquet"
    try:
        actual = con.execute(f"select count(*) from read_parquet('{glob}')").fetchone()[0]
    except Exception as e:
        print(f"  verify FAILED: {e}")
        return False

    ok = actual == expected_rows
    print(f"  verify {'OK' if ok else 'FAILED'}: postgres={expected_rows} parquet={actual}")

    if ok and actual:
        # Prove the archive is actually queryable, not merely present. An archive nobody has
        # ever read back is a backup nobody has ever restored.
        sample = con.execute(f"""
            select event_action, count(*) as n
            from read_parquet('{glob}')
            group by 1 order by n desc limit 3
        """).fetchall()
        print(f"  top actions: {', '.join(f'{a}={n}' for a, n in sample)}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--date", help="day to archive, YYYY-MM-DD (default: yesterday)")
    parser.add_argument("--backfill", type=int, metavar="N",
                        help="archive the last N days instead of one")
    parser.add_argument("--compression", default="zstd", choices=["zstd", "snappy", "gzip", "none"])
    parser.add_argument("--verify", action="store_true", help="read back and compare row counts")
    args = parser.parse_args()

    if args.backfill:
        today = dt.date.today()
        days = [today - dt.timedelta(days=i) for i in range(args.backfill)]
    elif args.date:
        days = [dt.date.fromisoformat(args.date)]
    else:
        days = [dt.date.today() - dt.timedelta(days=1)]

    fs = s3_filesystem()
    failures = 0

    with connect() as conn:
        for day in sorted(days):
            result = archive_day(conn, fs, day, args.compression)
            if result.get("skipped"):
                print(f"{day}: nothing to archive")
                continue

            print(f"{day}: {result['rows']:,} rows -> {result['files']} file(s), "
                  f"{result['bytes'] / 1024 / 1024:.1f} MB "
                  f"({result['bytes_per_row']} B/row, {result['compression_ratio']}x smaller "
                  f"than in-memory)")

            if args.verify and not verify(day, result["rows"]):
                failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
