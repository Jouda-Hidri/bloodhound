#!/usr/bin/env python3
"""
Iceberg on top of the same Parquet files: snapshots, time travel, schema evolution.

    python analytics/iceberg_table.py demo
    python analytics/iceberg_table.py history

Why bother, when archive.py already writes perfectly good Parquet?

Raw Parquet in a directory tree is a *pile of files*. It has no notion of a commit, so:

  * a reader can observe a half-finished write, because "the files that exist right now" is
    the only definition of the table;
  * compaction is dangerous — deleting the originals after writing the replacement is a window
    in which readers see both, or neither;
  * "what did this table look like on Tuesday" is unanswerable;
  * adding a column means every reader must cope with files that lack it.

A table format fixes all four by putting a *manifest* between the reader and the files. The
table is whatever the current snapshot says it is, snapshots are swapped atomically, and old
snapshots remain readable. That is the entire idea, and it is why Iceberg/Delta/Hudi exist.

The catalogue lives in Postgres, the data in MinIO — the same split a real deployment uses
(Glue/Nessie + S3).
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys

import duckdb

from lake import ACCESS_KEY, ENDPOINT, SECRET_KEY, WAREHOUSE_BUCKET, duckdb_s3_setup
from db import dsn

NAMESPACE = "security"
TABLE = f"{NAMESPACE}.events"


def catalog():
    from pyiceberg.catalog.sql import SqlCatalog

    # The catalogue is the source of truth for what the table *is*. Losing it loses the table,
    # even though every byte of data is still sitting in object storage — which is why it lives
    # in Postgres and gets backed up, rather than in a file next to the data.
    uri = dsn().replace("postgresql://", "postgresql+psycopg2://")
    return SqlCatalog("bloodhound", **{
        "uri": uri,
        "warehouse": f"s3://{WAREHOUSE_BUCKET}/",
        "s3.endpoint": ENDPOINT,
        "s3.access-key-id": ACCESS_KEY,
        "s3.secret-access-key": SECRET_KEY,
        "s3.path-style-access": "true",
        "s3.region": "us-east-1",
    })


def source_batch(limit: int, offset: int = 0):
    """Pull a slice of the archived Parquet as an Arrow table."""
    from lakehouse import archive_glob

    con = duckdb.connect()
    duckdb_s3_setup(con)
    return con.execute(
        f"select * from read_parquet('{archive_glob()}') "
        f"limit {limit} offset {offset}"
    ).fetch_arrow_table()


def cmd_demo(args) -> int:
    cat = catalog()
    cat.create_namespace_if_not_exists(NAMESPACE)

    # Start clean so the demo is reproducible.
    try:
        cat.drop_table(TABLE)
    except Exception:
        pass

    first = source_batch(args.rows)
    if first.num_rows == 0:
        print("Nothing archived yet — run archive.py first.")
        return 1

    print("Iceberg table format")
    print("-" * 72)

    table = cat.create_table(TABLE, schema=first.schema)
    print(f"  created {TABLE}")

    # --- snapshot 1 ---------------------------------------------------
    table.append(first)
    table.refresh()
    snap1 = table.current_snapshot().snapshot_id
    print(f"  append {first.num_rows:>7,} rows  -> snapshot {snap1}")

    # --- snapshot 2 ---------------------------------------------------
    second = source_batch(args.rows, offset=args.rows)
    if second.num_rows:
        table.append(second)
        table.refresh()
        snap2 = table.current_snapshot().snapshot_id
        print(f"  append {second.num_rows:>7,} rows  -> snapshot {snap2}")
    else:
        snap2 = snap1

    total = len(table.scan().to_arrow())
    print(f"\n  current table: {total:,} rows")

    # --- time travel --------------------------------------------------
    # The point: snapshot 1 is still a complete, readable table. Nothing was overwritten —
    # the append added new files and a new manifest, and the old manifest still points at
    # the old set. "What did this look like before the load?" becomes a normal query.
    as_of_first = len(table.scan(snapshot_id=snap1).to_arrow())
    print(f"  as of snapshot 1: {as_of_first:,} rows   <- time travel, no restore required")

    # --- schema evolution ---------------------------------------------
    # Adding a column to a pile of Parquet files means every reader must tolerate files that
    # lack it. Iceberg tracks field *ids*, not positions or names, so old files are read back
    # with the new column as null and nothing has to be rewritten.
    from pyiceberg.types import StringType

    with table.update_schema() as update:
        update.add_column("enrichment_asn", StringType(),
                          doc="Autonomous system, added after the fact")
    table.refresh()
    fields = [f.name for f in table.schema().fields]
    print(f"\n  added column enrichment_asn without rewriting a single file")
    print(f"  schema now {len(fields)} fields, old files still readable: "
          f"{len(table.scan().to_arrow()):,} rows")

    print(f"\n  snapshots: {len(list(table.snapshots()))}")
    print("  Every one of these is a complete, atomically-committed version of the table.")
    print("  That is what a directory of Parquet files cannot give you.")
    return 0


def cmd_history(args) -> int:
    cat = catalog()
    try:
        table = cat.load_table(TABLE)
    except Exception as e:
        print(f"No Iceberg table yet ({e}). Run: iceberg_table.py demo")
        return 1

    print(f"Snapshots of {TABLE}")
    print("-" * 72)
    print(f"  {'snapshot id':<22} {'when':<26} {'operation':<12} rows")
    for snap in table.snapshots():
        when = dt.datetime.fromtimestamp(snap.timestamp_ms / 1000, dt.timezone.utc)
        summary = snap.summary or {}
        op = summary.get("operation", "?")
        total = summary.get("total-records", "?")
        print(f"  {snap.snapshot_id:<22} {when:%Y-%m-%d %H:%M:%S UTC}     {op:<12} {total}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo", help="build a table and show snapshots, time travel, evolution")
    d.add_argument("--rows", type=int, default=20_000)
    sub.add_parser("history", help="list the table's snapshots")

    args = parser.parse_args()
    return {"demo": cmd_demo, "history": cmd_history}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
