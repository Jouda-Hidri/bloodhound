"""
Shared configuration for the object-storage tier.

MinIO speaks the S3 API, so everything here works unchanged against real S3 — only the endpoint
and credentials change. That is the point of developing against it rather than against a mock.
"""

import os

import pyarrow.fs as pafs

BUCKET = os.environ.get("BLOODHOUND_LAKE_BUCKET", "bloodhound-events")
WAREHOUSE_BUCKET = os.environ.get("BLOODHOUND_WAREHOUSE_BUCKET", "bloodhound-warehouse")

ENDPOINT = os.environ.get("BLOODHOUND_S3_ENDPOINT", "http://localhost:9000")
ACCESS_KEY = os.environ.get("BLOODHOUND_S3_ACCESS_KEY", "bloodhound")
SECRET_KEY = os.environ.get("BLOODHOUND_S3_SECRET_KEY", "bloodhound123")

# Target size for a single Parquet file.
#
# This number is the whole Week 14 lesson. Too small and every query pays per-file overhead —
# open, read footer, close — which at 10,000 files dominates the actual scan and is why "lots of
# tiny files" is the classic lakehouse failure. Too large and readers cannot skip or parallelise,
# and a single corrupt object costs more. 128MB is the conventional compromise; at this project's
# volume a day rarely reaches it, which is exactly why the compaction step exists.
TARGET_FILE_BYTES = 128 * 1024 * 1024

# Row group size within a file. Readers skip whole row groups using column statistics, so this
# is the granularity of predicate pushdown.
ROW_GROUP_SIZE = 128 * 1024


def s3_filesystem() -> pafs.S3FileSystem:
    endpoint = ENDPOINT.replace("http://", "").replace("https://", "")
    return pafs.S3FileSystem(
        endpoint_override=endpoint,
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        scheme="https" if ENDPOINT.startswith("https") else "http",
        # MinIO is not a region-aware service; setting one avoids a lookup that would fail.
        region="us-east-1",
        allow_bucket_creation=True,
        allow_bucket_deletion=False,
    )


def duckdb_s3_setup(con) -> None:
    """Point a DuckDB connection at the same object store."""
    # Everything in this project is UTC, and DuckDB otherwise renders timestamps in the
    # machine's local zone. That is worth forcing rather than tolerating: an investigator
    # comparing a log line in CET against an alert in UTC and not noticing is a genuine
    # incident-analysis failure, and the hour is exactly the size of mistake nobody catches.
    # It also happens to be what Iceberg requires — it rejects any zone other than UTC.
    con.execute("set TimeZone='UTC'")
    con.execute("install httpfs; load httpfs;")
    con.execute(f"set s3_endpoint='{ENDPOINT.replace('http://', '').replace('https://', '')}'")
    con.execute(f"set s3_access_key_id='{ACCESS_KEY}'")
    con.execute(f"set s3_secret_access_key='{SECRET_KEY}'")
    con.execute("set s3_use_ssl=false")
    # MinIO serves bucket-in-path, not bucket-as-subdomain.
    con.execute("set s3_url_style='path'")
