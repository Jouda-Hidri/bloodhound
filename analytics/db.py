"""Shared database connection helper for the analytics scripts."""

import os

import psycopg

DEFAULT_DSN = "postgresql://bloodhound:bloodhound@localhost:5433/bloodhound"


def dsn() -> str:
    """Connection string, overridable with BLOODHOUND_DSN."""
    return os.environ.get("BLOODHOUND_DSN", DEFAULT_DSN)


def connect() -> psycopg.Connection:
    return psycopg.connect(dsn())


def table_exists(conn: psycopg.Connection, schema: str, table: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """
            select exists (
                select 1 from information_schema.tables
                where table_schema = %s and table_name = %s
            )
            """,
            (schema, table),
        )
        return cur.fetchone()[0]


def fmt_pct(value) -> str:
    """Percentages, with an explicit marker for 'not measurable' rather than a misleading 0%."""
    if value is None:
        return "   n/a"
    return f"{value * 100:5.1f}%"
