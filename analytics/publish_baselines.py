#!/usr/bin/env python3
"""
Publish per-account baselines from Postgres to the compacted Kafka topic.

    python analytics/publish_baselines.py
    python analytics/publish_baselines.py --dry-run

Why a topic rather than the detector reading Postgres directly: a per-event database lookup on a
stream processor's hot path is how you acquire a latency problem that is very hard to see. The
detector consumes this topic into a GlobalKTable, which is an in-memory lookup with no network
call per event, and which rebuilds itself from the topic on a cold start.

`cleanup.policy=compact` is what makes that rebuild work — the topic keeps the latest value per
key indefinitely, so it behaves as a table rather than a stream.

Published through Redpanda's HTTP proxy rather than a Kafka client library. One fewer Python
dependency, and the wire format stays visible.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

from db import connect

PROXY = os.environ.get("BLOODHOUND_PANDAPROXY", "http://localhost:18082")
TOPIC = "security.baselines"

SELECT_SQL = """
select
    user_id,
    computed_at,
    window_days,
    total_events,
    logins,
    login_failures,
    failure_rate,
    events_per_day,
    countries,
    primary_country,
    distinct_source_ips,
    user_agents,
    active_hours,
    peak_hour,
    dormant_days
from user_baseline
order by user_id
"""

# Redpanda's proxy batches, but not without limit — a few hundred records per request keeps the
# payload well inside the default 1MB message size with the user_agents arrays included.
BATCH = 200


def to_record(row, columns) -> dict:
    d = dict(zip(columns, row))

    def num(value):
        return float(value) if value is not None else None

    return {
        "key": d["user_id"],
        "value": {
            "user_id": d["user_id"],
            # The detector deserialises this as an Instant, so it has to be ISO-8601 with an
            # offset. Postgres would otherwise render it in whatever the session timezone is.
            "computed_at": d["computed_at"].isoformat() if d["computed_at"] else None,
            "window_days": d["window_days"],
            "total_events": d["total_events"],
            "logins": d["logins"],
            "login_failures": d["login_failures"],
            "failure_rate": num(d["failure_rate"]),
            "events_per_day": num(d["events_per_day"]),
            "countries": sorted(set(d["countries"] or [])),
            "primary_country": d["primary_country"],
            "distinct_source_ips": d["distinct_source_ips"],
            "user_agents": sorted(set(d["user_agents"] or [])),
            "active_hours": sorted(set(d["active_hours"] or [])),
            "peak_hour": d["peak_hour"],
            "dormant_days": num(d["dormant_days"]),
        },
    }


def publish(records: list) -> int:
    """
    Publish with the *binary* proxy format, base64-encoding key and value.

    The obvious choice is `vnd.kafka.json.v2+json`, and it silently breaks the join. That format
    JSON-encodes the key as well as the value, so `"u-00000"` reaches the topic as the nine bytes
    `"u-00000"` — quotes included — while the detector looks up the seven bytes `u-00000`. The
    GlobalKTable is fully populated, every lookup misses, and the rule produces nothing at all
    with no error anywhere.

    The binary format hands over exact bytes, which is what a key needs to be.
    """
    encoded = [
        {
            "key": base64.b64encode(r["key"].encode()).decode(),
            "value": base64.b64encode(json.dumps(r["value"]).encode()).decode(),
        }
        for r in records
    ]
    body = json.dumps({"records": encoded}).encode()
    request = urllib.request.Request(
        f"{PROXY}/topics/{TOPIC}",
        data=body,
        headers={"Content-Type": "application/vnd.kafka.binary.v2+json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Proxy rejected the batch ({e.code}): {e.read().decode()[:300]}")

    errors = [o for o in result.get("offsets", []) if o.get("error_code")]
    if errors:
        raise SystemExit(f"Broker rejected {len(errors)} record(s): {errors[:3]}")
    return len(records)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="print one record and stop")
    args = parser.parse_args()

    with connect() as conn, conn.cursor() as cur:
        cur.execute(SELECT_SQL)
        columns = [d.name for d in cur.description]
        rows = cur.fetchall()

    if not rows:
        print("No baselines in Postgres. Run baseline.py first.")
        return 1

    records = [to_record(row, columns) for row in rows]

    if args.dry_run:
        print(json.dumps(records[0], indent=2))
        print(f"\n{len(records)} record(s) would be published to {TOPIC}")
        return 0

    published = 0
    for i in range(0, len(records), BATCH):
        published += publish(records[i:i + BATCH])

    known_countries = sum(len(r["value"]["countries"]) for r in records) / len(records)
    print(f"Published {published} baseline(s) to {TOPIC}")
    print(f"  mean countries per account: {known_countries:.2f}")
    print(f"  accounts with >1 country:   "
          f"{sum(1 for r in records if len(r['value']['countries']) > 1)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
