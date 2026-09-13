#!/usr/bin/env python3
"""
Drive the pipeline until something breaks, and record where.

    python analytics/loadtest.py ramp --steps 20,100,500,2000,5000 --seconds 60
    python analytics/loadtest.py sustain --rate 2000 --minutes 10
    python analytics/loadtest.py report

The point is not a headline number. It is finding which component gives out first, and being able
to say why — "we do N events/sec, and above that the bottleneck is X" is a far more useful
sentence than "we do N events/sec".

Measurements are taken from the pipeline's own metrics rather than from the load generator, so
what is reported is what actually landed, not what was offered. A generator that reports its own
throughput while the consumer silently falls behind is measuring nothing.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from db import connect

PRODUCER = "http://localhost:8101"
CONSUMER = "http://localhost:8102"
DETECTOR = "http://localhost:8103"


def get_json(url: str, timeout: int = 10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def post(url: str, timeout: int = 20):
    request = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def metric(service: str, name: str, tag: str = None) -> float:
    """Read one Micrometer counter. Returns 0 when the metric does not exist yet."""
    url = f"{service}/actuator/metrics/{name}"
    if tag:
        url += f"?tag={tag}"
    try:
        data = get_json(url)
        return float(data["measurements"][0]["value"])
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, IndexError):
        return 0.0


def timer_percentiles(service: str, name: str) -> dict:
    """Micrometer exposes COUNT, TOTAL_TIME and MAX for a Timer."""
    try:
        data = get_json(f"{service}/actuator/metrics/{name}")
        out = {m["statistic"]: m["value"] for m in data["measurements"]}
        count = out.get("COUNT", 0)
        total = out.get("TOTAL_TIME", 0)
        return {
            "count": count,
            "mean_ms": (total / count * 1000) if count else 0,
            "max_ms": out.get("MAX", 0) * 1000,
        }
    except Exception:
        return {"count": 0, "mean_ms": 0, "max_ms": 0}


def pipeline_state() -> dict:
    """Everything worth knowing at one instant, read from the pipeline itself."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""
            select
                count(*) filter (where ingested_at > now() - interval '1 minute') as last_minute,
                coalesce(max(extract(epoch from (ingested_at - ts))), 0)          as max_lag_s,
                coalesce(avg(extract(epoch from (ingested_at - ts))), 0)          as avg_lag_s
            from raw_events
            where ingested_at > now() - interval '2 minutes'
        """)
        rows_last_minute, max_lag, avg_lag = cur.fetchone()

    batch = timer_percentiles(CONSUMER, "bloodhound.ingest.batch")
    return {
        "ingested": metric(CONSUMER, "bloodhound.events.ingested"),
        "rejected": metric(CONSUMER, "bloodhound.events.rejected"),
        "duplicates": metric(CONSUMER, "bloodhound.events.duplicates"),
        "dlq": metric(CONSUMER, "bloodhound.deadletters.published"),
        "search_dropped": metric(CONSUMER, "bloodhound.search.dropped"),
        "alerts": metric(DETECTOR, "bloodhound.detector.alerts"),
        "rows_last_minute": int(rows_last_minute or 0),
        "max_lag_s": round(float(max_lag or 0), 2),
        "avg_lag_s": round(float(avg_lag or 0), 2),
        "batch_mean_ms": round(batch["mean_ms"], 2),
        "batch_max_ms": round(batch["max_ms"], 2),
    }


def set_rate(rate: int) -> None:
    post(f"{PRODUCER}/sim/traffic?enabled=true&eventsPerSecond={rate}")


def measure_step(rate: int, seconds: int) -> dict:
    """Hold one rate and report what the pipeline actually achieved."""
    set_rate(rate)

    # Let the rate settle before measuring. Without this, each step's numbers are dominated by
    # the previous step's backlog draining.
    time.sleep(10)

    before = pipeline_state()
    started = time.time()
    samples = []
    while time.time() - started < seconds:
        time.sleep(5)
        samples.append(pipeline_state())
    after = pipeline_state()
    elapsed = time.time() - started

    achieved = (after["ingested"] - before["ingested"]) / elapsed
    lags = [s["max_lag_s"] for s in samples] or [0]

    return {
        "offered_rate": rate,
        "achieved_rate": round(achieved, 1),
        # The ratio is the number that matters: below ~0.95 the pipeline is not keeping up,
        # whatever the absolute throughput says.
        "keep_up_ratio": round(achieved / rate, 3) if rate else 0,
        "max_lag_s": round(max(lags), 2),
        "median_lag_s": round(statistics.median(lags), 2),
        "batch_mean_ms": after["batch_mean_ms"],
        "dlq_delta": int(after["dlq"] - before["dlq"]),
        "rejected_delta": int(after["rejected"] - before["rejected"]),
        "search_dropped_delta": int(after["search_dropped"] - before["search_dropped"]),
        "alerts_delta": int(after["alerts"] - before["alerts"]),
    }


def cmd_ramp(args) -> int:
    steps = [int(s) for s in args.steps.split(",")]
    print(f"Ramp: {steps} events/sec, {args.seconds}s per step")
    print("=" * 96)
    print(f"  {'offered':>8} {'achieved':>9} {'keep-up':>8} {'lag max':>9} {'batch ms':>9} "
          f"{'dropped':>8} {'dlq':>5} {'alerts':>7}")

    results = []
    breaking_point = None
    for rate in steps:
        r = measure_step(rate, args.seconds)
        results.append(r)
        print(f"  {r['offered_rate']:>8} {r['achieved_rate']:>9} {r['keep_up_ratio']:>8} "
              f"{r['max_lag_s']:>9} {r['batch_mean_ms']:>9} {r['search_dropped_delta']:>8} "
              f"{r['dlq_delta']:>5} {r['alerts_delta']:>7}")

        if breaking_point is None and r["keep_up_ratio"] < 0.95:
            breaking_point = r

    set_rate(args.restore)
    print(f"\n  restored to {args.restore} events/sec")

    print("\nWhere it gives out")
    print("-" * 96)
    if breaking_point:
        print(f"  First rate not kept up with: {breaking_point['offered_rate']}/s "
              f"(achieved {breaking_point['achieved_rate']}/s, "
              f"{breaking_point['keep_up_ratio'] * 100:.0f}%)")
        diagnose(breaking_point)
    else:
        best = results[-1]
        print(f"  Kept up at every step tested, to {best['offered_rate']}/s.")
        print("  The bottleneck is above this range — raise --steps to find it.")

    if args.save:
        save(results)
    return 0


def diagnose(step: dict) -> None:
    """Name the most likely constraint from the shape of the failure, not from a guess."""
    print()
    if step["dlq_delta"] > 0 or step["rejected_delta"] > 0:
        print("  Events were dead-lettered under load. That is data loss, not slowness —")
        print("  investigate before believing any throughput number above this rate.")
    if step["search_dropped_delta"] > 0:
        print("  The OpenSearch indexer shed batches. By design: it drops rather than")
        print("  slowing ingestion, so search coverage degrades before the pipeline does.")
    if step["batch_mean_ms"] > 200:
        print(f"  Batch insert latency {step['batch_mean_ms']}ms — the constraint is Postgres.")
        print("  Look at index maintenance and WAL before blaming Kafka.")
    elif step["max_lag_s"] > 30:
        print("  Lag grew while batch latency stayed low: the consumer is not the constraint.")
        print("  Look at consumer concurrency against topic partitions (6), then the broker.")
    print()


def cmd_sustain(args) -> int:
    """Hold one rate and watch whether lag is stable or growing."""
    print(f"Sustain: {args.rate} events/sec for {args.minutes} minutes")
    print("=" * 72)
    set_rate(args.rate)
    time.sleep(10)

    deadline = time.time() + args.minutes * 60
    lags = []
    print(f"  {'elapsed':>8} {'rows/min':>9} {'lag max':>9} {'batch ms':>9}")
    while time.time() < deadline:
        s = pipeline_state()
        lags.append(s["max_lag_s"])
        elapsed = args.minutes * 60 - (deadline - time.time())
        print(f"  {elapsed:>7.0f}s {s['rows_last_minute']:>9} {s['max_lag_s']:>9} "
              f"{s['batch_mean_ms']:>9}")
        time.sleep(30)

    set_rate(args.restore)
    # Growing lag under a constant rate is the definition of not keeping up, and it is invisible
    # in a short test — the queue absorbs the first minute or two.
    trend = lags[-1] - lags[0] if len(lags) > 1 else 0
    print(f"\n  lag start {lags[0]}s  end {lags[-1]}s  trend {trend:+.1f}s")
    print("  " + ("STABLE — the pipeline is keeping up at this rate."
                  if trend < 5 else
                  "GROWING — lag is accumulating; this rate is above what it sustains."))
    return 0


def save(results: list) -> None:
    stamp = datetime.now(timezone.utc).isoformat()
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""
            create table if not exists load_test_runs (
                id bigserial primary key,
                run_at timestamptz not null,
                offered_rate int, achieved_rate numeric, keep_up_ratio numeric,
                max_lag_s numeric, batch_mean_ms numeric,
                dlq_delta int, search_dropped_delta int
            )
        """)
        for r in results:
            cur.execute("""
                insert into load_test_runs (run_at, offered_rate, achieved_rate, keep_up_ratio,
                                            max_lag_s, batch_mean_ms, dlq_delta, search_dropped_delta)
                values (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (stamp, r["offered_rate"], r["achieved_rate"], r["keep_up_ratio"],
                  r["max_lag_s"], r["batch_mean_ms"], r["dlq_delta"], r["search_dropped_delta"]))
        conn.commit()
    print(f"  saved {len(results)} rows to load_test_runs")


def cmd_report(args) -> int:
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select to_regclass('load_test_runs')")
        if cur.fetchone()[0] is None:
            print("No load test runs recorded yet.")
            return 1
        cur.execute("""
            select run_at, offered_rate, achieved_rate, keep_up_ratio, max_lag_s, batch_mean_ms
            from load_test_runs order by run_at desc, offered_rate limit 40
        """)
        print(f"  {'run':<22} {'offered':>8} {'achieved':>9} {'keep-up':>8} "
              f"{'lag':>7} {'batch ms':>9}")
        for row in cur.fetchall():
            print(f"  {str(row[0])[:19]:<22} {row[1]:>8} {row[2]:>9} {row[3]:>8} "
                  f"{row[4]:>7} {row[5]:>9}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("ramp", help="step through rates until the pipeline stops keeping up")
    r.add_argument("--steps", default="20,100,500,1000,2500,5000")
    r.add_argument("--seconds", type=int, default=45)
    r.add_argument("--restore", type=int, default=20)
    r.add_argument("--save", action="store_true")

    s = sub.add_parser("sustain", help="hold one rate and watch whether lag grows")
    s.add_argument("--rate", type=int, required=True)
    s.add_argument("--minutes", type=int, default=5)
    s.add_argument("--restore", type=int, default=20)

    sub.add_parser("report", help="previous load test results")

    args = parser.parse_args()
    return {"ramp": cmd_ramp, "sustain": cmd_sustain, "report": cmd_report}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
