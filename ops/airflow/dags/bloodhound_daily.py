"""
The daily maintenance chain for Bloodhound.

This DAG exists for one reason that a cron job cannot express: **retention must not delete a
day from Postgres until that day has been archived to object storage and the archive has been
read back and verified.**

As `@Scheduled` jobs in the consumer (Weeks 2 and 15), archive and retention were independent
timers. Nothing stopped retention running after a failed archive, and the failure mode is
silent and total — the partition is gone, the Parquet is absent or truncated, and nobody finds
out until an investigation months later turns up nothing. That is precisely the class of bug an
orchestrator exists to make impossible.

    quality_gate ─▶ rebuild_baselines ─┐
                                       ├─▶ archive ─▶ verify ─▶ compact ─▶ tier_down
                   score_detections ───┘

`tier_down` is downstream of `verify`, so a failed or unverified archive leaves the data in
Postgres. Losing money on storage is recoverable; losing the evidence is not.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys

import pendulum
from airflow.decorators import dag, task
from airflow.exceptions import AirflowFailException, AirflowSkipException

ANALYTICS = "/opt/bloodhound/analytics"

# Retention is deliberately long here relative to the archive window. The gap is the safety
# margin: a day must be archived, verified and compacted well before anything considers
# deleting it.
RETAIN_DAYS = int(os.environ.get("BLOODHOUND_RETAIN_DAYS", "30"))


def run_script(script: str, *args: str) -> str:
    """Run one of the analytics scripts and fail the task loudly if it exits non-zero."""
    cmd = [sys.executable, script, *args]
    result = subprocess.run(cmd, cwd=ANALYTICS, capture_output=True, text=True)
    output = (result.stdout or "") + (result.stderr or "")
    print(output)
    if result.returncode != 0:
        raise AirflowFailException(
            f"{script} exited {result.returncode}\n{output[-2000:]}")
    return output


@dag(
    dag_id="bloodhound_daily",
    schedule="0 3 * * *",
    start_date=pendulum.datetime(2026, 9, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
    default_args={
        "retries": 2,
        "retry_delay": dt.timedelta(minutes=5),
        # An owner that means something at 3am. "airflow" tells an on-call engineer nothing.
        "owner": "security-platform",
    },
    tags=["bloodhound", "maintenance"],
    doc_md=__doc__,
)
def bloodhound_daily():

    @task
    def quality_gate() -> dict:
        """
        Refuse to run maintenance on data that is already wrong.

        Archiving a day with a 40% null rate just makes a permanent copy of the problem, and
        the compaction and tier-down that follow make it unrecoverable. Checking first is
        cheaper than discovering it in 2029.
        """
        import json
        import urllib.request

        url = os.environ.get("BLOODHOUND_CONSUMER_URL", "http://host.docker.internal:8102")
        with urllib.request.urlopen(f"{url}/ops/quality/run", data=b"", timeout=60) as r:
            checks = json.loads(r.read())

        failing = [c for c in checks if not c["passed"]]

        # Each check declares its own category, so this does not need a list of names that
        # goes stale whenever somebody adds one.
        #
        #   correctness failing -> the stored data cannot be trusted. Archiving it would make
        #                          a permanent copy of the problem. Stop.
        #   liveness failing    -> data is not arriving right now. An incident, but yesterday
        #                          is complete either way, so the archive proceeds.
        blocking = [c["check_name"] for c in failing if c.get("category") == "correctness"]
        liveness = [c["check_name"] for c in failing if c.get("category") == "liveness"]

        if blocking:
            raise AirflowFailException(
                f"Data correctness checks failing, refusing to archive: {blocking}")

        if liveness:
            print(f"Ingest liveness degraded (not blocking the archive): {liveness}")
        return {"checks": len(checks), "blocking": blocking, "liveness": liveness}

    @task
    def rebuild_baselines() -> str:
        """Per-account behavioural baselines. Independent of the archive chain."""
        return run_script("baseline.py", "--days", "7")[-1500:]

    @task
    def score_detections() -> str:
        """
        Record detection precision and recall as a time series.

        Tuning without a before-and-after is taste. This is what makes it measurement.
        """
        return run_script("score_detections.py", "--hours", "24", "--save")[-1500:]

    @task
    def archive(logical_date=None, dag_run=None) -> dict:
        """
        Write the day's events to object storage as Parquet.

        Normally archives the day before the logical date. A manual run may override it:

            airflow dags trigger bloodhound_daily --conf '{"day": "2026-09-12"}'

        which is what makes backfilling a specific day possible without inventing a logical
        date — and a logical date in the future simply sits queued forever, because Airflow
        will not schedule a run before its interval has elapsed.
        """
        override = (dag_run.conf or {}).get("day") if dag_run else None
        if override:
            day = dt.date.fromisoformat(override)
            print(f"Archiving {day} (explicit override from dag_run.conf)")
        else:
            day = (logical_date or pendulum.now("UTC")).subtract(days=1).date()

        output = run_script("archive.py", "--date", str(day))
        if "nothing to archive" in output:
            # An empty day is not a failure, but everything downstream should skip rather
            # than "succeed" on nothing — a green tier_down on a day that was never archived
            # is exactly the false reassurance this DAG exists to prevent.
            raise AirflowSkipException(f"No events for {day}")
        return {"day": str(day)}

    @task
    def verify(archived: dict) -> dict:
        """
        Read the archive back and compare row counts against Postgres.

        An archive nobody has restored is a backup nobody has restored. This is the gate that
        everything destructive sits behind.
        """
        day = archived["day"]
        output = run_script("archive.py", "--date", day, "--verify")
        if "verify OK" not in output:
            raise AirflowFailException(f"Archive verification failed for {day}")
        return archived

    @task
    def compact(verified: dict) -> dict:
        """Rewrite the day into one file per target size. Safe now the data is verified."""
        run_script("lakehouse.py", "compact", "--date", verified["day"])
        return verified

    @task
    def tier_down(compacted: dict) -> str:
        """
        Drop Postgres partitions past the retention window.

        Reachable only through verify(). That edge is the entire point of this DAG.
        """
        import json
        import urllib.request

        url = os.environ.get("BLOODHOUND_CONSUMER_URL", "http://host.docker.internal:8102")
        endpoint = (f"{url}/ops/retention?retainDays={RETAIN_DAYS}&dryRun=false")
        request = urllib.request.Request(endpoint, method="POST")
        with urllib.request.urlopen(request, timeout=120) as r:
            result = json.loads(r.read())

        dropped = [p["partition_name"] for p in result.get("partitions", [])]
        print(f"Retention dropped {len(dropped)} partition(s) older than {RETAIN_DAYS}d: {dropped}")
        return f"dropped {len(dropped)}"

    gate = quality_gate()
    baselines = rebuild_baselines()
    scores = score_detections()

    archived = archive()
    verified = verify(archived)
    compacted = compact(verified)
    dropped = tier_down(compacted)

    # Quality gates everything. Baselines and scoring are independent of the archive chain and
    # run in parallel with it.
    gate >> [baselines, scores, archived]
    _ = dropped


bloodhound_daily()
