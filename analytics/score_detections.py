#!/usr/bin/env python3
"""
Score the detection rules against simulated ground truth.

    python analytics/score_detections.py [--hours 6] [--tolerance-minutes 20] [--save]

This is the most important script in the project.

Everything else answers "did a detection fire?". This answers "was it right?" — and those are
completely different questions. A rule that fires on every attack and also on everything else has
perfect recall and is worthless. Without measurement you cannot tell the two apart, and tuning
becomes taste.

How the scoring works
---------------------
The attack simulator labels every event it produces with `labels.scenario` and `labels.run_id`.
Detections never read those labels; this script is the only consumer of them.

  * An attack **run** is a set of (entity, time range) pairs: the accounts and source addresses a
    simulated attack actually touched.
  * An alert is a **true positive** if its entity was involved in some attack run that overlaps
    its detection window, within a tolerance.
  * An alert with no overlapping attack run is a **false positive**.
  * An attack run that produced no alert at all is a **false negative**.

Two honest caveats, both of which matter more than the numbers:

1. This is entity-level attribution, not rule-level. An alert from the brute-force rule that lands
   on an account being credential-stuffed counts as a true positive — it caught *an* attack, just
   not the one its author had in mind. Real detection work cares about that distinction; this
   script deliberately does not, because rule-to-scenario mapping bakes in assumptions that quietly
   flatter the rules.

2. Background traffic is *not* labelled as benign ground truth, so the false positive count here
   only measures alerts on entities no simulated attack touched. Real false positives include
   alerts that fire on genuine but harmless activity, and those need a human verdict — which is
   what the /alerts/{id}/triage endpoint and the `triage` column exist for.

3. **Detector downtime is scored as missed detection.** The script compares attacks against
   alerts and has no idea whether the detector was running when a given attack happened, so an
   attack fired during a restart is reported identically to one no rule covers. That is the
   difference between "we have no detection for this" and "we had no detection *running*", and
   conflating them will send you tuning rules that were never given a chance.

   Use `--minutes` to score a window you know the detector was up for. Properly, this wants the
   detector's uptime as an input — a real deployment tracks coverage gaps explicitly, because
   "how much of the last week were we actually watching" is a question a SOC has to answer.
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from db import connect, fmt_pct, table_exists

# What each attack run touched. The simulator geotags and labels its events; this reconstructs
# the ground truth from the event store rather than trusting an in-memory record, so it works
# across restarts and against data somebody else generated.
GROUND_TRUTH_SQL = """
select
    labels ->> 'scenario'          as scenario,
    labels ->> 'run_id'            as run_id,
    labels ->> 'attack_technique'  as technique,
    array_agg(distinct user_id) filter (where user_id is not null)      as users,
    array_agg(distinct host(source_ip)) filter (where source_ip is not null) as source_ips,
    min(ts)                        as started,
    max(ts)                        as ended,
    count(*)                       as events
from raw_events
where labels ? 'scenario'
  and ts > now() - make_interval(secs => %(lookback_seconds)s)
group by 1, 2, 3
order by started
"""

# Selected on last_detected_at, not first_detected_at.
#
# Alert deduplication means a re-attack on an entity that already has an open alert updates that
# row rather than creating one — occurrences goes up, first_detected_at does not move. Filtering
# on first_detected_at therefore made a *successfully detected* attack look undetected, purely
# because the alert had been opened before the scoring window began.
#
# Observed: a 30-event brute force against u-00074 reported as 0% recall while the alert sat in
# the database with occurrences=3 and last_detected_at equal to the attack. Deduplication is a
# feature; a scorer that does not account for it measures the wrong thing.
ALERTS_SQL = """
select
    id, rule_id, severity, entity_type, entity_id,
    first_detected_at, last_detected_at, occurrences, triage
from detections.alerts
where last_detected_at > now() - make_interval(secs => %(window_seconds)s)
order by last_detected_at
"""

SAVE_SQL = """
insert into detection_scores (
    window_hours, rule_id, scenario,
    true_positives, false_positives, false_negatives,
    precision, recall, f1, notes
) values (%(hours)s, %(rule_id)s, %(scenario)s, %(tp)s, %(fp)s, %(fn)s,
          %(precision)s, %(recall)s, %(f1)s, %(notes)s)
"""


def overlaps(alert_start, alert_end, attack_start, attack_end, tolerance_seconds):
    """Do an alert's window and an attack's window overlap, allowing for detection delay?"""
    return (alert_start - attack_end).total_seconds() <= tolerance_seconds and \
           (attack_start - alert_end).total_seconds() <= tolerance_seconds


def safe_div(numerator, denominator):
    """None, not zero, when the denominator is zero — 'unmeasurable' is not 'perfect'."""
    return numerator / denominator if denominator else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hours", type=int, default=6, help="scoring window in hours")
    parser.add_argument("--minutes", type=int, default=None,
                        help="scoring window in minutes; overrides --hours. Useful straight "
                             "after a detector restart, when a wider window would include "
                             "attacks fired while nothing was listening and report them as "
                             "missed detections rather than as missing coverage.")
    parser.add_argument("--tolerance-minutes", type=int, default=20,
                        help="how late an alert may be and still count as catching the attack")
    parser.add_argument("--save", action="store_true", help="write results to detection_scores")
    args = parser.parse_args()
    tolerance = args.tolerance_minutes * 60
    window_hours = (args.minutes / 60.0) if args.minutes else args.hours
    # make_interval(hours => ...) rejects a fractional argument; secs takes a double.
    window_seconds = window_hours * 3600.0

    # Ground truth is loaded over a *wider* window than alerts are scored in.
    #
    # Recall is measured over attacks that started inside the window. Precision is measured over
    # alerts active inside it — and those alerts may legitimately refer to an attack that began
    # before it, because deduplication keeps one alert open across repeated attacks. Loading only
    # in-window attacks made every such alert look like a false positive, which is the mirror
    # image of the bug this pairing fixes. Both windows have to be right or one metric lies.
    lookback_seconds = window_seconds * 3 + tolerance * 2

    with connect() as conn:
        if not table_exists(conn, "detections", "alerts"):
            print("No detections.alerts table. Start the responder first.")
            return 1

        with conn.cursor() as cur:
            cur.execute(GROUND_TRUTH_SQL, {"lookback_seconds": lookback_seconds})
            attacks = cur.fetchall()

        with conn.cursor() as cur:
            cur.execute(ALERTS_SQL, {"window_seconds": window_seconds})
            alerts = cur.fetchall()

        if not attacks:
            print(f"No labelled attacks in the last {window_hours * 60:.0f}m. "
                  f"Fire some: make brute-force / make adversary-on")
            return 1

        print(f"Scoring window: {window_hours * 60:.0f}m   tolerance: {args.tolerance_minutes}m")
        print(f"Attack runs: {len(attacks)}   Alerts: {len(alerts)}\n")

        # --- match alerts to attacks -------------------------------------------------
        attack_detected = {}
        per_rule = defaultdict(lambda: {"tp": 0, "fp": 0})
        per_scenario = defaultdict(lambda: {"runs": 0, "detected": 0, "alerts": 0})

        # Recall counts only attacks that began inside the scoring window. The wider set is
        # loaded so alerts can be attributed correctly, not so old attacks count as missed.
        window_start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        in_window = {(a[0], a[1]) for a in attacks if a[5] >= window_start}

        for scenario, run_id, _technique, users, ips, started, ended, _events in attacks:
            if (scenario, run_id) not in in_window:
                continue
            attack_detected[(scenario, run_id)] = False
            per_scenario[scenario]["runs"] += 1

        for (alert_id, rule_id, _severity, entity_type, entity_id,
             first_seen, last_seen, _occurrences, _triage) in alerts:

            # Credit *every* overlapping attack run, not just the first one found.
            #
            # Stopping at the first match was wrong in a way that produced confident nonsense:
            # when several scenarios target the same account at once, each alert was attributed
            # to whichever run happened to be first in the list, and the others were reported as
            # completely undetected. A scoring bug that understates recall is more dangerous than
            # an obvious crash — it sends you tuning rules that were working fine.
            matched = False
            for scenario, run_id, _t, users, ips, started, ended, _e in attacks:
                entities = (users or []) if entity_type == "user" else (ips or [])
                if entity_id in entities and overlaps(first_seen, last_seen, started, ended, tolerance):
                    matched = True
                    # Only in-window attacks are being scored for recall; an older one still
                    # legitimises the alert for precision.
                    if (scenario, run_id) in attack_detected:
                        attack_detected[(scenario, run_id)] = True
                        per_scenario[scenario]["alerts"] += 1

            per_rule[rule_id]["tp" if matched else "fp"] += 1

        for (scenario, run_id), detected in attack_detected.items():
            if detected:
                per_scenario[scenario]["detected"] += 1

        # --- per rule ----------------------------------------------------------------
        print("Per rule")
        print("-" * 78)
        print(f"  {'rule':<34} {'alerts':>7} {'TP':>5} {'FP':>5} {'precision':>10}")
        rows_to_save = []
        for rule_id in sorted(per_rule):
            counts = per_rule[rule_id]
            total = counts["tp"] + counts["fp"]
            precision = safe_div(counts["tp"], total)
            print(f"  {rule_id:<34} {total:>7} {counts['tp']:>5} {counts['fp']:>5} "
                  f"{fmt_pct(precision):>10}")
            rows_to_save.append({
                "hours": window_hours, "rule_id": rule_id, "scenario": None,
                "tp": counts["tp"], "fp": counts["fp"], "fn": 0,
                "precision": precision, "recall": None, "f1": None,
                "notes": "entity-level attribution against simulated ground truth",
            })

        # --- per scenario ------------------------------------------------------------
        print("\nPer attack scenario")
        print("-" * 78)
        print(f"  {'scenario':<26} {'runs':>6} {'detected':>9} {'missed':>7} {'recall':>9}")
        for scenario in sorted(per_scenario):
            stats = per_scenario[scenario]
            missed = stats["runs"] - stats["detected"]
            recall = safe_div(stats["detected"], stats["runs"])
            print(f"  {scenario:<26} {stats['runs']:>6} {stats['detected']:>9} "
                  f"{missed:>7} {fmt_pct(recall):>9}")
            rows_to_save.append({
                "hours": window_hours, "rule_id": None, "scenario": scenario,
                "tp": stats["detected"], "fp": 0, "fn": missed,
                "precision": None, "recall": recall, "f1": None,
                "notes": "run-level recall",
            })

        # --- overall -----------------------------------------------------------------
        total_tp = sum(c["tp"] for c in per_rule.values())
        total_fp = sum(c["fp"] for c in per_rule.values())
        total_runs = sum(s["runs"] for s in per_scenario.values())
        total_detected = sum(s["detected"] for s in per_scenario.values())

        precision = safe_div(total_tp, total_tp + total_fp)
        recall = safe_div(total_detected, total_runs)
        f1 = None
        if precision and recall and (precision + recall):
            f1 = 2 * precision * recall / (precision + recall)

        print("\nOverall")
        print("-" * 78)
        print(f"  precision  {fmt_pct(precision)}   ({total_tp} of {total_tp + total_fp} alerts "
              f"landed on an entity under attack)")
        print(f"  recall     {fmt_pct(recall)}   ({total_detected} of {total_runs} attack runs "
              f"produced at least one alert)")
        print(f"  f1         {fmt_pct(f1)}")

        missed = [f"{s}:{r}" for (s, r), found in attack_detected.items() if not found]
        if missed:
            print(f"\n  Undetected attack runs ({len(missed)}):")
            for run in missed[:15]:
                print(f"    - {run}")
            print("\n  Each of these is a gap. Either the rule that should cover it is tuned too")
            print("  high, or there is no rule for it at all. Both are worth writing down.")

        if args.save:
            with conn.cursor() as cur:
                for row in rows_to_save:
                    cur.execute(SAVE_SQL, row)
            conn.commit()
            print(f"\n  Saved {len(rows_to_save)} rows to detection_scores.")
            print("  Re-run after tuning to see whether you improved anything or just moved it.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
