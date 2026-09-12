#!/usr/bin/env python3
"""
Rebuild per-account behavioural baselines from the raw event store.

    python analytics/baseline.py [--days 7] [--show 15]

Why this exists: threshold rules treat every account the same. A baseline lets a detection ask
"is this unusual *for this account*", which is what separates a rule that works on the median
user from one that works on the whole population.

This is a batch job by design. It reads a week of history, writes a summary table, and the
detection path never touches it during ingestion — mixing a batch aggregate into a streaming hot
path is how pipelines acquire mysterious latency spikes.
"""

import argparse
import sys

from db import connect

# Computed entirely in SQL. Pulling a million rows into Python to group them would be slower,
# use more memory, and obscure the one thing worth reading here — the aggregation itself.
BASELINE_SQL = """
with recent as (
    select *
    from raw_events
    where ts > now() - make_interval(days => %(days)s)
      and user_id is not null
),
per_user as (
    select
        user_id,
        count(*)                                                        as total_events,
        count(*) filter (where event_action = 'user-login')             as logins,
        count(*) filter (where event_action = 'user-login'
                           and event_outcome = 'failure')               as login_failures,
        count(distinct source_ip)                                       as distinct_source_ips,
        count(distinct source_country)                                  as distinct_countries,
        count(distinct user_agent)                                      as distinct_user_agents,
        array_agg(distinct source_country)
            filter (where source_country is not null)                   as countries,
        array_agg(distinct user_agent)
            filter (where user_agent is not null)                       as user_agents,
        array_agg(distinct extract(hour from ts at time zone 'UTC')::int) as active_hours,
        min(ts)                                                         as first_seen,
        max(ts)                                                         as last_seen
    from recent
    group by user_id
),
-- Mode, not max: the country an account is *usually* in, which is the one worth comparing
-- against. A single login from elsewhere should not redefine where someone normally works.
primary_country as (
    select distinct on (user_id) user_id, source_country
    from recent
    where source_country is not null
    group by user_id, source_country
    order by user_id, count(*) desc
),
peak_hour as (
    select distinct on (user_id)
        user_id, extract(hour from ts at time zone 'UTC')::int as hour
    from recent
    group by user_id, extract(hour from ts at time zone 'UTC')
    order by user_id, count(*) desc
)
insert into user_baseline (
    user_id, computed_at, window_days, total_events, logins, login_failures,
    failure_rate, events_per_day, countries, primary_country, distinct_countries,
    distinct_source_ips, user_agents, distinct_user_agents, active_hours, peak_hour,
    first_seen, last_seen, dormant_days
)
select
    p.user_id,
    now(),
    %(days)s,
    p.total_events,
    p.logins,
    p.login_failures,
    round(p.login_failures::numeric / nullif(p.logins, 0), 4),
    round(p.total_events::numeric / %(days)s, 2),
    p.countries,
    c.source_country,
    p.distinct_countries,
    p.distinct_source_ips,
    p.user_agents,
    p.distinct_user_agents,
    p.active_hours,
    h.hour,
    p.first_seen,
    p.last_seen,
    round(extract(epoch from (now() - p.last_seen)) / 86400.0, 2)
from per_user p
left join primary_country c on c.user_id = p.user_id
left join peak_hour h on h.user_id = p.user_id
on conflict (user_id) do update set
    computed_at          = excluded.computed_at,
    window_days          = excluded.window_days,
    total_events         = excluded.total_events,
    logins               = excluded.logins,
    login_failures       = excluded.login_failures,
    failure_rate         = excluded.failure_rate,
    events_per_day       = excluded.events_per_day,
    countries            = excluded.countries,
    primary_country      = excluded.primary_country,
    distinct_countries   = excluded.distinct_countries,
    distinct_source_ips  = excluded.distinct_source_ips,
    user_agents          = excluded.user_agents,
    distinct_user_agents = excluded.distinct_user_agents,
    active_hours         = excluded.active_hours,
    peak_hour            = excluded.peak_hour,
    first_seen           = excluded.first_seen,
    last_seen            = excluded.last_seen,
    dormant_days         = excluded.dormant_days
"""

DISTRIBUTION_SQL = """
select
    count(*)                                              as accounts,
    round(avg(events_per_day), 1)                         as mean_events_per_day,
    round(percentile_cont(0.5) within group (order by events_per_day)::numeric, 1)  as median,
    round(percentile_cont(0.95) within group (order by events_per_day)::numeric, 1) as p95,
    round(max(events_per_day), 1)                         as max,
    round(avg(failure_rate), 4)                           as mean_failure_rate,
    round(avg(distinct_countries), 2)                     as mean_countries
from user_baseline
"""

OUTLIERS_SQL = """
select user_id, events_per_day, failure_rate, distinct_countries,
       distinct_source_ips, primary_country, dormant_days
from user_baseline
order by events_per_day desc
limit %(show)s
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=7, help="history window in days")
    parser.add_argument("--show", type=int, default=10, help="busiest accounts to print")
    args = parser.parse_args()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(BASELINE_SQL, {"days": args.days})
            written = cur.rowcount
        conn.commit()

        print(f"Rebuilt baselines for {written} accounts over {args.days} day(s).\n")

        with conn.cursor() as cur:
            cur.execute(DISTRIBUTION_SQL)
            row = cur.fetchone()
            if not row or not row[0]:
                print("No baseline rows. Is the pipeline running?")
                return 1
            cols = [d.name for d in cur.description]

        print("Population shape")
        print("-" * 60)
        for name, value in zip(cols, row):
            print(f"  {name:22} {value}")

        # The gap between median and p95 is the whole lesson. A threshold tuned on the median
        # account fires constantly on the top 5%, and those are usually the service accounts —
        # the ones an attacker most wants.
        median, p95 = row[2], row[3]
        if median and p95:
            print(f"\n  p95 is {p95 / median:.1f}x the median. Any fixed per-account threshold")
            print("  will be either blind for the busy accounts or noisy for the quiet ones.")

        print(f"\nBusiest {args.show} accounts")
        print("-" * 60)
        with conn.cursor() as cur:
            cur.execute(OUTLIERS_SQL, {"show": args.show})
            print(f"  {'user':<12} {'ev/day':>8} {'fail':>7} {'ctry':>5} {'ips':>5}  home  dormant")
            for user_id, per_day, fail, countries, ips, country, dormant in cur.fetchall():
                fail_str = f"{fail:.3f}" if fail is not None else "    -"
                print(f"  {user_id:<12} {per_day:>8} {fail_str:>7} {countries:>5} "
                      f"{ips:>5}  {country or '--':<5} {dormant}d")

    return 0


if __name__ == "__main__":
    sys.exit(main())
