-- Analyst queries against raw_events.
--
-- These are exploration queries, not detections. Run them, read the output, and get a feel for
-- what normal looks like — that instinct is what Month 3's detection rules are built on.
--
--   make psql
--   \i /dev/stdin   (or just paste one in)


-- ---------------------------------------------------------------------------
-- Ingest health
-- ---------------------------------------------------------------------------

-- Volume and pipeline lag. If avg_lag grows over time, the consumer is falling behind.
-- If it is negative, something is stamping events in the future.
select
    count(*)                                              as events,
    count(distinct user_id)                               as users,
    min(ts)                                               as earliest,
    max(ts)                                               as latest,
    round(avg(extract(epoch from (ingested_at - ts)))::numeric, 3) as avg_lag_s,
    round(max(extract(epoch from (ingested_at - ts)))::numeric, 3) as max_lag_s
from raw_events
where ts > now() - interval '1 hour';

-- Events per minute, by outcome. The shape of normal traffic.
select
    date_trunc('minute', ts) as minute,
    event_outcome,
    count(*)
from raw_events
where ts > now() - interval '30 minutes'
group by 1, 2
order by 1 desc, 2;

-- Duplicate check. Should always be zero: the primary key enforces it.
-- If it is not zero, the dedupe key is wrong.
select event_id, count(*)
from raw_events
group by event_id
having count(*) > 1
limit 10;


-- ---------------------------------------------------------------------------
-- Baseline: what does normal look like?
-- ---------------------------------------------------------------------------

-- The real baseline failure rate, which a brute-force threshold has to sit above.
select
    count(*) filter (where event_outcome = 'failure')::numeric
        / nullif(count(*), 0) as failure_rate,
    count(*)                  as login_attempts
from raw_events
where event_action = 'user-login'
  and ts > now() - interval '1 hour';

-- Per-user activity distribution. Note how skewed it is — a threshold tuned on the median
-- account will fire constantly on the busiest one.
select
    user_id,
    count(*) as events,
    count(*) filter (where event_outcome = 'failure') as failures
from raw_events
where ts > now() - interval '1 hour'
group by user_id
order by events desc
limit 20;

-- Each account's usual countries. The input to an impossible-travel rule.
select
    user_id,
    source_country,
    count(*) as events,
    min(ts)  as first_seen,
    max(ts)  as last_seen
from raw_events
where ts > now() - interval '24 hours'
group by user_id, source_country
order by user_id, events desc
limit 40;


-- ---------------------------------------------------------------------------
-- Detection material
-- ---------------------------------------------------------------------------

-- Brute force: many failures against one account in a short window.
-- MITRE ATT&CK T1110.001.
select
    user_id,
    count(*)                                 as failures,
    count(distinct source_ip)                as distinct_sources,
    min(ts)                                  as first_attempt,
    max(ts)                                  as last_attempt,
    max(ts) - min(ts)                        as duration,
    string_agg(distinct host(source_ip), ', ') as sources
from raw_events
where event_action = 'user-login'
  and event_outcome = 'failure'
  and ts > now() - interval '15 minutes'
group by user_id
having count(*) >= 10
order by failures desc;

-- Credential stuffing: one source against many accounts. Same data, pivoted.
-- MITRE ATT&CK T1110.004.
select
    host(source_ip)                                   as source,
    source_country,
    count(*)                                          as attempts,
    count(distinct user_id)                           as distinct_users,
    count(*) filter (where event_outcome = 'success') as successes,
    max(ts)                                           as last_seen
from raw_events
where event_action = 'user-login'
  and ts > now() - interval '15 minutes'
group by source_ip, source_country
having count(distinct user_id) >= 10
order by distinct_users desc;

-- Successful login from a country the account has never used before.
-- A window function over each user's own history — no baseline table needed yet.
with logins as (
    select
        user_id,
        ts,
        source_country,
        host(source_ip) as source,
        lag(source_country) over (partition by user_id order by ts) as prev_country,
        lag(ts)            over (partition by user_id order by ts) as prev_ts
    from raw_events
    where event_action = 'user-login'
      and event_outcome = 'success'
      and ts > now() - interval '24 hours'
)
select user_id, prev_country, source_country, prev_ts, ts, ts - prev_ts as gap, source
from logins
where prev_country is not null
  and source_country <> prev_country
  and ts - prev_ts < interval '1 hour'   -- too fast to be a real flight
order by ts desc
limit 20;

-- Brute force that ended in a success: the attempt that actually worked.
-- This is the one that becomes a high-severity alert rather than noise.
with failures as (
    select user_id, count(*) as n, max(ts) as last_failure
    from raw_events
    where event_action = 'user-login' and event_outcome = 'failure'
      and ts > now() - interval '1 hour'
    group by user_id
    having count(*) >= 10
)
select
    f.user_id,
    f.n              as preceding_failures,
    s.ts             as compromise_time,
    host(s.source_ip) as source,
    s.source_country
from failures f
join raw_events s
  on s.user_id = f.user_id
 and s.event_action = 'user-login'
 and s.event_outcome = 'success'
 and s.ts between f.last_failure - interval '10 minutes' and f.last_failure + interval '10 minutes'
order by s.ts desc;


-- ---------------------------------------------------------------------------
-- Scoring your detections (Week 11)
-- ---------------------------------------------------------------------------

-- Simulated attacks tag their events. Detections must never read `labels` — but this is how
-- you measure whether a detection found what was actually there.
select
    labels ->> 'scenario'         as scenario,
    labels ->> 'run_id'           as run_id,
    labels ->> 'attack_technique' as technique,
    count(*)                      as events,
    count(distinct user_id)       as users_touched,
    min(ts)                       as started,
    max(ts)                       as ended
from raw_events
where labels is not null
group by 1, 2, 3
order by started desc;


-- ---------------------------------------------------------------------------
-- Storage
-- ---------------------------------------------------------------------------

select
    c.relname                                     as partition,
    pg_size_pretty(pg_total_relation_size(c.oid)) as total_size,
    c.reltuples::bigint                           as approx_rows
from pg_class c
join pg_inherits i on i.inhrelid = c.oid
join pg_class p on p.oid = i.inhparent
where p.relname = 'raw_events'
order by c.relname;

-- Should be empty. Rows here mean that day can no longer be partitioned. See ADR 0002.
select count(*) from raw_events_default;

-- Prove partition pruning works: look for "Partitions removed" in the plan.
explain (analyze, buffers)
select count(*) from raw_events where ts > now() - interval '10 minutes';
