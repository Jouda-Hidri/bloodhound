-- Per-account behavioural baselines, rebuilt by analytics/baseline.py.
--
-- A threshold rule asks "is this a lot?". A baseline lets you ask "is this a lot *for them?*" —
-- which is the difference between a rule that works on the median account and one that works on
-- the whole population. Twenty logins an hour is alarming for a person and unremarkable for a
-- service account.

create table if not exists user_baseline (
    user_id             text        primary key,
    computed_at         timestamptz not null default now(),
    window_days         integer     not null,

    -- Volume
    total_events        bigint      not null default 0,
    logins              bigint      not null default 0,
    login_failures      bigint      not null default 0,
    failure_rate        numeric,
    events_per_day      numeric,

    -- Where they normally are
    countries           text[],
    primary_country     text,
    distinct_countries  integer     not null default 0,
    distinct_source_ips integer     not null default 0,

    -- What they normally use
    user_agents         text[],
    distinct_user_agents integer    not null default 0,

    -- When they are normally active (UTC hours, 0-23)
    active_hours        integer[],
    peak_hour           integer,

    first_seen          timestamptz,
    last_seen           timestamptz,
    -- Days since last activity. Dormancy is only meaningful measured against real history.
    dormant_days        numeric
);

create index if not exists user_baseline_dormant_idx on user_baseline (dormant_days desc);
create index if not exists user_baseline_country_idx on user_baseline (primary_country);

comment on table user_baseline is
    'Rebuilt on a schedule from raw_events. Never written by the ingest path.';


-- Scoring runs: how well detections performed against simulated ground truth.
-- Kept as a time series so tuning has a before and after rather than an opinion.
create table if not exists detection_scores (
    id             bigserial   primary key,
    scored_at      timestamptz not null default now(),
    window_hours   integer     not null,

    rule_id        text,
    scenario       text,

    true_positives  integer    not null default 0,
    false_positives integer    not null default 0,
    false_negatives integer    not null default 0,

    precision      numeric,
    recall         numeric,
    f1             numeric,
    notes          text
);

create index if not exists detection_scores_rule_idx on detection_scores (rule_id, scored_at desc);
create index if not exists detection_scores_time_idx on detection_scores (scored_at desc);
