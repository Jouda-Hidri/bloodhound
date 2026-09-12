-- Raw security event store.
--
-- Design notes:
--  * Hot query columns are extracted; the full ECS document is kept in `raw`. Detections read
--    columns (fast, indexed); investigators read `raw` (complete, including fields we have not
--    thought to extract yet).
--  * Range-partitioned by day. Retention then becomes DROP PARTITION rather than a DELETE that
--    rewrites the table, and time-bounded queries prune to the days they need.
--  * The primary key (event_id, ts) is the deduplication key. It must include the partition
--    column — Postgres requires it — which is why it is composite rather than just event_id.

create table if not exists raw_events (
    event_id            text        not null,
    ts                  timestamptz not null,
    ingested_at         timestamptz not null default now(),

    event_category      text,
    event_action        text,
    event_outcome       text,
    event_reason        text,

    user_id             text,
    user_name           text,
    user_domain         text,

    source_ip           inet,
    source_port         integer,
    source_country      text,
    source_city         text,

    service_name        text,
    service_environment text,
    user_agent          text,

    labels              jsonb,
    raw                 jsonb       not null,

    primary key (event_id, ts)
) partition by range (ts);

comment on table raw_events is 'Immutable append-only log of security events, ECS-shaped.';
comment on column raw_events.ts is 'Event time (when it happened), not ingest time.';
comment on column raw_events.ingested_at is 'Processing time. ts - ingested_at is pipeline lag.';
comment on column raw_events.labels is 'Simulation ground truth. Detections must not read this.';

-- Indexes declared on the parent are created on every partition, existing and future.
create index if not exists raw_events_user_ts_idx   on raw_events (user_id, ts desc);
create index if not exists raw_events_source_ts_idx on raw_events (source_ip, ts desc);
create index if not exists raw_events_action_ts_idx on raw_events (event_action, event_outcome, ts desc);


-- Creates the daily partition for one day if it does not exist yet.
create or replace function ensure_event_partition(p_day date) returns boolean
language plpgsql as $$
declare
    part_name text := format('raw_events_%s', to_char(p_day, 'YYYYMMDD'));
begin
    if to_regclass(part_name) is not null then
        return false;
    end if;
    execute format(
        'create table %I partition of raw_events for values from (%L) to (%L)',
        part_name, p_day, p_day + 1);
    return true;
end;
$$;

comment on function ensure_event_partition(date) is
    'Idempotently create the daily partition for p_day. Returns true if it was created.';


-- Creates every daily partition in [p_from, p_to]. Called on a schedule by the consumer.
create or replace function ensure_event_partitions(p_from date, p_to date) returns integer
language plpgsql as $$
declare
    d       date := p_from;
    created integer := 0;
begin
    while d <= p_to loop
        if ensure_event_partition(d) then
            created := created + 1;
        end if;
        d := d + 1;
    end loop;
    return created;
end;
$$;


-- Safety net for events whose timestamp falls outside any existing partition, which would
-- otherwise fail the insert outright.
--
-- The catch, and it is a real one: a day that has rows sitting in the default partition can no
-- longer have its own partition attached. The maintenance job is what keeps this empty; if rows
-- ever appear here, they have to be moved out before the day's partition can be created.
-- Watch it: select count(*) from raw_events_default;
create table if not exists raw_events_default partition of raw_events default;


-- Bootstrap a window around today so the very first insert has somewhere to go.
select ensure_event_partitions(current_date - 7, current_date + 7);
