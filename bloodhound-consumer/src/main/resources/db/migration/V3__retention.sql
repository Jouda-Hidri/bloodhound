-- Retention: drop whole partitions instead of deleting rows.
--
-- A DELETE of a month of events rewrites the heap, leaves dead tuples behind, needs a vacuum, and
-- holds locks the whole time. Dropping a partition is a catalogue update — effectively instant,
-- regardless of how many rows it held. This is the payoff for partitioning, and the reason it was
-- worth the maintenance burden.

create or replace function drop_old_event_partitions(p_retain_days integer, p_dry_run boolean default false)
returns table (partition_name text, dropped boolean)
language plpgsql as $$
declare
    cutoff date := current_date - p_retain_days;
    rec    record;
begin
    if p_retain_days < 1 then
        raise exception 'Refusing to run retention with retain_days=% (must be >= 1)', p_retain_days;
    end if;

    for rec in
        select c.relname
        from pg_class c
        join pg_inherits i on i.inhrelid = c.oid
        join pg_class p on p.oid = i.inhparent
        where p.relname = 'raw_events'
          -- Only the dated partitions. raw_events_default is never dropped automatically:
          -- rows land there precisely because something was wrong with them, and silently
          -- deleting the evidence is the opposite of what a security platform should do.
          and c.relname ~ '^raw_events_[0-9]{8}$'
          and to_date(right(c.relname, 8), 'YYYYMMDD') < cutoff
        order by c.relname
    loop
        partition_name := rec.relname;
        if p_dry_run then
            dropped := false;
        else
            execute format('drop table %I', rec.relname);
            dropped := true;
        end if;
        return next;
    end loop;
end;
$$;

comment on function drop_old_event_partitions(integer, boolean) is
    'Drop raw_events partitions older than p_retain_days. Pass p_dry_run to preview.';


-- Data quality snapshots, so quality is a trend rather than a spot check.
create table if not exists data_quality_checks (
    id          bigserial primary key,
    checked_at  timestamptz not null default now(),
    check_name  text        not null,
    passed      boolean     not null,
    observed    numeric,
    threshold   numeric,
    detail      text
);

create index if not exists dq_checks_name_time_idx on data_quality_checks (check_name, checked_at desc);
