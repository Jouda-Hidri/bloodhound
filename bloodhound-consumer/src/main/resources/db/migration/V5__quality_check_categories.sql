-- Data quality checks answer two different questions, and conflating them makes the results
-- unusable for automation.
--
--   liveness    — is data arriving right now? (freshness, lag, cardinality)
--   correctness — is the data that arrived trustworthy? (nulls, unknowns, dead letters)
--
-- The orchestrator needs the distinction. Archiving yesterday's events is perfectly safe while
-- ingestion is stopped — yesterday is complete either way — but it is never safe when yesterday
-- is full of nulls. Without a category, a paused producer blocks the archive for no reason,
-- and the obvious workaround (hard-code the exempt check names in the DAG) goes stale the
-- moment somebody adds a check.

alter table data_quality_checks
    add column if not exists category text not null default 'correctness'
        check (category in ('liveness', 'correctness'));

create index if not exists dq_checks_category_idx
    on data_quality_checks (category, checked_at desc);

-- Reclassify the rows already recorded, so history stays comparable.
update data_quality_checks
set category = 'liveness'
where check_name in ('freshness_seconds', 'max_lag_seconds', 'distinct_users_hourly');
