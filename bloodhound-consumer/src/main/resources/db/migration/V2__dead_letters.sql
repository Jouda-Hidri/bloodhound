-- Messages the pipeline could not process, persisted for inspection and replay.
--
-- A dead letter queue only helps if somebody looks at it. Mirroring the DLQ topic into a table
-- means the backlog is queryable alongside everything else, and gives replay somewhere to record
-- that it happened.

create table if not exists dead_letters (
    id              bigserial primary key,
    failed_at       timestamptz not null,
    recorded_at     timestamptz not null default now(),

    source_topic    text        not null,
    source_partition integer    not null,
    source_offset   bigint      not null,
    source_key      text,

    failure_type    text        not null,
    failure_reason  text,
    consumer        text,

    payload         text        not null,

    -- Replay bookkeeping. A dead letter replayed and still failing comes back with a new row,
    -- so replay_count on the original stays an honest record of how many attempts were made.
    replayed_at     timestamptz,
    replay_count    integer     not null default 0,

    -- One row per failed message, not one per delivery attempt. Redelivery of the same broken
    -- offset must not grow this table without bound.
    unique (source_topic, source_partition, source_offset)
);

create index if not exists dead_letters_failed_at_idx on dead_letters (failed_at desc);
create index if not exists dead_letters_type_idx      on dead_letters (failure_type, failed_at desc);

comment on table dead_letters is
    'Messages that failed parsing, validation or persistence. Non-empty is an alertable condition.';
