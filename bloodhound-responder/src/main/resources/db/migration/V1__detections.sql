-- Detection-side state: alerts, incidents, risk, response actions, audit.
--
-- This lives in its own schema with its own Flyway history table. Two services sharing one
-- `public` schema and both running migrations is a race waiting to happen — whichever starts
-- first wins, and neither owns the result. Schema-per-service keeps ownership unambiguous while
-- still allowing cross-schema joins for analysis.


-- ---------------------------------------------------------------------------
-- Alerts
-- ---------------------------------------------------------------------------

create table if not exists alerts (
    id                text        primary key,
    dedupe_key        text        not null,

    first_detected_at timestamptz not null,
    last_detected_at  timestamptz not null,
    occurrences       integer     not null default 1,

    rule_id           text        not null,
    rule_name         text,
    severity          text        not null,
    technique         text,

    entity_type       text        not null,
    entity_id         text        not null,

    observed          bigint,
    threshold         bigint,
    window_start      timestamptz,
    window_end        timestamptz,

    context           jsonb,
    sample_event_ids  text[],

    -- open: the condition is current. closed: it stopped recurring and was rolled up.
    active            boolean     not null default true,

    -- Analyst verdict, fed back into rule tuning. This column is the entire point of the
    -- precision/recall work: without a human saying "this was wrong", there is nothing to tune on.
    triage            text        not null default 'untriaged'
                      check (triage in ('untriaged', 'true_positive', 'false_positive', 'benign')),
    triaged_at        timestamptz,
    triaged_by        text,
    triage_note       text,

    incident_id       bigint
);

-- One open alert per ongoing condition. This partial unique index *is* the deduplication:
-- a hundred repeats of the same rule firing on the same entity update one row's occurrence
-- count instead of creating a hundred rows. Alert fatigue is the most common way a real
-- detection programme dies, and it dies here if this index is missing.
create unique index if not exists alerts_open_dedupe_idx
    on alerts (dedupe_key) where active;

create index if not exists alerts_entity_idx   on alerts (entity_type, entity_id, last_detected_at desc);
create index if not exists alerts_rule_idx     on alerts (rule_id, first_detected_at desc);
create index if not exists alerts_severity_idx on alerts (severity, last_detected_at desc);
create index if not exists alerts_triage_idx   on alerts (triage, last_detected_at desc);


-- ---------------------------------------------------------------------------
-- Risk
-- ---------------------------------------------------------------------------

-- Current risk per entity. Decay is applied on read and on update rather than by a sweeper job,
-- so a score is always correct as of the moment it is asked for.
create table if not exists risk_scores (
    entity_type  text        not null,
    entity_id    text        not null,
    score        numeric     not null default 0,
    peak_score   numeric     not null default 0,
    updated_at   timestamptz not null default now(),
    peaked_at    timestamptz,
    primary key (entity_type, entity_id)
);

create index if not exists risk_scores_score_idx on risk_scores (score desc);


-- ---------------------------------------------------------------------------
-- Incidents
-- ---------------------------------------------------------------------------

create table if not exists incidents (
    id           bigserial   primary key,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),

    -- new -> triaged -> investigating -> contained -> resolved, or -> false_positive
    status       text        not null default 'new'
                 check (status in ('new','triaged','investigating','contained','resolved','false_positive')),

    severity     text        not null,
    title        text        not null,
    entity_type  text        not null,
    entity_id    text        not null,
    risk_score   numeric,
    assignee     text,
    closed_at    timestamptz,
    resolution   text
);

create index if not exists incidents_status_idx on incidents (status, created_at desc);
create index if not exists incidents_entity_idx on incidents (entity_type, entity_id);

-- At most one open incident per entity, so a sustained attack produces one investigation rather
-- than a new incident for every alert it generates.
create unique index if not exists incidents_open_entity_idx
    on incidents (entity_type, entity_id)
    where status not in ('resolved', 'false_positive');

create table if not exists incident_notes (
    id          bigserial   primary key,
    incident_id bigint      not null references incidents(id) on delete cascade,
    at          timestamptz not null default now(),
    author      text        not null,
    note        text        not null
);

create index if not exists incident_notes_incident_idx on incident_notes (incident_id, at);


-- ---------------------------------------------------------------------------
-- Response
-- ---------------------------------------------------------------------------

create table if not exists response_actions (
    id            bigserial   primary key,
    incident_id   bigint      references incidents(id) on delete set null,
    alert_id      text,

    action        text        not null,
    target_type   text        not null,
    target_id     text        not null,
    reason        text,

    -- proposed -> approved -> executed, or -> rejected / failed.
    -- A destructive action that lands in `proposed` and stays there is the system working as
    -- designed, not a bug: someone has to say yes.
    status        text        not null default 'proposed'
                  check (status in ('proposed','approved','executed','failed','rejected','reverted')),

    requires_approval boolean not null default true,
    reversible        boolean not null default false,

    proposed_at   timestamptz not null default now(),
    approved_at   timestamptz,
    approved_by   text,
    executed_at   timestamptz,
    result        text,
    error         text,
    reverted_at   timestamptz,
    reverted_by   text
);

create index if not exists response_actions_status_idx   on response_actions (status, proposed_at desc);
create index if not exists response_actions_incident_idx on response_actions (incident_id);
create index if not exists response_actions_target_idx   on response_actions (target_type, target_id);


-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

-- Append-only. Every state change anyone or anything makes goes here.
--
-- On a platform that can disable accounts, the audit log is not paperwork — it is the only way to
-- answer "why was this user locked out at 3am" after the fact, and the only defence if the
-- automation itself is ever abused.
create table if not exists audit_log (
    id           bigserial   primary key,
    at           timestamptz not null default now(),
    actor        text        not null,
    action       text        not null,
    subject_type text,
    subject_id   text,
    outcome      text        not null,
    detail       jsonb
);

create index if not exists audit_log_at_idx      on audit_log (at desc);
create index if not exists audit_log_subject_idx on audit_log (subject_type, subject_id, at desc);
create index if not exists audit_log_actor_idx   on audit_log (actor, at desc);

comment on table audit_log is 'Append-only record of every action taken. Never updated, never deleted.';
