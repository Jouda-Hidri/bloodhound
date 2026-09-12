# 0001 — Event schema and transport

Status: accepted; the schema-registry section is superseded by
[0003](0003-schema-contracts.md)
Date: 2026-09-11

> **Later note (2026-09-12).** Two things below did not survive contact with Week 3, and are left
> unedited because being wrong in a recorded way is the point of an ADR:
>
> - *"Avro + Schema Registry in Week 3"* — JSON Schema was used instead, for debuggability.
> - *"the registry is already running in Docker Compose (port 18081)"* — Redpanda's registry
>   cannot represent this schema at all (it rejects any property named `id`, and ECS mandates two).
>   Confluent's registry runs against Redpanda's broker instead, on port 18085.
>
> Everything else here still holds. See [0003](0003-schema-contracts.md).

## Context

Everything downstream — detections, enrichment, storage layout, the eventual search tier — reads
the event schema. Getting it wrong is expensive later, because rewriting a schema means rewriting
every rule written against it.

## Decisions

### Elastic Common Schema (ECS) field names, not our own

`@timestamp`, `event.action`, `event.outcome`, `source.ip`, `user.id`.

ECS is what Elastic/OpenSearch, most SIEM content, and the Sigma rule library already speak.
Inventing `eventType` and `sourceIp` would mean writing a translation layer before any of that
could be reused, and would make the project unreadable to anyone from the security side.

The cost is verbosity — `source.geo.country_iso_code` rather than `country`. Worth it.

### JSON on the wire for now, Avro + Schema Registry in Week 3

JSON is debuggable: `rpk topic consume` shows readable events, which matters a lot while the
pipeline is still being built. It is also untyped and roughly 3× the size of Avro.

The registry is already running in Docker Compose (port 18081), unused, so that switching is a
code change rather than an infrastructure change.

### `event.action` and `event.category` are enums, not free text

ECS treats these as strings. Constraining them means a typo in a detection rule is a compile
error instead of a rule that silently matches nothing — the most common and most dangerous
failure mode in detection engineering.

Unknown values deserialise to `UNKNOWN` rather than throwing, so a newer producer cannot take the
consumer down. Unknown JSON fields are ignored for the same reason.

### Partition key is `user.id`

All of one account's events land on one partition, in order. This is what makes per-user windowed
aggregation possible in Week 6 without a repartition step.

The cost is skew: a service account with 1000× the traffic of a human becomes a hot partition.
Accepted for now; revisit if one partition's lag diverges from the others.

### `acks=all` with idempotent producer

Security telemetry that silently drops events is worse than no telemetry, because it produces
confident wrong answers. The throughput cost is real and will be measured in Week 16.

## Consequences

- Detections can be written against the same field names as public Sigma rules.
- Adding a field is backward compatible; renaming or removing one is not, and after Week 3 the
  registry will reject it outright.
- Any external log source (CloudTrail in Week 20) needs a mapping layer into ECS. That mapping
  is where most real SIEM engineering effort actually goes.
