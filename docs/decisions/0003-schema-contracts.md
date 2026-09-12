# 0003 — Schema contracts

Status: accepted
Date: 2026-09-12

## Context

The producer and every consumer deploy independently. The contract between them is implicit, and
implicit contracts get broken by accident. Renaming `user.id` is a one-line change that compiles,
passes tests, and silently blinds every per-user detection in production — the alerts simply stop,
which looks identical to a quiet week.

ADR 0001 deferred this to "Avro + Schema Registry in Week 3". What actually got built differs, and
the reasons are worth recording.

## Decisions

### JSON Schema, not Avro

Avro is more compact and stricter. It was not chosen, and the honest reason is debuggability:
`rpk topic consume` on an Avro topic prints binary. During development, being able to read the
wire format by eye has been worth more than the bytes saved — most of the bugs found so far were
found by looking at a message.

The registry enforces the contract either way. Encoding is a separable decision; switching to Avro
later touches the serializer and nothing else.

### The producer refuses to start on an incompatible schema

`SchemaContract` runs on `ApplicationReadyEvent`: it sets the subject's compatibility mode, checks
the bundled schema against the registered one, and registers it. An incompatible schema throws and
the application does not start.

Verified by renaming `user.id` → `user.userId` and starting the producer:

```
java.lang.IllegalStateException: Event schema is INCOMPATIBLE with the registered version of
subject 'security.events.raw-value'. Backward compatibility allows adding optional fields;
it forbids removing or renaming required ones.
```

That failure lands on the machine of the person who made the change, which is the entire point.

### BACKWARD compatibility

A consumer on the previous schema must still read data written under the new one. That is the
right asymmetry when producers deploy before consumers, which is the usual order.

### The schema is a closed content model, and this is load-bearing

Every object carries `additionalProperties: false`. This is not style. With an open content model
the compatibility checker produces the *opposite* of the intuitive answer:

| change | `additionalProperties: true` | `additionalProperties: false` |
|---|---|---|
| add an optional field | **BREAKING** | compatible |
| remove a required field | compatible | **BREAKING** |
| rename a required field | compatible | **BREAKING** |

Measured, not assumed — the open-model row is what the registry actually returned before the
schema was closed.

The open-model results are technically correct and operationally useless. An open schema already
accepts anything, so adding a typed property *narrows* what it accepts, while dropping a
requirement *widens* it. Left open, the gate would wave through exactly the change that blinds
downstream detections and reject the harmless one — while reporting `is_compatible` with complete
confidence either way. This is the sharpest edge in JSON Schema compatibility.

### Strict about what we send, tolerant in what we accept

The schema is closed, but the consumer sets `FAIL_ON_UNKNOWN_PROPERTIES = false` and ignores
fields it does not recognise. That is deliberate, not contradictory:

- The registry is a **deploy-time** gate on what we agree to publish.
- The consumer is **runtime**-lenient so that a misbehaving producer cannot stop ingestion.

A security pipeline that halts because someone added a field has failed worse than one that
ignores it.

### Confluent's Schema Registry, not Redpanda's

Redpanda ships a registry and it would be the obvious choice. Its JSON Schema support rejects any
schema containing a property literally named `id`, anywhere in the tree.

Minimal reproduction against `redpandadata/redpanda:v24.3.1`:

```bash
# fails
curl -X POST localhost:18085/subjects/probe/versions \
  -H 'Content-Type: application/vnd.schemaregistry.v1+json' \
  -d '{"schemaType":"JSON","schema":"{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"}}}"}'
# {"error_code":422,"message":"bundled schema with mismatched dialect '...' for id key"}

# identical schema, property renamed — succeeds
curl -X POST localhost:18085/subjects/probe2/versions \
  -H 'Content-Type: application/vnd.schemaregistry.v1+json' \
  -d '{"schemaType":"JSON","schema":"{\"type\":\"object\",\"properties\":{\"event_id\":{\"type\":\"string\"}}}"}'
```

It appears to treat a *property named* `id` as the legacy draft-04 `id` keyword. ECS mandates both
`event.id` and `user.id`, so renaming is not available.

`confluentinc/cp-schema-registry` handles the same schema correctly and runs against Redpanda's
Kafka API, so only the URL changed. Worth internalising: "Kafka-compatible" holds reliably at the
protocol level and much less reliably across the surrounding ecosystem.

### Reaching the registry is not required to run

A registry that is down produces a warning, not a startup failure. It is a development-time
guardrail; making it a hard runtime dependency would mean a registry outage stops security
telemetry — a far worse failure than an unverified schema.

## Consequences

- Adding an optional field is a normal change. Removing or renaming a required one requires a new
  subject and a consumer migration, and the build tells you so.
- The schema file is a second place the event shape is written down, and it can drift from the
  Java records. Nothing currently enforces that they agree — a test that serialises a
  `SecurityEvent` and validates it against the schema would close the gap. Not yet written.
- Per-event validation is not performed. The contract is checked at deploy time only; a producer
  that ignores it and publishes malformed events is caught downstream by the consumer's validation
  and dead-lettered.
