# Eleven things that broke

The third of three write-ups on Bloodhound. The [first](01-architecture.md) covered the
architecture, the [second](02-detection-quality.md) covered measuring detection quality.

This one is the failures, kept because they were the useful part. Several are not bugs in this
project at all — they are places where a tool behaves reasonably and the reasonable behaviour is
the opposite of what you assume.

---

## 1. A detection found a bug in the data generator

`distributed-brute-force` counts distinct source addresses per account. It flooded with false
positives on ordinary users.

The simulator drew a **fresh random IP for every event**, so any account with five failures
looked attacked from five addresses. Real users have one or two addresses that change rarely.

**Source-diversity detection is untestable when the baseline already looks like an attack.** The
detection was correct; the world it was detecting in was wrong.

## 2. JSON Schema compatibility is inverted for open content models

With `additionalProperties: true`:

| change | registry says |
|---|---|
| add an optional field | **BREAKING** |
| remove a required field | compatible |

Both technically correct — an open schema already accepts anything, so adding a typed property
*narrows* it while dropping a requirement *widens* it. And both operationally useless: the gate
would wave through exactly the change that blinds every downstream detection, and reject the
harmless one.

Closing the content model (`additionalProperties: false`) inverts it back to the intuitive
answers. The registry reports `is_compatible` with complete confidence either way.

## 3. Redpanda's schema registry rejects any property named `id`

```
{"error_code":422,"message":"bundled schema with mismatched dialect '...' for id key"}
```

It appears to treat a *property named* `id` as the legacy draft-04 `id` keyword. ECS mandates
both `event.id` and `user.id`.

Fixed by running Confluent's registry against Redpanda's Kafka API. **"Kafka-compatible" holds
reliably at the protocol level and much less reliably across the surrounding ecosystem.**

## 4. The bucket policy locked Terraform out of its own bucket

The audit-trail bucket denies deletion, which is the point — destroying logs is a standard
post-compromise step. The first version also denied `s3:PutLifecycleConfiguration`.

Terraform applies the bucket policy *before* the lifecycle rule, so the next resource was refused
by the policy just created. The error body was empty, which reads like an emulator bug and is
not.

**An explicit `Deny` on `Principal: "*"` applies to the bucket owner and to whatever manages the
infrastructure.** There is no implicit exemption for "us". Protecting configuration actions needs
a condition exempting the deployment principal.

## 5. Spring Boot auto-registers every `Filter` bean

The API-key filter was a `@Component` extending `OncePerRequestFilter`, so it ran on every
request regardless of the security filter chain. After switching to OIDC it rejected perfectly
valid bearer tokens with:

```
{"error":"missing or invalid X-Api-Key header"}
```

A 401 naming the wrong mechanism entirely. The fix is a `FilterRegistrationBean` with
`setEnabled(false)`, which leaves the filter available to be added to the chain deliberately.

## 6. Index templates apply only at index creation

The OpenSearch indexer installed its template *after* its first successful write. The index was
already created with dynamic mappings, so `source.ip` was typed `text` rather than `ip`, and CIDR
queries returned zero hits — silently, because zero is a valid answer.

**Dynamic mapping is sticky.** The only fix afterwards is delete and reindex. The template has to
be in place before the first document, not after.

## 7. The broker auto-created Kafka Streams' internal topics

Redpanda created the repartition topics with one partition before Streams could create them with
six, and the client shut itself down:

```
Existing internal topic ...-repartition has invalid partitions: expected: 6; actual: 1
```

Auto-creation is now off and all topics are declared explicitly — which also means a typo in a
topic name fails loudly instead of quietly publishing into a brand new topic nobody reads.

## 8. The HTTP proxy JSON-encodes the key

Publishing baselines with `vnd.kafka.json.v2+json` put `"u-00000"` on the topic — **quotes
included** — while the detector looked up `u-00000`.

The `GlobalKTable` was fully populated. Every lookup missed. The rule produced nothing, with no
error anywhere. Fixed by using the binary format with base64, which hands over exact bytes.

Adjacent, same afternoon: a `GlobalKTable`'s store is *timestamped*, so it returns
`ValueAndTimestamp<V>`. Declaring it as `ReadOnlyKeyValueStore<K, V>` compiles cleanly — generics
are erased — and throws `ClassCastException` on the first lookup, taking the stream thread down.
And a global store must **not** be named in `process(...)`, which is the opposite of the rule for
ordinary state stores.

## 9. Deduplication silently downgraded severity

Alerts deduplicate on (rule, entity) while open. The update incremented the occurrence count and
never touched severity — so a HIGH firing was absorbed into an open LOW alert and a genuinely
worse situation sat in the console still labelled LOW.

Severity now escalates on merge and never downgrades. **Of the two directions this could be wrong
in, that was the dangerous one.**

## 10. A data quality check that cried wolf

`max_lag_seconds` failed on every simulated attack, because the simulator back-dates a burst
across the minutes it would really have taken — indistinguishable from pipeline lag.

It now measures organic traffic only. **A red light that means nothing is worse than no light,
because people stop looking at it.**

This one generalised: data quality checks turned out to answer two different questions —
*liveness* (is data arriving?) and *correctness* (is the data trustworthy?) — and the nightly job
needs to treat them differently. Archiving yesterday while ingestion is stopped is fine;
archiving yesterday when yesterday is full of nulls is not. Each check now declares its own
category, so the orchestrator does not need a hard-coded list of names that goes stale.

## 11. Deduplication made a working detection look broken

A 30-event brute force landed, the detector was confirmed `RUNNING`, and the scorer reported
**0% recall**.

The alert had fired correctly. It had been *deduplicated* into an alert opened 27 minutes
earlier — `occurrences=3`, `last_detected_at` exactly matching the attack. The scorer filtered on
`first_detected_at`, so an alert that already existed looked like an alert that never happened.

Fixing that naively broke the other metric: selecting alerts on `last_detected_at` pulled in
alerts whose ground-truth attack sat *outside* the window, and precision fell to 44%. Both
windows have to be right independently — recall is measured over attacks that started in the
window, precision over alerts active in it, and the ground truth is loaded over a wider span so
alerts can be attributed to attacks that began before the window opened.

**Deduplication is a feature. A scorer that does not account for it measures the wrong thing —
in both directions, one metric at a time.**

---

## The pattern

Six of these eleven are cases where **a tool did something reasonable that was the opposite of what
I assumed**, and the symptom pointed somewhere other than the cause:

- an empty Terraform error that was an IAM policy
- a 401 naming API keys in an OIDC deployment
- zero search results from a mapping decision made days earlier
- a rule producing nothing because of two quote characters
- a schema registry confidently approving the breaking change

None was found by reading the code. All were found by running the thing and being suspicious of
the output — which is the actual argument for measuring, testing under load, and running attack
scenarios concurrently rather than one at a time.

The other five were mine: a simulator too random to detect against, a scoring script that
understated recall by 3×, a baseline too short to mean anything, a dedupe that lost severity, and
a scorer that reported a working detection as a total failure.

**Four of those five were in the measurement, not the system.** Every time, the instrument said
something specific and confident and wrong, and the system it was measuring was fine. The
temptation each time was to go and fix the detection.

Instrument the instruments.
