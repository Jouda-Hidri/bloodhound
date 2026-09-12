# 0004 — Detections as data, and where that stops working

Status: accepted
Date: 2026-09-12

## Context

Detections change constantly — thresholds get tuned, new techniques appear, false positives need
suppressing. If every change is a Java edit, a review and a deploy, tuning does not happen. In a
real team the people with the best ideas about what to detect are frequently not the people who
can ship a service, and a rule format is what closes that gap.

## Decisions

### Rules are YAML, loaded and validated at startup

A rule declares what to match, what to group by, a window, and a threshold. Adding a detection is
adding a file.

```yaml
id: brute-force-single-account
severity: high
technique: T1110.001
match:
  event.action: user-login
  event.outcome: failure
group_by: user.id
entity_type: user
window: PT5M
threshold: 10
```

### Field paths are a closed set, and a typo is a startup failure

`EventFields.SUPPORTED` enumerates every referenceable path. A rule naming `user.emial` fails to
load.

This matters more than it looks. The alternative — resolving paths reflectively or via a JSON
tree — accepts the typo happily and produces a rule that matches nothing, forever, while appearing
in every coverage report as a detection you have. **A silently blind detection is worse than no
detection, because you believe you are covered.**

### The threshold fires once per entity per window

`DetectionState` carries a sticky `alerted` flag. A 500-attempt brute force produces one alert,
not 491. Deduplication across windows is the responder's job; this is deduplication within one.

### Caching is disabled so alerts fire on threshold crossing, not window close

`statestore.cache.max.bytes: 0` makes the aggregate emit on every update. With the default
buffering, an alert would arrive when its window closed — up to five minutes after the attack.
A detection that late is an after-action report.

### The DSL deliberately cannot express everything

Impossible travel is implemented as a hand-written `Processor`, not a rule. It asks "what happened
immediately before this, and was it consistent with it" — a comparison between consecutive events
for one key, with no threshold at all. Bending the DSL to cover that would have meant inventing a
sequence language.

The boundary drawn is: **aggregate over a window** is data; anything stateful across events is
code. Knowing where a declarative abstraction stops paying for itself is most of the skill in
building one — a rule DSL that grows until it is a worse programming language is a well-known way
for a project like this to go wrong.

Consequences of that boundary, accepted knowingly:

- **No rate conditions.** `password-spray-source` and `credential-stuffing-source` overlap by
  design: both ask "one source, many distinct accounts", differing only in window and threshold.
  A fast attack trips both. The DSL has no way to say "many accounts but *not* quickly", because
  it has no notion of rate — only counts within a window. Collapsing the duplicate alerts is left
  to the responder's deduplication rather than solved in the rule.
- **No cross-rule conditions.** A rule cannot reference another rule's output. Correlation happens
  in risk scoring instead.
- **No baseline comparison.** Rules use absolute thresholds. `user_baseline` exists and nothing
  reads it yet.

### Every rule maps to a MITRE ATT&CK technique, enforced by a test

`/rules/coverage` reports what the rule set covers. The mapping is what makes coverage legible to
anyone from the security side, and what makes public Sigma content comparable to ours.

### Sigma export is lossy, and the lossy part is the interesting part

Sigma describes *what to match* very well and *aggregation over time* barely at all — its
`| count() by field > N` extension is informal and most backends ignore it.

So an exported rule matches the right events but will not reproduce the windowing, and an imported
Sigma rule generally needs a threshold invented for it. That gap is precisely why this project has
its own engine rather than running Sigma directly. The aggregation clause is emitted anyway,
because omitting it would make the rule look like it fires on a single event, which would be
actively misleading.

## Costs

**One repartition topic per rule.** Kafka Streams requires unique processor node names, so rules
cannot share a repartition even when they group by the same field. N rules means N extra
round-trips through the broker.

This is tolerable only because the repartition happens *after* each rule's filter — a rule matching
5% of events ships 5% of the stream. A rule with no `match` clause would repartition everything,
which is why one should never be written.

(The first version of this topology named the repartition after the `group_by` field, on the
assumption that rules sharing a field would share the topic. They do not. The topology failed to
build with `Processor by-user-id-repartition-filter is already added` — a useful correction.)

## Known gaps

- Rules are loaded once at startup. Hot reload is deliberately absent: changing a rule under a
  running topology would change the meaning of state stores that are already populated.
- No per-rule enable/disable at runtime — only in the file.
- `suspicious-password-change` matches on user agent, which any attacker defeats by setting a
  browser string. It is kept as a demonstration of `match_any` and as a weak risk-score
  contributor, not as a serious control.
