# Five-minute demo

A run sheet for showing the platform end to end: attack → detection → alert → risk → incident →
containment → audit → revert. Timings assume everything is already running.

## Before you start

```bash
make up                       # infra
make build                    # compile and test
# four terminals:
make consumer                 # 8102
make detector                 # 8103
make responder                # 8104
make producer                 # 8101
```

Leave it running for **at least an hour** before recording. Baselines need history, and the
detector's windows need to have seen normal traffic — a demo on a cold start shows a platform
with no idea what normal is, which is the least interesting version of it.

```bash
make baseline && make publish-baselines    # so baseline-relative rules have something to compare
```

---

## 0:00 — What it is (30s)

> "Applications emit security events. This detects attacks in them, scores risk per account,
> opens incidents, and can contain an account — with a human in the loop. Everything you'll see
> is real: real Kafka, real stream processing, real Postgres, real containment."

Show the architecture diagram in the README. Do not read it out.

## 0:30 — Normal traffic (30s)

```bash
make stats
```

> "200 simulated accounts, about 20 events a second. Roughly 6% of logins fail for ordinary
> reasons — that noise floor is deliberate. Without it any brute-force rule scores perfectly and
> teaches you nothing."

## 1:00 — Attack (45s)

```bash
make attack-all
```

> "Seven attack scenarios: brute force, credential stuffing, password spraying, impossible
> travel, session hijack, privilege escalation, API key abuse. Every event they emit is labelled
> with ground truth, so I can score the detections later. The detections never read those
> labels."

## 1:45 — Detection (45s)

```bash
make alerts
```

> "Ten rules. Eight are YAML — adding a detection is adding a file. Three are hand-written
> processors, because sequence detection doesn't fit a 'count things in a window' format, and I'd
> rather draw that line than invent a sequence language."

Point out one thing specifically:

> "Notice credential stuffing is attributed to the **source address**, not the accounts. That
> matters at response time: blocking the source is right, and locking the 30 accounts it touched
> would mean denying service to 30 innocent users on the attacker's behalf."

## 2:30 — Risk and incidents (45s)

```bash
make risk
make incidents
```

> "Alerts aren't decisions. Risk accumulates per entity across rules and decays with a six-hour
> half-life — so an account that looked bad on Tuesday and has been quiet since doesn't stay
> suspicious forever. Incidents open on accumulated risk, one per entity, so a sustained attack
> is one investigation rather than a ticket every five minutes."

## 3:15 — Containment, gated (60s)

```bash
make pending
```

> "Containment is proposed, not performed. Account lockout always needs a human."

Show the authorization boundary — this is the bit people remember:

```bash
make authz-matrix
```

> "Four roles against three endpoint classes. The analyst can triage and cannot contain. The
> `nobody` user authenticates perfectly and is authorised for nothing — authentication and
> authorisation are different questions, and that user exists so the tests prove it."

Then approve:

```bash
make approve ID=<id>          # responder role
make contained
```

## 4:15 — The loop closes (30s)

```bash
make recent                   # the account's logins now fail with "account disabled"
make alerts                   # contained-account-persistence has fired
```

> "That's the part I'd point at. Containment isn't a row in a table — the account is actually
> disabled, its next login fails in the live event stream, and a rule fires on continued attempts
> to measure whether the containment worked."

## 4:45 — Audit and revert (15s)

```bash
make audit
make revert ID=<id>
```

> "Append-only audit log naming a person, not a shared key. And every containment action had a
> reversal path written before it shipped — the first false positive that locks out a real user
> at 3am is not the moment to be writing one."

---

## If you have ten minutes, add

**Measurement** — the thing most projects skip:

```bash
make score
```

> "Precision and recall against labelled ground truth. This is what turned tuning from taste into
> measurement — session hijack sat at 50% recall for weeks and the report said so on every run,
> which is how I knew to build sequence detection."

**Load testing:**

```bash
make load-report
```

> "Clean to 5,000 events a second, then congestion collapse. The bottleneck is the Postgres batch
> insert. I raised consumer concurrency from 3 to 6 expecting to double throughput and got 1.24×,
> because the constraint was downstream and the extra threads just queued against each other."

**The lakehouse:**

```bash
make lake-stats
make lake-small-files
```

> "15× cheaper per row than Postgres. And this demonstrates the classic failure — 200 small files
> against one compacted file is 11× slower and 60% larger, for the same rows."

---

## Questions to expect, and honest answers

**"Is this production-ready?"**
No, and the README lists why. One machine, no MFA, Terraform never applied to real AWS, response
acts on a lab IAM service that refuses to touch anything outside its own simulated population.

**"How do you know the detections work?"**
Measured, not asserted. 100% precision and recall on seven scenarios — and I'd immediately caveat
that: precision is flattered by entity-level attribution, background traffic isn't labelled
benign, and I wrote both the attacks and the detections, which is exactly the circularity a red
team exists to break.

**"What was hardest?"**
Not the streaming. Measuring whether it worked, and trusting the measurements — three of the four
bugs I introduced were in the measurement rather than the system.

**"What would you do next?"**
Enrichment at ingest. It came up three separate times — ASN for network comparison, parsed IAM
policy documents, per-account baselines — and I only recognised the pattern the third time. Rules
that reach for data they don't have are rules that are subtly wrong.
