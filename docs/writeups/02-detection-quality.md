# How do you know your detections work?

The second of three write-ups on Bloodhound. The [first](01-architecture.md) covered the
architecture; the [third](03-postmortems.md) is a list of things that broke.

This one is about the question most detection projects never answer.

---

## The problem with "it fired"

Every detection demo ends the same way: fire an attack, watch an alert appear, conclude the
detection works.

That demonstrates recall on a sample of one, and says nothing at all about precision. A rule that
fires on every attack *and on everything else* passes that demo perfectly and is worthless — in
practice worse than worthless, because it trains people to ignore the console.

Without measurement, tuning is taste. Somebody decides 10 failed logins feels about right, and
nobody ever finds out.

## Ground truth you can actually score against

The attack simulator labels every event it produces:

```json
"labels": { "scenario": "brute_force", "run_id": "bf-1", "attack_technique": "T1110.001" }
```

Detection logic never reads those labels. One script does, and it is the only consumer of them.

That gives the thing most security teams cannot get: a dataset where you know, exactly, which
events were part of an attack. Real SOCs approximate this with analyst verdicts, which are slow,
sparse and inconsistent. A simulator hands it to you for free — and is the single strongest
argument for building the adversary before building the detections.

```
make score
```

- an **attack run** is a set of (entity, time range) pairs
- an alert is a **true positive** if its entity was under attack in an overlapping window
- an alert with no overlapping attack is a **false positive**
- an attack run with no alert is a **false negative**

## What it found

**Session hijack sat at 50% recall for weeks, and the report said so every time.**

That is the part worth dwelling on. The gap was not discovered by an audit or by someone thinking
hard; it was printed, in plain text, on every run:

```
  scenario              runs  detected  missed    recall
  session_hijack           2         1       1     50.0%

  Undetected attack runs (1):
    - session_hijack:sh-5
```

Every credential-focused rule was blind to it, because the attack never touches the login
endpoint — the attacker starts with a stolen token. No failed logins, no threshold to cross. It
needed sequence detection, which is a different kind of rule, and the measurement is what made
that obvious rather than a thing to eventually get round to.

After building it: **100% precision, 100% recall across all seven scenarios.**

## Three ways the measurement itself was wrong

Scoring is code, and code is wrong until tested. All three of these produced confident, specific,
incorrect numbers.

**The scorer under-reported recall by 3×.** It stopped at the first matching attack run, so when
several scenarios hit one account, the rest were reported undetected. Recall read 33% when it was
92%.

A scoring bug that *understates* is more dangerous than a crash. A crash is obvious. This sends
you tuning rules that were working fine, and you break them.

**A short-window baseline is not a weak baseline, it is a misleading one.** Baseline-relative
detection used each account's usual active hours. The baselines had 7.7 hours of history — so
"usual hours" was not when the person works, it was when the pipeline happened to be running.
Every event outside that window looked anomalous: **197 alerts, 197 of them noise.**

The fix is a guard: ignore the hour signal until the account has been observed across at least 12
distinct hours. A baseline computed over too little data fires hardest exactly when you have
least reason to trust it.

**Detector downtime scores identically to missing coverage.** The script compares attacks to
alerts and has no idea whether the detector was running. An attack fired during a restart looks
exactly like one no rule covers.

"We have no detection for this" and "we had no detection *running*" are completely different
problems with completely different fixes. A real deployment tracks coverage gaps explicitly,
because *how much of last week were we actually watching* is a question a SOC has to be able to
answer.

## Tuning, with numbers

The first session-hijack implementation fired on any source address change:

```
130 alerts
126 of them (97%) a user moving within their own /24
precision ~3%
```

A phone dropping to wifi. A DHCP lease. A second interface.

The fix was one comparison — check the *network*, not the address — and it removed all 126
without touching any of the 4 real hijacks. An attacker with a stolen token is not on the
victim's subnet.

```
before: 130 alerts, ~3% precision
after:    4 alerts, 100% precision
```

Then, running scenarios *together* rather than one at a time:

```
52 session-hijack alerts from a single credential-stuffing run
```

A failed login is not "succeeded", so it fell through to the session-use branch. Every
stuffing victim who happened to have a live session generated a hijack alert — describing an
attack a different rule had already reported correctly.

**One attack manufacturing false positives in an unrelated rule is invisible unless you run
scenarios concurrently.** Testing rules in isolation would never have surfaced it. It is also not
unique: impossible travel has the same interaction with credential stuffing, documented since
Week 1, because stuffing traffic is geotagged to one country and a victim's normal login plus a
stuffed login looks like travel.

## Read the numbers sceptically

100%/100% is a suspicious result and it should be read as one.

- **Precision is flattered by entity-level attribution.** An alert from the brute-force rule that
  lands on an account being credential-stuffed counts as a true positive. It caught *an* attack,
  not the one its author intended.
- **Background traffic is not labelled benign.** False positives here only count alerts on
  entities no simulated attack touched. An alert firing on genuinely harmless activity needs a
  human verdict, which is what the `triage` column and `/alerts/{id}/triage` are for.
- **Seven scenarios is a small, self-authored corpus.** Everything the simulator produces is
  something somebody thought to simulate. Real attackers are not limited to my imagination, and
  the scenarios and the detections were written by the same person — which is exactly the
  circularity that makes a red team valuable.

The number is not the deliverable. Being able to state it, defend it, and say precisely what it
does not cover is.

---

*Next: [things that broke](03-postmortems.md).*
