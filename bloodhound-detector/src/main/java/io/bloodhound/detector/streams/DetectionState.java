package io.bloodhound.detector.streams;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.bloodhound.common.event.EventFields;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.detector.rules.DetectionRule;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What a rule has accumulated for one entity in one window.
 *
 * <p>Every collection in here is capped. This state lives in a RocksDB store with one entry per
 * (entity, window), and the number of entities is attacker-controlled — a credential-stuffing run
 * touching 100,000 accounts creates 100,000 entries. Unbounded evidence collection inside each
 * one is how a detection engine gets taken down by the thing it is supposed to detect.
 */
public record DetectionState(

        @JsonProperty("count") long count,

        /** Values seen for the rule's {@code distinct} field, capped. */
        @JsonProperty("distinct_values") Set<String> distinctValues,

        /** True once the cap was hit, so an alert can say the evidence is a lower bound. */
        @JsonProperty("distinct_truncated") boolean distinctTruncated,

        @JsonProperty("sample_event_ids") List<String> sampleEventIds,

        /** Field path → a few observed values, for triage without leaving the alert. */
        @JsonProperty("context") Map<String, Set<String>> context,

        @JsonProperty("first_seen") Instant firstSeen,
        @JsonProperty("last_seen") Instant lastSeen,

        /** Sticky: true from the moment the threshold was crossed in this window. */
        @JsonProperty("alerted") boolean alerted,

        /** True only on the single update that crossed the threshold. */
        @JsonProperty("just_alerted") boolean justAlerted
) {

    /** Enough distinct values to be convincing evidence; far short of enough to exhaust memory. */
    private static final int DISTINCT_CAP = 5_000;
    private static final int SAMPLE_CAP = 5;
    private static final int CONTEXT_VALUES_CAP = 8;

    @JsonCreator
    public DetectionState {
        distinctValues = distinctValues == null ? Set.of() : distinctValues;
        sampleEventIds = sampleEventIds == null ? List.of() : sampleEventIds;
        context = context == null ? Map.of() : context;
    }

    public static DetectionState empty() {
        return new DetectionState(0, new LinkedHashSet<>(), false, new ArrayList<>(),
                new LinkedHashMap<>(), null, null, false, false);
    }

    /** How many things this rule is actually counting — events, or distinct field values. */
    @JsonIgnore
    public long observed(DetectionRule rule) {
        return rule.isDistinctRule() ? distinctValues.size() : count;
    }

    public DetectionState add(SecurityEvent event, DetectionRule rule) {
        long newCount = count + 1;

        Set<String> newDistinct = new LinkedHashSet<>(distinctValues);
        boolean truncated = distinctTruncated;
        if (rule.isDistinctRule()) {
            String value = EventFields.get(event, rule.distinct());
            if (value != null) {
                if (newDistinct.size() < DISTINCT_CAP) {
                    newDistinct.add(value);
                } else if (!newDistinct.contains(value)) {
                    truncated = true;
                }
            }
        }

        List<String> newSamples = new ArrayList<>(sampleEventIds);
        if (newSamples.size() < SAMPLE_CAP && event.event() != null && event.event().id() != null) {
            newSamples.add(event.event().id());
        }

        Map<String, Set<String>> newContext = new LinkedHashMap<>();
        context.forEach((field, values) -> newContext.put(field, new LinkedHashSet<>(values)));
        for (String field : rule.contextFieldsOrDefault()) {
            String value = EventFields.get(event, field);
            if (value != null) {
                Set<String> values = newContext.computeIfAbsent(field, f -> new LinkedHashSet<>());
                if (values.size() < CONTEXT_VALUES_CAP) {
                    values.add(value);
                }
            }
        }

        Instant eventTime = event.timestamp();
        Instant newFirst = firstSeen == null || (eventTime != null && eventTime.isBefore(firstSeen))
                ? eventTime : firstSeen;
        Instant newLast = lastSeen == null || (eventTime != null && eventTime.isAfter(lastSeen))
                ? eventTime : lastSeen;

        long observedNow = rule.isDistinctRule() ? newDistinct.size() : newCount;
        boolean crossed = observedNow >= rule.threshold();

        // `alerted` is sticky so the rule fires once per (entity, window) rather than on every
        // event past the threshold. A brute force of 500 attempts should produce one alert, not
        // 491. The responder deduplicates across windows; this deduplicates within one.
        boolean nowAlerted = alerted || crossed;
        boolean firesNow = !alerted && crossed;

        return new DetectionState(newCount, newDistinct, truncated, newSamples, newContext,
                newFirst, newLast, nowAlerted, firesNow);
    }
}
