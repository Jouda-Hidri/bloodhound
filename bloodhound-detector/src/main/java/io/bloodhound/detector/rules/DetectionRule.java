package io.bloodhound.detector.rules;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.common.event.EventFields;
import io.bloodhound.common.event.SecurityEvent;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * A detection expressed as data rather than code.
 *
 * <p>The point of this shape is that adding a detection is editing a YAML file, not writing,
 * reviewing and deploying Java. In a real security team the people with the best ideas about what
 * to detect are frequently not the people who can ship a service, and a rule format is what
 * closes that gap.
 *
 * <p>It also deliberately does <em>not</em> try to express everything. Sequence detections
 * (impossible travel) do not fit a windowed count and are implemented as dedicated processors
 * instead. A rule DSL that grows until it is a worse programming language is a well-known way for
 * this kind of project to go wrong; the honest boundary is drawn at "aggregate over a window".
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record DetectionRule(

        @JsonProperty("id") String id,
        @JsonProperty("name") String name,
        @JsonProperty("description") String description,
        @JsonProperty("severity") Severity severity,

        /** MITRE ATT&CK technique id, e.g. T1110.001. */
        @JsonProperty("technique") String technique,

        @JsonProperty("enabled") Boolean enabled,

        /** Field path → required exact value. All entries must match. */
        @JsonProperty("match") Map<String, String> match,

        /** Field path → any-of values. All entries must match at least one of their values. */
        @JsonProperty("match_any") Map<String, List<String>> matchAny,

        /** Field path whose value becomes the alert's entity, e.g. {@code user.id}. */
        @JsonProperty("group_by") String groupBy,

        /** What the entity is, so the responder knows what it may act on. */
        @JsonProperty("entity_type") EntityType entityType,

        /** Window length in ISO-8601 duration form, e.g. PT5M. */
        @JsonProperty("window") Duration window,

        /** How long after a window closes late events are still accepted. */
        @JsonProperty("grace") Duration grace,

        /** Fire when the count reaches this. */
        @JsonProperty("threshold") long threshold,

        /**
         * When set, count <em>distinct values of this field</em> rather than events.
         * This is what separates "20 failures against one account" from "20 different accounts
         * touched by one IP" — the same events, a completely different conclusion.
         */
        @JsonProperty("distinct") String distinct,

        /** Extra field paths to summarise into the alert as triage evidence. */
        @JsonProperty("context_fields") List<String> contextFields
) {

    public boolean isEnabled() {
        return enabled == null || enabled;
    }

    public boolean isDistinctRule() {
        return distinct != null && !distinct.isBlank();
    }

    public Duration graceOrDefault() {
        return grace == null ? Duration.ofMinutes(1) : grace;
    }

    public List<String> contextFieldsOrDefault() {
        return contextFields == null ? List.of() : contextFields;
    }

    /** Does this event satisfy every condition on the rule? */
    public boolean matches(SecurityEvent event) {
        if (match != null) {
            for (Map.Entry<String, String> condition : match.entrySet()) {
                if (!condition.getValue().equals(EventFields.get(event, condition.getKey()))) {
                    return false;
                }
            }
        }
        if (matchAny != null) {
            for (Map.Entry<String, List<String>> condition : matchAny.entrySet()) {
                String actual = EventFields.get(event, condition.getKey());
                if (actual == null || !condition.getValue().contains(actual)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Fails loudly at load time for anything structurally wrong.
     *
     * <p>Validating at startup rather than at match time is the whole reason field paths are a
     * closed set. A rule with a typo'd field would otherwise load fine, match nothing forever, and
     * look exactly like a rule that is working — a silently blind detection is worse than none,
     * because you believe you are covered.
     */
    public void validate() {
        require(id != null && !id.isBlank(), "rule id is required");
        require(name != null && !name.isBlank(), "rule '" + id + "': name is required");
        require(severity != null, "rule '" + id + "': severity is required");
        require(groupBy != null, "rule '" + id + "': group_by is required");
        require(entityType != null, "rule '" + id + "': entity_type is required");
        require(window != null && !window.isZero() && !window.isNegative(),
                "rule '" + id + "': window must be a positive duration like PT5M");
        require(threshold > 0, "rule '" + id + "': threshold must be > 0");
        require(EventFields.isSupported(groupBy),
                "rule '" + id + "': unknown group_by field '" + groupBy + "'");

        if (isDistinctRule()) {
            require(EventFields.isSupported(distinct),
                    "rule '" + id + "': unknown distinct field '" + distinct + "'");
        }
        if (match != null) {
            match.keySet().forEach(field -> require(EventFields.isSupported(field),
                    "rule '" + id + "': unknown match field '" + field + "'"));
        }
        if (matchAny != null) {
            matchAny.keySet().forEach(field -> require(EventFields.isSupported(field),
                    "rule '" + id + "': unknown match_any field '" + field + "'"));
        }
        contextFieldsOrDefault().forEach(field -> require(EventFields.isSupported(field),
                "rule '" + id + "': unknown context field '" + field + "'"));

        require(graceOrDefault().compareTo(window) <= 0,
                "rule '" + id + "': grace must not exceed the window — a longer grace keeps "
                        + "windows open past their usefulness and inflates state store size");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
