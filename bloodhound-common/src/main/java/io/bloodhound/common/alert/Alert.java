package io.bloodhound.common.alert;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * A detection that fired.
 *
 * <p>An alert is a claim about an entity over a time window, not about a single event. It carries
 * the evidence needed to triage it without going back to the raw store: which rule, what it
 * observed versus what it expected, and a sample of the events that triggered it.
 *
 * <p>{@code dedupeKey} is what makes repeated firings of the same condition collapse into one
 * alert with a rising count instead of a hundred separate ones. Alert fatigue is the single most
 * common way a real detection programme fails.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Alert(

        @JsonProperty("id") String id,

        /** When the detector fired. */
        @JsonProperty("detected_at") Instant detectedAt,

        /** Event-time bounds of the window that triggered it — not wall-clock bounds. */
        @JsonProperty("window_start") Instant windowStart,
        @JsonProperty("window_end") Instant windowEnd,

        @JsonProperty("rule_id") String ruleId,
        @JsonProperty("rule_name") String ruleName,
        @JsonProperty("severity") Severity severity,

        /** MITRE ATT&CK technique, e.g. {@code T1110.001}. */
        @JsonProperty("technique") String technique,

        @JsonProperty("entity_type") EntityType entityType,
        @JsonProperty("entity_id") String entityId,

        /** What the rule counted, and the threshold it crossed. */
        @JsonProperty("observed") long observed,
        @JsonProperty("threshold") long threshold,

        /** Evidence for triage: distinct sources, sample users, countries seen. */
        @JsonProperty("context") Map<String, String> context,

        /** A handful of raw event ids, enough to pivot into the event store. */
        @JsonProperty("sample_event_ids") List<String> sampleEventIds
) {

    /**
     * Identity of the *condition*, independent of when it fired. Two alerts sharing this key are
     * the same ongoing situation, and the responder merges them.
     */
    public String dedupeKey() {
        return ruleId + "|" + entityType.value() + "|" + entityId;
    }
}
