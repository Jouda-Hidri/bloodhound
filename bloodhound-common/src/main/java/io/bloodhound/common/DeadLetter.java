package io.bloodhound.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * An envelope around a message that could not be processed.
 *
 * <p>The original payload is kept verbatim as a string, never re-parsed — it may well be the
 * thing that failed to parse. Everything needed to find the message again and to replay it after
 * a fix is captured alongside it.
 *
 * <p>Dropping bad security telemetry is not acceptable: an attacker who can make your parser fail
 * has found a way to make their activity invisible. A dead letter queue turns that from a silent
 * blind spot into a visible, alertable backlog.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeadLetter(

        @JsonProperty("failed_at") Instant failedAt,

        /** Where it came from, so it can be replayed to exactly the right place. */
        @JsonProperty("source_topic") String sourceTopic,
        @JsonProperty("source_partition") int sourcePartition,
        @JsonProperty("source_offset") long sourceOffset,
        @JsonProperty("source_key") String sourceKey,

        /** Coarse bucket: PARSE_ERROR, VALIDATION_ERROR, PERSIST_ERROR. */
        @JsonProperty("failure_type") String failureType,
        @JsonProperty("failure_reason") String failureReason,

        /** The service that gave up on it. */
        @JsonProperty("consumer") String consumer,

        /** The original bytes, as text. Never re-serialised. */
        @JsonProperty("payload") String payload
) {

    public static final String PARSE_ERROR = "PARSE_ERROR";
    public static final String VALIDATION_ERROR = "VALIDATION_ERROR";
    public static final String PERSIST_ERROR = "PERSIST_ERROR";
}
