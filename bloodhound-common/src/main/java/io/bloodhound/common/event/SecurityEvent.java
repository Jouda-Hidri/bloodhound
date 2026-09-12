package io.bloodhound.common.event;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;

/**
 * A single security-relevant event, shaped after the Elastic Common Schema (ECS).
 *
 * <p>Field names deliberately match ECS ({@code @timestamp}, {@code event.action},
 * {@code source.ip}, {@code user.id}) so that the same events can later be fed to
 * Elasticsearch/OpenSearch, matched by Sigma rules, or compared against real SIEM data
 * without a translation layer.
 *
 * <p>The wire format is JSON. See {@code docs/decisions/0001-event-schema-and-transport.md}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SecurityEvent(
        @JsonProperty("@timestamp") Instant timestamp,
        @JsonProperty("event") EventInfo event,
        @JsonProperty("user") UserInfo user,
        @JsonProperty("source") SourceInfo source,
        @JsonProperty("service") ServiceInfo service,
        @JsonProperty("user_agent") UserAgentInfo userAgent,
        @JsonProperty("labels") Map<String, String> labels
) {

    /** ECS {@code event.*} — what happened, and how it turned out. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record EventInfo(
            /** Stable unique id for this event. The deduplication key. */
            @JsonProperty("id") String id,
            @JsonProperty("category") EventCategory category,
            @JsonProperty("action") EventAction action,
            @JsonProperty("outcome") Outcome outcome,
            /** Free-text detail, e.g. "invalid password", "mfa timeout". */
            @JsonProperty("reason") String reason
    ) {}

    /** ECS {@code user.*} — the subject the event is about. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UserInfo(
            @JsonProperty("id") String id,
            @JsonProperty("name") String name,
            @JsonProperty("domain") String domain
    ) {}

    /** ECS {@code source.*} — where the request came from. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SourceInfo(
            @JsonProperty("ip") String ip,
            @JsonProperty("port") Integer port,
            @JsonProperty("geo") GeoInfo geo
    ) {}

    /** ECS {@code source.geo.*}. Populated by the producer here; enriched for real in Month 3. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record GeoInfo(
            @JsonProperty("country_iso_code") String countryIsoCode,
            @JsonProperty("city_name") String cityName
    ) {}

    /** ECS {@code service.*} — which of our systems emitted this. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ServiceInfo(
            @JsonProperty("name") String name,
            @JsonProperty("version") String version,
            @JsonProperty("environment") String environment
    ) {}

    /** ECS {@code user_agent.*}. Only the raw string for now; parsed fields come with enrichment. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UserAgentInfo(
            @JsonProperty("original") String original
    ) {}
}
