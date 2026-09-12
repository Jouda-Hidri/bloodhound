package io.bloodhound.common.event;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The wire format is a contract between two services. These tests pin it down, so that a
 * refactor that silently renames a JSON field fails here rather than in production at 3am.
 */
class SecurityEventJsonTest {

    private final ObjectMapper mapper = EventJson.mapper();

    private static SecurityEvent sample() {
        return new SecurityEvent(
                Instant.parse("2026-09-11T08:30:00Z"),
                new SecurityEvent.EventInfo("evt-1", EventCategory.AUTHENTICATION,
                        EventAction.USER_LOGIN, Outcome.FAILURE, "invalid password"),
                new SecurityEvent.UserInfo("u-00001", "anna.beck", "bloodhound.lab"),
                new SecurityEvent.SourceInfo("203.0.113.9", 51234,
                        new SecurityEvent.GeoInfo("GR", "Athens")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo("curl/8.6.0"),
                Map.of("scenario", "brute_force"));
    }

    @Test
    void serialisesToEcsFieldNames() throws Exception {
        JsonNode json = mapper.readTree(mapper.writeValueAsString(sample()));

        assertThat(json.get("@timestamp").asText()).isEqualTo("2026-09-11T08:30:00Z");
        assertThat(json.at("/event/action").asText()).isEqualTo("user-login");
        assertThat(json.at("/event/outcome").asText()).isEqualTo("failure");
        assertThat(json.at("/event/category").asText()).isEqualTo("authentication");
        assertThat(json.at("/user/id").asText()).isEqualTo("u-00001");
        assertThat(json.at("/source/ip").asText()).isEqualTo("203.0.113.9");
        assertThat(json.at("/source/geo/country_iso_code").asText()).isEqualTo("GR");
        assertThat(json.at("/user_agent/original").asText()).isEqualTo("curl/8.6.0");
    }

    @Test
    void roundTrips() throws Exception {
        String json = mapper.writeValueAsString(sample());
        assertThat(mapper.readValue(json, SecurityEvent.class)).isEqualTo(sample());
    }

    @Test
    void omitsNullFieldsRatherThanEmittingNulls() throws Exception {
        SecurityEvent minimal = new SecurityEvent(
                Instant.parse("2026-09-11T08:30:00Z"),
                new SecurityEvent.EventInfo("evt-2", EventCategory.API,
                        EventAction.PERMISSION_CHECK, Outcome.SUCCESS, null),
                new SecurityEvent.UserInfo("u-2", null, null),
                null, null, null, null);

        String json = mapper.writeValueAsString(minimal);

        assertThat(json).doesNotContain("null");
        assertThat(json).doesNotContain("\"source\"");
    }

    /**
     * A producer on a newer schema version must not break an older consumer. This is the
     * backward-compatibility rule that Week 3 enforces properly with a schema registry.
     */
    @Test
    void toleratesUnknownFieldsFromNewerProducers() throws Exception {
        String futureJson = """
                {
                  "@timestamp": "2026-09-11T08:30:00Z",
                  "event": {"id": "evt-3", "action": "user-login", "outcome": "success",
                            "risk_score": 42},
                  "user": {"id": "u-3"},
                  "threat": {"indicator": {"type": "ipv4-addr"}}
                }
                """;

        SecurityEvent parsed = mapper.readValue(futureJson, SecurityEvent.class);

        assertThat(parsed.event().id()).isEqualTo("evt-3");
        assertThat(parsed.user().id()).isEqualTo("u-3");
    }

    /** An action we have never seen must not take the consumer down. */
    @Test
    void mapsUnknownEnumValuesToUnknown() {
        assertThat(EventAction.from("something-new")).isEqualTo(EventAction.UNKNOWN);
        assertThat(EventCategory.from(null)).isEqualTo(EventCategory.UNKNOWN);
        assertThat(Outcome.from("FAILURE")).isEqualTo(Outcome.FAILURE);
    }
}
