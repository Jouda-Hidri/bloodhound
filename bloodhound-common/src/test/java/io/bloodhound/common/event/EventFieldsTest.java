package io.bloodhound.common.event;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Field paths are the interface between YAML rules and Java. A rule saying {@code group_by:
 * user.id} only works because this resolver agrees on the spelling, so the spellings are pinned.
 */
class EventFieldsTest {

    private static final SecurityEvent EVENT = new SecurityEvent(
            Instant.parse("2026-09-12T08:00:00Z"),
            new SecurityEvent.EventInfo("evt-1", EventCategory.AUTHENTICATION,
                    EventAction.USER_LOGIN, Outcome.FAILURE, "invalid password"),
            new SecurityEvent.UserInfo("u-1", "anna.beck", "bloodhound.lab"),
            new SecurityEvent.SourceInfo("203.0.113.9", 443,
                    new SecurityEvent.GeoInfo("GR", "Athens")),
            new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
            new SecurityEvent.UserAgentInfo("curl/8.6.0"),
            Map.of("scenario", "brute_force"));

    @Test
    void resolvesEveryDocumentedPath() {
        assertThat(EventFields.get(EVENT, "event.action")).isEqualTo("user-login");
        assertThat(EventFields.get(EVENT, "event.outcome")).isEqualTo("failure");
        assertThat(EventFields.get(EVENT, "event.category")).isEqualTo("authentication");
        assertThat(EventFields.get(EVENT, "event.reason")).isEqualTo("invalid password");
        assertThat(EventFields.get(EVENT, "user.id")).isEqualTo("u-1");
        assertThat(EventFields.get(EVENT, "user.name")).isEqualTo("anna.beck");
        assertThat(EventFields.get(EVENT, "source.ip")).isEqualTo("203.0.113.9");
        assertThat(EventFields.get(EVENT, "source.geo.country_iso_code")).isEqualTo("GR");
        assertThat(EventFields.get(EVENT, "source.geo.city_name")).isEqualTo("Athens");
        assertThat(EventFields.get(EVENT, "service.name")).isEqualTo("payment-api");
        assertThat(EventFields.get(EVENT, "user_agent.original")).isEqualTo("curl/8.6.0");
    }

    /** Every path in SUPPORTED must actually resolve, or a rule could pass validation and fail live. */
    @Test
    void everySupportedPathIsResolvable() {
        for (String path : EventFields.SUPPORTED) {
            assertThat(EventFields.get(EVENT, path))
                    .as("supported path '%s' should resolve", path)
                    .isNotNull();
        }
    }

    @Test
    void returnsNullForAbsentNestedObjectsRatherThanThrowing() {
        SecurityEvent sparse = new SecurityEvent(
                Instant.now(),
                new SecurityEvent.EventInfo("evt-2", null, null, null, null),
                new SecurityEvent.UserInfo("u-2", null, null),
                null, null, null, null);

        assertThat(EventFields.get(sparse, "source.ip")).isNull();
        assertThat(EventFields.get(sparse, "source.geo.country_iso_code")).isNull();
        assertThat(EventFields.get(sparse, "user_agent.original")).isNull();
        assertThat(EventFields.get(sparse, "event.action")).isNull();
    }

    /**
     * The behaviour the whole design rests on: an unknown path is an error, not a silent null.
     * A rule with a typo'd field must fail at load rather than match nothing forever.
     */
    @Test
    void rejectsUnknownPaths() {
        assertThatThrownBy(() -> EventFields.get(EVENT, "user.emial"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported field path");

        assertThat(EventFields.isSupported("user.emial")).isFalse();
        assertThat(EventFields.isSupported("user.id")).isTrue();
    }
}
