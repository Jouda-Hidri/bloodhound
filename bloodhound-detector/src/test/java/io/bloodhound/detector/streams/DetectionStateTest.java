package io.bloodhound.detector.streams;

import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.detector.rules.DetectionRule;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionStateTest {

    private static final DetectionRule COUNT_RULE = new DetectionRule(
            "count-rule", "Count", "d", Severity.HIGH, "T1110.001", true,
            Map.of(), null, "user.id", EntityType.USER,
            Duration.ofMinutes(5), Duration.ofMinutes(1), 3, null,
            List.of("source.geo.country_iso_code"));

    private static final DetectionRule DISTINCT_RULE = new DetectionRule(
            "distinct-rule", "Distinct", "d", Severity.HIGH, "T1110.004", true,
            Map.of(), null, "user.id", EntityType.USER,
            Duration.ofMinutes(5), Duration.ofMinutes(1), 3, "source.ip",
            List.of());

    private static SecurityEvent event(String ip, String country) {
        return new SecurityEvent(
                Instant.parse("2026-09-12T08:00:00Z"),
                new SecurityEvent.EventInfo("evt-" + ip, EventCategory.AUTHENTICATION,
                        EventAction.USER_LOGIN, Outcome.FAILURE, null),
                new SecurityEvent.UserInfo("u-1", "a.b", "bloodhound.lab"),
                new SecurityEvent.SourceInfo(ip, 443, new SecurityEvent.GeoInfo(country, "X")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo("curl"),
                Map.of());
    }

    /**
     * The behaviour the entire alert volume depends on: crossing the threshold fires exactly once
     * per window. A 500-attempt brute force must produce one alert, not 498.
     */
    @Test
    void firesExactlyOnceWhenTheThresholdIsCrossed() {
        DetectionState state = DetectionState.empty();
        int fired = 0;

        for (int i = 0; i < 20; i++) {
            state = state.add(event("10.0.0." + i, "GR"), COUNT_RULE);
            if (state.justAlerted()) {
                fired++;
                assertThat(state.count()).isEqualTo(3);
            }
        }

        assertThat(fired).isEqualTo(1);
        assertThat(state.count()).isEqualTo(20);
        assertThat(state.alerted()).isTrue();
    }

    @Test
    void distinctRuleCountsUniqueValuesNotEvents() {
        DetectionState state = DetectionState.empty();

        // Same address ten times: one distinct value, must not fire a threshold of 3.
        for (int i = 0; i < 10; i++) {
            state = state.add(event("203.0.113.5", "RU"), DISTINCT_RULE);
            assertThat(state.justAlerted()).isFalse();
        }
        assertThat(state.count()).isEqualTo(10);
        assertThat(state.observed(DISTINCT_RULE)).isEqualTo(1);

        state = state.add(event("203.0.113.6", "RU"), DISTINCT_RULE);
        assertThat(state.justAlerted()).isFalse();

        state = state.add(event("203.0.113.7", "RU"), DISTINCT_RULE);
        assertThat(state.justAlerted()).isTrue();
        assertThat(state.observed(DISTINCT_RULE)).isEqualTo(3);
    }

    @Test
    void capsEvidenceSoAttackerControlledCardinalityCannotGrowStateUnbounded() {
        DetectionState state = DetectionState.empty();
        for (int i = 0; i < 50; i++) {
            state = state.add(event("10.1." + (i / 250) + "." + (i % 250), "GR"), COUNT_RULE);
        }

        // Sample ids are capped even though 50 events were seen.
        assertThat(state.sampleEventIds()).hasSize(5);
        // Context values are capped per field.
        assertThat(state.context().get("source.geo.country_iso_code")).hasSizeLessThanOrEqualTo(8);
    }

    @Test
    void tracksTheEventTimeSpanOfTheWindow() {
        DetectionState state = DetectionState.empty();
        SecurityEvent early = event("10.0.0.1", "GR");
        SecurityEvent late = new SecurityEvent(
                early.timestamp().plusSeconds(120), early.event(), early.user(),
                early.source(), early.service(), early.userAgent(), early.labels());

        state = state.add(late, COUNT_RULE).add(early, COUNT_RULE);

        assertThat(state.firstSeen()).isEqualTo(early.timestamp());
        assertThat(state.lastSeen()).isEqualTo(late.timestamp());
    }

    @Test
    void contextCollectsTheFieldsTheRuleAsksFor() {
        DetectionState state = DetectionState.empty()
                .add(event("10.0.0.1", "GR"), COUNT_RULE)
                .add(event("10.0.0.2", "DE"), COUNT_RULE);

        assertThat(state.context().get("source.geo.country_iso_code")).containsExactly("GR", "DE");
    }
}
