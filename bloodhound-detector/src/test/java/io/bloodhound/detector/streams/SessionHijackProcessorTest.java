package io.bloodhound.detector.streams;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import io.bloodhound.common.Topics;
import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.detector.config.DetectorProperties;
import io.bloodhound.detector.rules.RuleLoader;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TestOutputTopic;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the session-hijack tuning in place.
 *
 * <p>Each test here corresponds to a false-positive class that was measured live and fixed. The
 * point of the tests is that a future refactor cannot quietly reintroduce one — the numbers in
 * ADR 0009 (130 alerts down to 4, then 52 down to 5) are only meaningful if they stay true.
 */
class SessionHijackProcessorTest {

    private static final Instant T0 = Instant.parse("2026-09-14T08:00:00Z");

    private TopologyTestDriver driver;
    private TestInputTopic<String, String> events;
    private TestOutputTopic<String, String> alerts;
    private final ObjectMapper mapper = EventJson.mapper();

    @BeforeEach
    void setUp() {
        StreamsBuilder builder = new StreamsBuilder();
        DetectorProperties props = new DetectorProperties();
        // Only the processor under test, so an unrelated rule cannot account for an alert.
        props.getImpossibleTravel().setEnabled(false);
        props.getBaselineDeviation().setEnabled(false);
        props.setRulesDir(null);

        new DetectionTopology(new RuleLoader(), props, new SimpleMeterRegistry())
                .detectionStream(builder);

        Properties config = new Properties();
        config.put(StreamsConfig.APPLICATION_ID_CONFIG, "session-hijack-test");
        config.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, "dummy:9092");
        config.put(StreamsConfig.STATESTORE_CACHE_MAX_BYTES_CONFIG, 0);

        driver = new TopologyTestDriver(builder.build(), config);
        events = driver.createInputTopic(Topics.RAW_EVENTS,
                Serdes.String().serializer(), Serdes.String().serializer());
        alerts = driver.createOutputTopic(Topics.ALERTS,
                Serdes.String().deserializer(), Serdes.String().deserializer());
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            driver.close();
        }
    }

    private void send(String user, EventAction action, Outcome outcome, String ip,
                      String agent, Instant at) {
        SecurityEvent event = new SecurityEvent(at,
                new SecurityEvent.EventInfo(UUID.randomUUID().toString(),
                        action == EventAction.PERMISSION_CHECK ? EventCategory.API
                                : EventCategory.AUTHENTICATION,
                        action, outcome, null),
                new SecurityEvent.UserInfo(user, user, "bloodhound.lab"),
                new SecurityEvent.SourceInfo(ip, 443, new SecurityEvent.GeoInfo("DE", "Berlin")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo(agent),
                Map.of());
        try {
            events.pipeInput(user, mapper.writeValueAsString(event), at);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private List<Alert> hijackAlerts() {
        return alerts.readValuesToList().stream().map(v -> {
            try {
                return mapper.readValue(v, Alert.class);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).filter(a -> a.ruleId().equals(SessionHijackProcessor.RULE_ID)).toList();
    }

    // ------------------------------------------------------------------

    @Test
    void detectsASessionUsedFromAnotherNetworkWithAnotherClient() {
        send("u-1", EventAction.TOKEN_ISSUED, Outcome.SUCCESS, "10.0.1.5", "Firefox", T0);
        send("u-1", EventAction.PERMISSION_CHECK, Outcome.SUCCESS, "203.0.113.9",
                "python-requests/2.32.3", T0.plusSeconds(90));

        List<Alert> fired = hijackAlerts();
        assertThat(fired).hasSize(1);
        assertThat(fired.get(0).severity().value()).isEqualTo("high");
        assertThat(fired.get(0).entityId()).isEqualTo("u-1");
        assertThat(fired.get(0).context()).containsEntry("network_class_change",
                "internal_to_external");
    }

    /**
     * Bug 1 from ADR 0009. Firing on any address change produced 130 alerts of which 126 were a
     * user moving inside their own /24.
     */
    @Test
    void ignoresMovementWithinTheSameNetwork() {
        send("u-2", EventAction.TOKEN_ISSUED, Outcome.SUCCESS, "10.0.1.5", "Firefox", T0);
        send("u-2", EventAction.PERMISSION_CHECK, Outcome.SUCCESS, "10.0.1.88", "Firefox",
                T0.plusSeconds(90));

        assertThat(hijackAlerts()).isEmpty();
    }

    /**
     * Bug 2 from ADR 0009. A failed login is not a session being used — it is somebody trying to
     * create one. Treating it as session use meant a credential-stuffing run produced 52
     * session-hijack alerts for an attack another rule already reported.
     */
    @Test
    void failedLoginsFromElsewhereAreNotSessionUse() {
        send("u-3", EventAction.TOKEN_ISSUED, Outcome.SUCCESS, "10.0.2.5", "Firefox", T0);
        // A credential-stuffing attempt against this account from hostile infrastructure.
        for (int i = 0; i < 5; i++) {
            send("u-3", EventAction.USER_LOGIN, Outcome.FAILURE, "198.51.100.4",
                    "python-requests/2.32.3", T0.plusSeconds(60 + i * 5L));
        }

        assertThat(hijackAlerts()).isEmpty();
    }

    /** Re-authenticating legitimises the new location — that is how a user moves house. */
    @Test
    void reAuthenticationResetsTheFingerprint() {
        send("u-4", EventAction.TOKEN_ISSUED, Outcome.SUCCESS, "10.0.3.5", "Firefox", T0);
        send("u-4", EventAction.USER_LOGIN, Outcome.SUCCESS, "203.0.113.20", "Firefox",
                T0.plusSeconds(60));
        send("u-4", EventAction.PERMISSION_CHECK, Outcome.SUCCESS, "203.0.113.20", "Firefox",
                T0.plusSeconds(120));

        assertThat(hijackAlerts()).isEmpty();
    }

    /** Clients legitimately appear to shift immediately after authenticating. */
    @Test
    void ignoresMovementInsideTheGracePeriod() {
        send("u-5", EventAction.TOKEN_ISSUED, Outcome.SUCCESS, "10.0.4.5", "Firefox", T0);
        send("u-5", EventAction.PERMISSION_CHECK, Outcome.SUCCESS, "203.0.113.30", "Firefox",
                T0.plusSeconds(5));

        assertThat(hijackAlerts()).isEmpty();
    }

    /** No session on record means nothing to compare against. */
    @Test
    void doesNotFireWithoutAnEstablishedSession() {
        send("u-6", EventAction.PERMISSION_CHECK, Outcome.SUCCESS, "203.0.113.40", "Firefox", T0);
        assertThat(hijackAlerts()).isEmpty();
    }

    /** A network move with the same client is real but weaker, so it is not HIGH. */
    @Test
    void sameClientOnADifferentPrivateNetworkIsMediumNotHigh() {
        send("u-7", EventAction.TOKEN_ISSUED, Outcome.SUCCESS, "10.0.5.5", "Firefox", T0);
        send("u-7", EventAction.PERMISSION_CHECK, Outcome.SUCCESS, "10.9.9.9", "Firefox",
                T0.plusSeconds(120));

        List<Alert> fired = hijackAlerts();
        assertThat(fired).hasSize(1);
        assertThat(fired.get(0).severity().value()).isEqualTo("medium");
    }
}
