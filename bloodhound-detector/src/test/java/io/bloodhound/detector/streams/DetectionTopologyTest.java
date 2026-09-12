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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives the real topology — the same one that runs in production — through TopologyTestDriver.
 *
 * <p>This is the test that actually proves detection works. The unit tests above verify the
 * pieces; this verifies that windowing, repartitioning, serdes and event-time extraction combine
 * into an alert. Streams bugs live almost entirely in that combination, and none of them show up
 * until records flow through a built topology.
 *
 * <p>TopologyTestDriver advances stream time from record timestamps rather than the wall clock,
 * which is exactly what makes window behaviour testable at all.
 */
class DetectionTopologyTest {

    private static final Instant T0 = Instant.parse("2026-09-12T08:00:00Z");

    private TopologyTestDriver driver;
    private TestInputTopic<String, String> events;
    private TestOutputTopic<String, String> alerts;
    private final ObjectMapper mapper = EventJson.mapper();

    @BeforeEach
    void setUp() {
        StreamsBuilder builder = new StreamsBuilder();
        DetectorProperties props = new DetectorProperties();
        new DetectionTopology(new RuleLoader(), props, new SimpleMeterRegistry())
                .detectionStream(builder);

        Properties config = new Properties();
        config.put(StreamsConfig.APPLICATION_ID_CONFIG, "detection-topology-test");
        config.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, "dummy:9092");
        // Same setting as production: emit on every update so a threshold fires immediately
        // rather than at window close.
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

    // ------------------------------------------------------------------

    private void send(SecurityEvent event) {
        try {
            events.pipeInput(event.user().id(), mapper.writeValueAsString(event), event.timestamp());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private List<Alert> readAlerts() {
        return alerts.readValuesToList().stream().map(value -> {
            try {
                return mapper.readValue(value, Alert.class);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).toList();
    }

    private static SecurityEvent login(String user, String ip, Outcome outcome, Instant at) {
        return new SecurityEvent(at,
                new SecurityEvent.EventInfo(UUID.randomUUID().toString(), EventCategory.AUTHENTICATION,
                        EventAction.USER_LOGIN, outcome, "invalid password"),
                new SecurityEvent.UserInfo(user, user + "@lab", "bloodhound.lab"),
                new SecurityEvent.SourceInfo(ip, 443, new SecurityEvent.GeoInfo("RU", "Moscow")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo("python-requests/2.32.3"),
                Map.of());
    }

    // ------------------------------------------------------------------

    @Test
    void bruteForceFiresOnceWhenTheThresholdIsCrossed() {
        for (int i = 0; i < 25; i++) {
            send(login("u-1", "203.0.113.5", Outcome.FAILURE, T0.plusSeconds(i * 2L)));
        }

        List<Alert> fired = readAlerts().stream()
                .filter(a -> a.ruleId().equals("brute-force-single-account")).toList();

        assertThat(fired).hasSize(1);
        Alert alert = fired.get(0);
        assertThat(alert.entityId()).isEqualTo("u-1");
        assertThat(alert.technique()).isEqualTo("T1110.001");
        assertThat(alert.observed()).isEqualTo(alert.threshold());
        assertThat(alert.sampleEventIds()).isNotEmpty();
        assertThat(alert.context()).containsKey("source.ip");
    }

    @Test
    void successfulLoginsNeverTripTheBruteForceRule() {
        for (int i = 0; i < 50; i++) {
            send(login("u-2", "10.0.0.5", Outcome.SUCCESS, T0.plusSeconds(i * 2L)));
        }

        assertThat(readAlerts()).noneMatch(a -> a.ruleId().equals("brute-force-single-account"));
    }

    /**
     * Failures spread far enough apart never fill one window. This is the property an attacker
     * exploits by going slow, and the reason low-and-slow needs a different rule rather than a
     * lower threshold.
     */
    @Test
    void failuresSpreadBeyondTheWindowDoNotAccumulate() {
        for (int i = 0; i < 20; i++) {
            send(login("u-3", "203.0.113.9", Outcome.FAILURE, T0.plusSeconds(i * 600L)));
        }

        assertThat(readAlerts()).noneMatch(a -> a.ruleId().equals("brute-force-single-account"));
    }

    @Test
    void distributedBruteForceCountsDistinctSourcesNotEvents() {
        // Well past the event threshold, but all from one address.
        for (int i = 0; i < 12; i++) {
            send(login("u-4", "203.0.113.20", Outcome.FAILURE, T0.plusSeconds(i * 2L)));
        }
        assertThat(readAlerts()).noneMatch(a -> a.ruleId().equals("distributed-brute-force"));

        // Five distinct addresses is what that rule is actually looking for.
        for (int i = 0; i < 5; i++) {
            send(login("u-5", "203.0.113.10" + i, Outcome.FAILURE, T0.plusSeconds(i * 2L)));
        }

        List<Alert> fired = readAlerts().stream()
                .filter(a -> a.ruleId().equals("distributed-brute-force")).toList();
        assertThat(fired).hasSize(1);
        assertThat(fired.get(0).entityId()).isEqualTo("u-5");
        assertThat(fired.get(0).context()).containsEntry("distinct_field", "source.ip");
    }

    @Test
    void credentialStuffingIsAttributedToTheSourceNotTheVictims() {
        for (int i = 0; i < 30; i++) {
            send(login("victim-" + i, "198.51.100.7", Outcome.FAILURE, T0.plusSeconds(i * 2L)));
        }

        List<Alert> fired = readAlerts().stream()
                .filter(a -> a.ruleId().equals("credential-stuffing-source")).toList();

        assertThat(fired).hasSize(1);
        // The entity is the attacker's infrastructure. Responding to the victims would mean
        // locking out 30 innocent accounts on the attacker's behalf.
        assertThat(fired.get(0).entityType().value()).isEqualTo("source_ip");
        assertThat(fired.get(0).entityId()).isEqualTo("198.51.100.7");
    }

    @Test
    void impossibleTravelNeedsTwoSuccessfulLoginsFromDifferentCountries() {
        SecurityEvent home = new SecurityEvent(T0,
                new SecurityEvent.EventInfo(UUID.randomUUID().toString(), EventCategory.AUTHENTICATION,
                        EventAction.USER_LOGIN, Outcome.SUCCESS, null),
                new SecurityEvent.UserInfo("u-6", "x", "bloodhound.lab"),
                new SecurityEvent.SourceInfo("10.0.0.1", 443, new SecurityEvent.GeoInfo("DE", "Berlin")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo("Firefox"), Map.of());

        SecurityEvent abroad = new SecurityEvent(T0.plus(Duration.ofMinutes(4)),
                new SecurityEvent.EventInfo(UUID.randomUUID().toString(), EventCategory.AUTHENTICATION,
                        EventAction.USER_LOGIN, Outcome.SUCCESS, null),
                new SecurityEvent.UserInfo("u-6", "x", "bloodhound.lab"),
                new SecurityEvent.SourceInfo("203.0.113.50", 443, new SecurityEvent.GeoInfo("SG", "Singapore")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo("python-requests/2.32.3"), Map.of());

        send(home);
        send(abroad);

        List<Alert> fired = readAlerts().stream()
                .filter(a -> a.ruleId().equals("impossible-travel")).toList();

        assertThat(fired).hasSize(1);
        assertThat(fired.get(0).entityId()).isEqualTo("u-6");
        assertThat(fired.get(0).context())
                .containsEntry("previous_country", "DE")
                .containsEntry("current_country", "SG");
    }

    /**
     * A malformed record must not kill the stream thread. An attacker who can make the detector
     * crash has disabled every detection at once — the cheapest possible evasion.
     */
    @Test
    void malformedRecordsAreDroppedWithoutKillingTheTopology() {
        events.pipeInput("u-7", "this is not json", T0);
        events.pipeInput("u-7", "{\"@timestamp\":\"nonsense\"}", T0);

        // The topology is still alive and still detecting.
        for (int i = 0; i < 25; i++) {
            send(login("u-7", "203.0.113.77", Outcome.FAILURE, T0.plusSeconds(i * 2L)));
        }

        assertThat(readAlerts()).anyMatch(a -> a.ruleId().equals("brute-force-single-account"));
    }
}
