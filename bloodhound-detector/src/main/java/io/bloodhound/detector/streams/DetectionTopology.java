package io.bloodhound.detector.streams;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import io.bloodhound.common.Topics;
import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.event.EventFields;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.detector.config.DetectorProperties;
import io.bloodhound.detector.rules.DetectionRule;
import io.bloodhound.detector.rules.RuleLoader;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.utils.Bytes;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.Grouped;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Materialized;
import org.apache.kafka.streams.kstream.Named;
import org.apache.kafka.streams.kstream.Produced;
import org.apache.kafka.streams.kstream.TimeWindows;
import org.apache.kafka.streams.kstream.Windowed;
import org.apache.kafka.streams.state.KeyValueStore;
import org.apache.kafka.streams.state.StoreBuilder;
import org.apache.kafka.streams.state.Stores;
import org.apache.kafka.streams.state.WindowStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Builds one Kafka Streams topology covering every enabled rule.
 *
 * <p>All rules read from a single source. Each rule then gets its own filter, repartition topic and
 * windowed state store — Kafka Streams requires every processor node name to be unique, so rules
 * cannot share a repartition even when they group by the same field.
 *
 * <p>That is a real cost worth understanding before adding rules casually: <b>N rules means N
 * repartition topics</b>, each one an extra write and read through the broker. It is tolerable
 * here only because the repartition happens <em>after</em> each rule's filter, so a rule matching
 * 5% of events ships 5% of the stream rather than all of it. A rule with no {@code match} clause
 * would repartition everything, which is why one should never be written.
 */
@Configuration
public class DetectionTopology {

    private static final Logger log = LoggerFactory.getLogger(DetectionTopology.class);

    private final RuleLoader ruleLoader;
    private final DetectorProperties props;
    private final MeterRegistry meters;
    private final ObjectMapper mapper = EventJson.mapper();

    private volatile List<DetectionRule> loadedRules = List.of();

    public DetectionTopology(RuleLoader ruleLoader, DetectorProperties props, MeterRegistry meters) {
        this.ruleLoader = ruleLoader;
        this.props = props;
        this.meters = meters;
    }

    public List<DetectionRule> rules() {
        return loadedRules;
    }

    @Bean
    public KStream<String, SecurityEvent> detectionStream(StreamsBuilder builder) {
        Counter malformed = Counter.builder("bloodhound.detector.malformed")
                .description("Records on the input topic that could not be deserialised")
                .register(meters);

        JsonSerde<SecurityEvent> eventSerde =
                new JsonSerde<>(mapper, SecurityEvent.class, e -> malformed.increment());
        JsonSerde<DetectionState> stateSerde = new JsonSerde<>(mapper, DetectionState.class);
        JsonSerde<Alert> alertSerde = new JsonSerde<>(mapper, Alert.class);

        KStream<String, SecurityEvent> events = builder
                .stream(Topics.RAW_EVENTS,
                        Consumed.with(Serdes.String(), eventSerde)
                                .withTimestampExtractor(new EventTimeExtractor())
                                .withName("raw-events"))
                // Nulls are what JsonSerde returns for bytes it could not read. Dropping them here
                // keeps one malformed record from killing the stream thread.
                .filter((key, event) -> event != null, Named.as("drop-malformed"));

        List<DetectionRule> rules = ruleLoader.load(props.getRulesDir());
        this.loadedRules = rules;

        for (DetectionRule rule : rules) {
            if (!rule.isEnabled()) {
                log.info("Rule {} is disabled, skipping", rule.id());
                continue;
            }
            addThresholdRule(events, rule, eventSerde, stateSerde, alertSerde);
        }

        if (props.getImpossibleTravel().isEnabled()) {
            addImpossibleTravel(builder, events, eventSerde, alertSerde);
        }

        return events;
    }

    /**
     * Windowed count (or distinct count) crossing a threshold.
     *
     * <p>Caching is disabled globally in configuration so that the aggregate emits on every
     * update. That is what allows the alert to fire the moment the threshold is crossed, rather
     * than when the window closes — a brute force detected five minutes late is an incident
     * report, not a detection.
     */
    private void addThresholdRule(KStream<String, SecurityEvent> events,
                                  DetectionRule rule,
                                  JsonSerde<SecurityEvent> eventSerde,
                                  JsonSerde<DetectionState> stateSerde,
                                  JsonSerde<Alert> alertSerde) {

        Counter fired = Counter.builder("bloodhound.detector.alerts")
                .tag("rule", rule.id())
                .tag("severity", rule.severity().value())
                .description("Alerts emitted per rule")
                .register(meters);

        String safeId = rule.id().replaceAll("[^a-zA-Z0-9._-]", "-");
        // Retention must outlast window + grace, or late records would arrive to find their
        // window already expired and be silently dropped.
        Duration retention = rule.window().plus(rule.graceOrDefault()).plus(Duration.ofMinutes(5));

        events.filter((key, event) -> rule.matches(event), Named.as("match-" + safeId))
                .selectKey((key, event) -> EventFields.get(event, rule.groupBy()),
                        Named.as("key-" + safeId))
                .filter((entity, event) -> entity != null, Named.as("has-entity-" + safeId))
                // Named per rule, not per group_by field: processor node names must be unique
                // across the whole topology, and two rules grouping by user.id would collide.
                .groupByKey(Grouped.with("by-" + safeId, Serdes.String(), eventSerde))
                .windowedBy(TimeWindows.ofSizeAndGrace(rule.window(), rule.graceOrDefault()))
                .aggregate(
                        DetectionState::empty,
                        (entity, event, state) -> state.add(event, rule),
                        Materialized.<String, DetectionState, WindowStore<Bytes, byte[]>>as(
                                        "state-" + safeId)
                                .withKeySerde(Serdes.String())
                                .withValueSerde(stateSerde)
                                .withRetention(retention))
                .toStream(Named.as("stream-" + safeId))
                .filter((windowed, state) -> state != null && state.justAlerted(),
                        Named.as("threshold-" + safeId))
                .map((windowed, state) -> {
                    fired.increment();
                    return KeyValue.pair(windowed.key(), toAlert(rule, windowed, state));
                }, Named.as("alert-" + safeId))
                .to(Topics.ALERTS, Produced.with(Serdes.String(), alertSerde)
                        .withName("emit-" + safeId));
    }

    private Alert toAlert(DetectionRule rule, Windowed<String> windowed, DetectionState state) {
        Map<String, String> context = new LinkedHashMap<>();
        context.put("events_in_window", String.valueOf(state.count()));
        if (rule.isDistinctRule()) {
            context.put("distinct_field", rule.distinct());
            context.put("distinct_count", String.valueOf(state.distinctValues().size()));
            context.put("distinct_sample", sample(state.distinctValues(), 10));
            if (state.distinctTruncated()) {
                context.put("distinct_truncated", "true");
            }
        }
        state.context().forEach((field, values) -> context.put(field, String.join(", ", values)));
        if (state.firstSeen() != null) {
            context.put("first_seen", state.firstSeen().toString());
            context.put("last_seen", String.valueOf(state.lastSeen()));
        }

        return new Alert(
                UUID.randomUUID().toString(),
                Instant.now(),
                windowed.window().startTime(),
                windowed.window().endTime(),
                rule.id(),
                rule.name(),
                rule.severity(),
                rule.technique(),
                rule.entityType(),
                windowed.key(),
                state.observed(rule),
                rule.threshold(),
                context,
                state.sampleEventIds());
    }

    private void addImpossibleTravel(StreamsBuilder builder,
                                     KStream<String, SecurityEvent> events,
                                     JsonSerde<SecurityEvent> eventSerde,
                                     JsonSerde<Alert> alertSerde) {

        StoreBuilder<KeyValueStore<String, ImpossibleTravelProcessor.LastLogin>> store =
                Stores.keyValueStoreBuilder(
                        Stores.persistentKeyValueStore(ImpossibleTravelProcessor.STORE_NAME),
                        Serdes.String(),
                        new JsonSerde<>(mapper, ImpossibleTravelProcessor.LastLogin.class));
        builder.addStateStore(store);

        Counter fired = Counter.builder("bloodhound.detector.alerts")
                .tag("rule", ImpossibleTravelProcessor.RULE_ID)
                .tag("severity", "medium")
                .register(meters);

        events.filter((key, event) -> event.event() != null
                                && event.event().action() != null
                                && "user-login".equals(event.event().action().value())
                                && event.event().outcome() != null
                                && "success".equals(event.event().outcome().value()),
                        Named.as("match-impossible-travel"))
                .selectKey((key, event) -> EventFields.get(event, "user.id"),
                        Named.as("key-impossible-travel"))
                .filter((entity, event) -> entity != null, Named.as("has-entity-impossible-travel"))
                // The processor compares each login against the previous one for the same user,
                // so every event for a user must reach the same task. repartition() is what
                // guarantees that after selectKey changed the key.
                .repartition(org.apache.kafka.streams.kstream.Repartitioned
                        .with(Serdes.String(), eventSerde)
                        .withName("impossible-travel-by-user"))
                .process(() -> new ImpossibleTravelProcessor(props.getImpossibleTravel()),
                        Named.as("detect-impossible-travel"),
                        ImpossibleTravelProcessor.STORE_NAME)
                .peek((key, alert) -> fired.increment(), Named.as("count-impossible-travel"))
                .to(Topics.ALERTS, Produced.with(Serdes.String(), alertSerde)
                        .withName("emit-impossible-travel"));
    }

    private static String sample(Set<String> values, int limit) {
        List<String> sample = new ArrayList<>();
        for (String value : values) {
            if (sample.size() >= limit) {
                sample.add("…");
                break;
            }
            sample.add(value);
        }
        return String.join(", ", sample);
    }
}
