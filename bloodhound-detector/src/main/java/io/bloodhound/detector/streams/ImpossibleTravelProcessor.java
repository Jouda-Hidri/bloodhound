package io.bloodhound.detector.streams;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.detector.config.DetectorProperties;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.ProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.KeyValueStore;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Detects a successful login from a country the account was somewhere else in, moments ago.
 *
 * <p><b>Why this is not a YAML rule.</b> Every other detection here asks "how many things happened
 * in a window". This one asks "what happened immediately before this thing, and was it consistent
 * with it" — a comparison between consecutive events for the same key, with no threshold at all.
 * Bending the rule DSL to express that would have meant inventing a sequence language; writing
 * thirty lines of processor was the smaller cost. Knowing where a declarative abstraction stops
 * paying for itself is most of the skill in building one.
 *
 * <p>The known weakness, and it is significant: this cannot tell travel from a VPN. A user who
 * connects through a VPN egress in another country produces exactly this signal. In production
 * the fix is enrichment — knowing which IP ranges are your own VPN, which are hosting providers,
 * which are residential — not a cleverer rule. Until then the rule is deliberately MEDIUM
 * severity and feeds risk scoring rather than triggering containment on its own.
 */
public class ImpossibleTravelProcessor implements Processor<String, SecurityEvent, String, Alert> {

    public static final String STORE_NAME = "impossible-travel-last-login";
    public static final String RULE_ID = "impossible-travel";

    private final Duration maxPlausibleGap;
    private final Duration stateRetention;

    private ProcessorContext<String, Alert> context;
    private KeyValueStore<String, LastLogin> store;

    public ImpossibleTravelProcessor(DetectorProperties.ImpossibleTravel config) {
        this.maxPlausibleGap = config.getMaxPlausibleGap();
        this.stateRetention = config.getStateRetention();
    }

    @Override
    public void init(ProcessorContext<String, Alert> context) {
        this.context = context;
        this.store = context.getStateStore(STORE_NAME);

        // A KeyValueStore has no retention of its own — unlike a window store, entries live
        // forever. Without this sweep the store grows by one entry per account that has ever
        // logged in and never shrinks.
        context.schedule(Duration.ofHours(1),
                org.apache.kafka.streams.processor.PunctuationType.WALL_CLOCK_TIME,
                this::evictStaleEntries);
    }

    @Override
    public void process(Record<String, SecurityEvent> record) {
        SecurityEvent event = record.value();
        if (event == null || record.key() == null || event.timestamp() == null) {
            return;
        }

        String country = event.source() != null && event.source().geo() != null
                ? event.source().geo().countryIsoCode() : null;
        if (country == null) {
            return;
        }

        String ip = event.source() != null ? event.source().ip() : null;
        LastLogin previous = store.get(record.key());
        LastLogin current = new LastLogin(country, ip, event.timestamp());

        // Only move the stored position forward. Late-arriving events must not rewrite history
        // into an order that never happened.
        if (previous == null || current.at().isAfter(previous.at())) {
            store.put(record.key(), current);
        }

        if (previous == null || previous.country() == null || previous.country().equals(country)) {
            return;
        }

        Duration gap = Duration.between(previous.at(), event.timestamp()).abs();
        if (gap.compareTo(maxPlausibleGap) > 0) {
            return;
        }

        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("previous_country", previous.country());
        evidence.put("current_country", country);
        evidence.put("previous_ip", String.valueOf(previous.ip()));
        evidence.put("current_ip", String.valueOf(ip));
        evidence.put("gap_seconds", String.valueOf(gap.toSeconds()));
        evidence.put("max_plausible_gap_seconds", String.valueOf(maxPlausibleGap.toSeconds()));

        Alert alert = new Alert(
                UUID.randomUUID().toString(),
                Instant.now(),
                previous.at(),
                event.timestamp(),
                RULE_ID,
                "Login from an implausible location change",
                Severity.MEDIUM,
                "T1078",
                EntityType.USER,
                record.key(),
                gap.toSeconds(),
                maxPlausibleGap.toSeconds(),
                evidence,
                event.event() != null ? java.util.List.of(event.event().id()) : java.util.List.of());

        context.forward(record.withKey(record.key()).withValue(alert));
    }

    private void evictStaleEntries(long wallClockMillis) {
        Instant cutoff = Instant.ofEpochMilli(wallClockMillis).minus(stateRetention);
        try (var iterator = store.all()) {
            while (iterator.hasNext()) {
                var entry = iterator.next();
                if (entry.value != null && entry.value.at().isBefore(cutoff)) {
                    store.delete(entry.key);
                }
            }
        }
    }

    /** Where an account was last seen logging in from. */
    public record LastLogin(
            @JsonProperty("country") String country,
            @JsonProperty("ip") String ip,
            @JsonProperty("at") Instant at
    ) {}
}
