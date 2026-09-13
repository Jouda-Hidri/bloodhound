package io.bloodhound.detector.streams;

import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.common.baseline.UserBaseline;
import io.bloodhound.common.event.SecurityEvent;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.ProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.ReadOnlyKeyValueStore;
import org.apache.kafka.streams.state.ValueAndTimestamp;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Detections that compare an event against what is normal <em>for that account</em>.
 *
 * <p>Every rule up to this point used an absolute threshold, and the population makes that a
 * losing game: the 95th-percentile account here is 4.2× the median, so a threshold tuned on a
 * typical user is either blind for the busy accounts or constantly wrong about the quiet ones.
 * Service accounts — the ones an attacker most wants — sit at the top of that distribution.
 *
 * <p>Baselines arrive as a {@link org.apache.kafka.streams.kstream.GlobalKTable} rather than a
 * database query, so the lookup is in-memory with no network call per event.
 *
 * <p><b>Several weak signals, deliberately.</b> None of these alone justifies waking anyone.
 * A new country is a holiday; a new user agent is a browser update; an unusual hour is a late
 * night. They are scored individually at LOW/MEDIUM and left to accumulate in the risk model,
 * which is the entire argument for scoring across rules rather than alerting per rule. An
 * account that is simultaneously in a new country, on a new device, at an unusual hour, after
 * ninety days of silence is a different proposition from any one of those.
 */
public class BaselineDeviationProcessor
        implements Processor<String, SecurityEvent, String, Alert> {

    public static final String STORE_NAME = "user-baselines";
    public static final String RULE_ID = "baseline-deviation";

    /** Below this many observed events, a baseline is not yet worth comparing against. */
    private static final long MIN_BASELINE_EVENTS = 20;

    /** Days of silence after which a reactivation is itself notable. */
    private static final double DORMANT_DAYS = 30.0;

    /**
     * Distinct hours an account must have been observed in before "unusual hour" means anything.
     *
     * <p>Learned the hard way. With only ~8 hours of captured history the baseline's active_hours
     * is not "when this person works", it is "when the pipeline happened to be running" — so
     * every event outside that window looked anomalous and the rule produced 197 alerts, 197 of
     * which were noise. Half a day of coverage is the minimum at which the signal is about the
     * user rather than about the observer.
     *
     * <p>The general lesson: a baseline computed over too short a window is not a weak baseline,
     * it is a misleading one, and it fires hardest exactly when you have least reason to trust it.
     */
    private static final int MIN_HOURS_FOR_HOUR_SIGNAL = 12;

    private ProcessorContext<String, Alert> context;
    /**
     * Note the {@link ValueAndTimestamp} wrapper.
     *
     * <p>A GlobalKTable materialised through {@code Materialized.as(...)} is backed by a
     * <em>timestamped</em> store, so the value that comes back is wrapped rather than the
     * record itself. Declaring this as {@code ReadOnlyKeyValueStore<String, UserBaseline>}
     * compiles cleanly — generics are erased — and then throws ClassCastException on the first
     * lookup at runtime, taking the stream thread down with it.
     */
    private ReadOnlyKeyValueStore<String, ValueAndTimestamp<UserBaseline>> baselines;

    @Override
    public void init(ProcessorContext<String, Alert> context) {
        this.context = context;
        this.baselines = context.getStateStore(STORE_NAME);
    }

    @Override
    public void process(Record<String, SecurityEvent> record) {
        SecurityEvent event = record.value();
        String userId = record.key();
        if (event == null || userId == null || event.event() == null) {
            return;
        }

        // Only successful authentications are compared. A failed login from a new country is
        // already covered by the brute-force rules, and treating it as a baseline deviation
        // would double-count the same evidence into the risk score.
        if (event.event().outcome() == null
                || !"success".equals(event.event().outcome().value())) {
            return;
        }
        String action = event.event().action() == null ? "" : event.event().action().value();
        if (!"user-login".equals(action) && !"token-issued".equals(action)) {
            return;
        }

        ValueAndTimestamp<UserBaseline> stored = baselines.get(userId);
        UserBaseline baseline = stored == null ? null : stored.value();
        if (baseline == null) {
            // No baseline yet. Unknown is not anomalous — flagging every account the batch job
            // has not reached would make this rule fire hardest on the newest users.
            return;
        }
        if (baseline.totalEvents() == null || baseline.totalEvents() < MIN_BASELINE_EVENTS) {
            return;
        }

        List<String> deviations = new ArrayList<>();
        Map<String, String> evidence = new LinkedHashMap<>();

        String country = event.source() != null && event.source().geo() != null
                ? event.source().geo().countryIsoCode() : null;
        if (country != null && !baseline.isKnownCountry(country)) {
            deviations.add("new_country");
            evidence.put("observed_country", country);
            evidence.put("known_countries", String.join(",", baseline.countries()));
        }

        String userAgent = event.userAgent() != null ? event.userAgent().original() : null;
        if (userAgent != null && !baseline.isKnownUserAgent(userAgent)) {
            deviations.add("new_user_agent");
            evidence.put("observed_user_agent", userAgent);
            evidence.put("known_user_agents", String.valueOf(baseline.userAgents().size()));
        }

        boolean hourSignalTrustworthy = baseline.activeHours() != null
                && baseline.activeHours().size() >= MIN_HOURS_FOR_HOUR_SIGNAL;
        if (event.timestamp() != null && hourSignalTrustworthy) {
            int hour = event.timestamp().atZone(ZoneOffset.UTC).getHour();
            if (!baseline.isActiveHour(hour)) {
                deviations.add("unusual_hour");
                evidence.put("observed_hour_utc", String.valueOf(hour));
                evidence.put("usual_hours_utc", String.valueOf(baseline.activeHours()));
            }
        }

        if (baseline.isDormant(DORMANT_DAYS)) {
            deviations.add("dormant_reactivation");
            evidence.put("dormant_days", String.valueOf(Math.round(baseline.dormantDays())));
        }

        if (deviations.isEmpty()) {
            return;
        }

        evidence.put("deviations", String.join(",", deviations));
        evidence.put("baseline_events", String.valueOf(baseline.totalEvents()));
        evidence.put("baseline_computed_at", String.valueOf(baseline.computedAt()));
        if (event.source() != null && event.source().ip() != null) {
            evidence.put("source.ip", event.source().ip());
        }

        // Severity rises with how many independent things are unusual at once. One deviation is
        // a Tuesday; three simultaneously is worth a person's attention.
        Severity severity = switch (deviations.size()) {
            case 1 -> Severity.LOW;
            case 2 -> Severity.MEDIUM;
            default -> Severity.HIGH;
        };

        context.forward(record.withValue(new Alert(
                UUID.randomUUID().toString(),
                Instant.now(),
                event.timestamp(),
                event.timestamp(),
                RULE_ID,
                "Login inconsistent with this account's baseline",
                severity,
                "T1078",
                EntityType.USER,
                userId,
                deviations.size(),
                1,
                evidence,
                List.of(event.event().id()))));
    }
}
