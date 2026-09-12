package io.bloodhound.responder.alerts;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.alert.Alert;
import io.bloodhound.responder.config.ResponderProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

/**
 * Persists alerts, folding repeats of the same condition into one row.
 *
 * <p>Without this the console fills with hundreds of rows describing one attack. With it, an
 * ongoing brute force is a single alert whose occurrence count climbs — which is what an analyst
 * actually wants to see, and the difference between a detection programme people use and one
 * they mute.
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ResponderProperties props;
    private final Counter created;
    private final Counter deduped;

    public AlertService(JdbcTemplate jdbc, ObjectMapper eventObjectMapper,
                        ResponderProperties props, MeterRegistry meters) {
        this.jdbc = jdbc;
        this.mapper = eventObjectMapper;
        this.props = props;
        this.created = Counter.builder("bloodhound.alerts.created")
                .description("New alert rows opened").register(meters);
        this.deduped = Counter.builder("bloodhound.alerts.deduplicated")
                .description("Alerts folded into an existing open alert").register(meters);
    }

    /**
     * @return the stored alert: either a new row, or the existing open row with its occurrence
     *         count incremented.
     */
    @Transactional
    public StoredAlert record(Alert alert) {
        String context = toJson(alert.context());
        String[] samples = alert.sampleEventIds() == null
                ? new String[0] : alert.sampleEventIds().toArray(String[]::new);

        // Try to fold into an existing open alert first. The partial unique index on
        // (dedupe_key) where active guarantees there is at most one.
        List<Map<String, Object>> updated = jdbc.queryForList("""
                update alerts
                set last_detected_at = greatest(last_detected_at, ?),
                    occurrences      = occurrences + 1,
                    observed         = greatest(coalesce(observed, 0), ?),
                    window_end       = greatest(coalesce(window_end, ?), ?),
                    context          = ?::jsonb
                where dedupe_key = ? and active
                returning id, occurrences, incident_id
                """,
                Timestamp.from(alert.detectedAt()),
                alert.observed(),
                Timestamp.from(alert.windowEnd()), Timestamp.from(alert.windowEnd()),
                context,
                alert.dedupeKey());

        if (!updated.isEmpty()) {
            deduped.increment();
            Map<String, Object> row = updated.get(0);
            return new StoredAlert((String) row.get("id"),
                    ((Number) row.get("occurrences")).intValue(),
                    row.get("incident_id") == null ? null : ((Number) row.get("incident_id")).longValue(),
                    false);
        }

        jdbc.update("""
                insert into alerts (
                    id, dedupe_key, first_detected_at, last_detected_at, occurrences,
                    rule_id, rule_name, severity, technique,
                    entity_type, entity_id, observed, threshold,
                    window_start, window_end, context, sample_event_ids
                ) values (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?)
                on conflict (id) do nothing
                """,
                alert.id(), alert.dedupeKey(),
                Timestamp.from(alert.detectedAt()), Timestamp.from(alert.detectedAt()),
                alert.ruleId(), alert.ruleName(), alert.severity().value(), alert.technique(),
                alert.entityType().value(), alert.entityId(),
                alert.observed(), alert.threshold(),
                Timestamp.from(alert.windowStart()), Timestamp.from(alert.windowEnd()),
                context, samples);

        created.increment();
        return new StoredAlert(alert.id(), 1, null, true);
    }

    /**
     * Closes alerts that have stopped recurring.
     *
     * <p>Closing is what lets the condition alert again later. Without it the partial unique index
     * would keep folding next month's attack into a row from last month, and the occurrence count
     * would become meaningless. Suppression that never expires is not suppression, it is deafness.
     */
    @Scheduled(fixedRateString = "${bloodhound.responder.alerts.sweep-millis:60000}")
    @Transactional
    public void closeStaleAlerts() {
        long seconds = props.getAlerts().getSuppressionWindow().toSeconds();
        int closed = jdbc.update("""
                update alerts set active = false
                where active and last_detected_at < now() - make_interval(secs => ?)
                """, (double) seconds);
        if (closed > 0) {
            log.info("Closed {} alerts with no activity in the last {}s", closed, seconds);
        }
    }

    @Transactional
    public boolean triage(String alertId, String verdict, String analyst, String note) {
        if (!List.of("true_positive", "false_positive", "benign", "untriaged").contains(verdict)) {
            throw new IllegalArgumentException(
                    "verdict must be one of true_positive, false_positive, benign, untriaged");
        }
        return jdbc.update("""
                update alerts
                set triage = ?, triaged_at = now(), triaged_by = ?, triage_note = ?
                where id = ?
                """, verdict, analyst, note, alertId) > 0;
    }

    public List<Map<String, Object>> list(int limit, String severity, Boolean activeOnly,
                                          String triage) {
        StringBuilder sql = new StringBuilder("""
                select id, first_detected_at, last_detected_at, occurrences, rule_id, rule_name,
                       severity, technique, entity_type, entity_id, observed, threshold,
                       active, triage, incident_id, context
                from alerts where 1=1
                """);
        List<Object> args = new java.util.ArrayList<>();
        if (severity != null) {
            sql.append(" and severity = ?");
            args.add(severity);
        }
        if (activeOnly != null && activeOnly) {
            sql.append(" and active");
        }
        if (triage != null) {
            sql.append(" and triage = ?");
            args.add(triage);
        }
        sql.append(" order by last_detected_at desc limit ?");
        args.add(Math.min(Math.max(limit, 1), 200));
        return jdbc.queryForList(sql.toString(), args.toArray());
    }

    /** Per-rule volume and analyst verdicts — the raw material for tuning. */
    public List<Map<String, Object>> ruleStats() {
        return jdbc.queryForList("""
                select
                    rule_id,
                    count(*)                                              as alerts,
                    sum(occurrences)                                      as firings,
                    count(*) filter (where triage = 'true_positive')      as true_positives,
                    count(*) filter (where triage = 'false_positive')     as false_positives,
                    count(*) filter (where triage = 'untriaged')          as untriaged,
                    round(
                        count(*) filter (where triage = 'true_positive')::numeric
                        / nullif(count(*) filter (where triage in ('true_positive','false_positive')), 0),
                    3)                                                    as precision,
                    max(last_detected_at)                                 as last_fired
                from alerts
                group by rule_id
                order by alerts desc
                """);
    }

    private String toJson(Map<String, String> value) {
        try {
            return value == null ? "{}" : mapper.writeValueAsString(value);
        } catch (Exception e) {
            log.warn("Could not serialise alert context", e);
            return "{}";
        }
    }

    /** Outcome of storing an alert. */
    public record StoredAlert(String id, int occurrences, Long incidentId, boolean isNew) {}
}
