package io.bloodhound.responder.incidents;

import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.responder.audit.AuditLog;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Incidents: the unit of investigation, one per entity under suspicion.
 *
 * <p>Alerts are machine output; incidents are human work. The mapping is deliberately many-to-one
 * and keyed on the entity, so an account under sustained attack generates one investigation that
 * accumulates evidence rather than a new ticket every five minutes.
 *
 * <p>The state machine is enforced in code rather than left to convention. An incident that can
 * jump from `new` straight to `resolved` is a ticket, not an investigation — the value of the
 * intermediate states is that they force somebody to have actually looked.
 */
@Service
public class IncidentService {

    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    /** Which transitions are legal from each state. */
    private static final Map<String, Set<String>> TRANSITIONS = Map.of(
            "new", Set.of("triaged", "false_positive"),
            "triaged", Set.of("investigating", "contained", "resolved", "false_positive"),
            "investigating", Set.of("contained", "resolved", "false_positive"),
            "contained", Set.of("investigating", "resolved"),
            // Terminal. Reopening is deliberately not offered: if it comes back, it is a new
            // incident with a new timeline, and the old one stays as the record of what was
            // concluded and when.
            "resolved", Set.of(),
            "false_positive", Set.of());

    private final JdbcTemplate jdbc;
    private final AuditLog audit;
    private final Counter opened;

    public IncidentService(JdbcTemplate jdbc, AuditLog audit, MeterRegistry meters) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.opened = Counter.builder("bloodhound.incidents.opened").register(meters);
    }

    /**
     * Finds the open incident for this entity, or opens one.
     *
     * <p>Relies on the partial unique index rather than a read-then-write check: two alerts for
     * the same entity arriving on different consumer threads would both see "no incident" and
     * both insert. The database is the only place that race can be settled.
     */
    @Transactional
    public long openOrAttach(Alert alert, String alertId, double riskScore) {
        Optional<Long> existing = findOpen(alert.entityType(), alert.entityId());

        long incidentId;
        if (existing.isPresent()) {
            incidentId = existing.get();
            // An incident's severity is the worst thing seen in it, never downgraded by a
            // subsequent quieter alert.
            jdbc.update("""
                    update incidents
                    set updated_at = now(),
                        risk_score = ?,
                        severity = case
                            when ? = 'critical' then 'critical'
                            when ? = 'high' and severity not in ('critical') then 'high'
                            when ? = 'medium' and severity not in ('critical','high') then 'medium'
                            else severity end
                    where id = ?
                    """,
                    riskScore, alert.severity().value(), alert.severity().value(),
                    alert.severity().value(), incidentId);
        } else {
            incidentId = jdbc.queryForObject("""
                    insert into incidents (status, severity, title, entity_type, entity_id, risk_score)
                    values ('new', ?, ?, ?, ?, ?)
                    returning id
                    """, Long.class,
                    alert.severity().value(),
                    titleFor(alert),
                    alert.entityType().value(), alert.entityId(), riskScore);
            opened.increment();
            audit.record("system", "incident_opened", "incident", String.valueOf(incidentId), "success",
                    Map.of("entity", alert.entityType().value() + ":" + alert.entityId(),
                            "rule", alert.ruleId(), "riskScore", riskScore));
            log.info("Incident {} opened for {}:{} (risk {})",
                    incidentId, alert.entityType().value(), alert.entityId(), Math.round(riskScore));
        }

        jdbc.update("update alerts set incident_id = ? where id = ?", incidentId, alertId);
        return incidentId;
    }

    public Optional<Long> findOpen(EntityType entityType, String entityId) {
        List<Long> ids = jdbc.queryForList("""
                select id from incidents
                where entity_type = ? and entity_id = ?
                  and status not in ('resolved', 'false_positive')
                """, Long.class, entityType.value(), entityId);
        return ids.isEmpty() ? Optional.empty() : Optional.of(ids.get(0));
    }

    @Transactional
    public void transition(long incidentId, String newStatus, String actor, String note) {
        String current = jdbc.queryForObject(
                "select status from incidents where id = ?", String.class, incidentId);
        if (current == null) {
            throw new IllegalArgumentException("No incident " + incidentId);
        }
        Set<String> allowed = TRANSITIONS.getOrDefault(current, Set.of());
        if (!allowed.contains(newStatus)) {
            throw new IllegalArgumentException(
                    "Cannot move incident %d from '%s' to '%s'. Allowed: %s"
                            .formatted(incidentId, current, newStatus, allowed));
        }

        boolean terminal = newStatus.equals("resolved") || newStatus.equals("false_positive");
        jdbc.update("""
                update incidents
                set status = ?, updated_at = now(),
                    closed_at = case when ? then now() else closed_at end,
                    resolution = coalesce(?, resolution)
                where id = ?
                """, newStatus, terminal, terminal ? note : null, incidentId);

        if (note != null && !note.isBlank()) {
            addNote(incidentId, actor, note);
        }
        audit.record(actor, "incident_" + newStatus, "incident", String.valueOf(incidentId),
                "success", Map.of("from", current, "to", newStatus));
    }

    @Transactional
    public void assign(long incidentId, String assignee, String actor) {
        jdbc.update("update incidents set assignee = ?, updated_at = now() where id = ?",
                assignee, incidentId);
        audit.record(actor, "incident_assigned", "incident", String.valueOf(incidentId),
                "success", Map.of("assignee", assignee));
    }

    public void addNote(long incidentId, String author, String note) {
        jdbc.update("insert into incident_notes (incident_id, author, note) values (?, ?, ?)",
                incidentId, author, note);
    }

    public List<Map<String, Object>> list(String status, int limit) {
        if (status == null) {
            return jdbc.queryForList("""
                    select i.*, (select count(*) from alerts a where a.incident_id = i.id) as alert_count
                    from incidents i order by i.updated_at desc limit ?
                    """, Math.min(Math.max(limit, 1), 200));
        }
        return jdbc.queryForList("""
                select i.*, (select count(*) from alerts a where a.incident_id = i.id) as alert_count
                from incidents i where i.status = ? order by i.updated_at desc limit ?
                """, status, Math.min(Math.max(limit, 1), 200));
    }

    /** Everything about one incident: the record, its alerts, its notes, its response actions. */
    public Map<String, Object> detail(long incidentId) {
        Map<String, Object> incident = jdbc.queryForMap(
                "select * from incidents where id = ?", incidentId);
        return Map.of(
                "incident", incident,
                "alerts", jdbc.queryForList("""
                        select id, rule_id, rule_name, severity, technique, occurrences,
                               first_detected_at, last_detected_at, observed, threshold, triage, context
                        from alerts where incident_id = ? order by last_detected_at desc
                        """, incidentId),
                "notes", jdbc.queryForList(
                        "select at, author, note from incident_notes where incident_id = ? order by at",
                        incidentId),
                "actions", jdbc.queryForList("""
                        select id, action, target_type, target_id, status, requires_approval,
                               reversible, proposed_at, approved_by, executed_at, result, error
                        from response_actions where incident_id = ? order by proposed_at
                        """, incidentId),
                "allowedTransitions", TRANSITIONS.getOrDefault(
                        String.valueOf(incident.get("status")), Set.of()));
    }

    private static String titleFor(Alert alert) {
        String what = alert.severity() == Severity.CRITICAL || alert.severity() == Severity.HIGH
                ? "Suspected compromise" : "Suspicious activity";
        return "%s: %s %s".formatted(what, alert.entityType().value(), alert.entityId());
    }
}
