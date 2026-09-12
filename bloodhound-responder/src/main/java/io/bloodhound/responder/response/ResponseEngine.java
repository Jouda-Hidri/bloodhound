package io.bloodhound.responder.response;

import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.responder.audit.AuditLog;
import io.bloodhound.responder.config.ResponderProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Decides what to do about an incident, and does it — under supervision.
 *
 * <p>The design principle throughout: <b>propose freely, execute reluctantly.</b> Every action is
 * written down before anything happens, destructive ones wait for a human, and the reversal path
 * exists before the action does.
 *
 * <p>The reason for that caution is not squeamishness. Response automation is a weapon pointed at
 * your own users: an attacker who works out that twelve failed logins disables an account has
 * been handed a way to lock out anyone they can name. Every automatic containment decision has to
 * be justified against that, and the honest answer for account lockout is "not without a human".
 */
@Service
public class ResponseEngine {

    private static final Logger log = LoggerFactory.getLogger(ResponseEngine.class);

    public static final String DISABLE_ACCOUNT = "disable_account";
    public static final String REVOKE_SESSIONS = "revoke_sessions";
    public static final String BLOCK_SOURCE_IP = "block_source_ip";

    private final JdbcTemplate jdbc;
    private final LabIamClient iam;
    private final AuditLog audit;
    private final ResponderProperties props;
    private final Counter proposed;
    private final Counter executed;
    private final Counter failed;

    public ResponseEngine(JdbcTemplate jdbc, LabIamClient iam, AuditLog audit,
                          ResponderProperties props, MeterRegistry meters) {
        this.jdbc = jdbc;
        this.iam = iam;
        this.audit = audit;
        this.props = props;
        this.proposed = Counter.builder("bloodhound.response.proposed").register(meters);
        this.executed = Counter.builder("bloodhound.response.executed").register(meters);
        this.failed = Counter.builder("bloodhound.response.failed").register(meters);
    }

    /**
     * Runs the playbook for an alert and proposes whatever it calls for.
     *
     * @return ids of the actions proposed (possibly empty)
     */
    @Transactional
    public List<Long> evaluate(Alert alert, String alertId, Long incidentId, double riskScore) {
        if (!props.getResponse().isEnabled()) {
            return List.of();
        }

        List<Long> actions = new ArrayList<>();
        double containAt = props.getRisk().getContainmentThreshold();

        if (alert.entityType() == EntityType.USER) {
            // Session revocation: the lighter-touch option, and the right first move for a
            // suspected token theft. It evicts an attacker holding a stolen session while leaving
            // the legitimate owner able to log straight back in.
            if (isSessionCompromiseSignal(alert)) {
                actions.add(propose(incidentId, alertId, REVOKE_SESSIONS, "user", alert.entityId(),
                        "%s (%s) — possible session or credential compromise"
                                .formatted(alert.ruleName(), alert.ruleId()),
                        false, true, alert.severity()));
            }

            // Account lockout: contains the attacker by also denying the user. Only at genuinely
            // high accumulated risk, and never without approval.
            if (riskScore >= containAt || alert.severity() == Severity.CRITICAL) {
                actions.add(propose(incidentId, alertId, DISABLE_ACCOUNT, "user", alert.entityId(),
                        "risk score %.0f at or above containment threshold %.0f"
                                .formatted(riskScore, containAt),
                        true, true, alert.severity()));
            }
        }

        if (alert.entityType() == EntityType.SOURCE_IP && alert.severity().atLeast(Severity.HIGH)) {
            actions.add(propose(incidentId, alertId, BLOCK_SOURCE_IP, "source_ip", alert.entityId(),
                    "%s — hostile infrastructure".formatted(alert.ruleName()),
                    true, true, alert.severity()));
        }

        return actions.stream().filter(java.util.Objects::nonNull).toList();
    }

    /** Impossible travel and session hijack both point at a live session being used by someone else. */
    private static boolean isSessionCompromiseSignal(Alert alert) {
        return ("T1078".equals(alert.technique()) || "T1539".equals(alert.technique())
                || "T1098".equals(alert.technique()))
                && alert.severity().atLeast(Severity.MEDIUM);
    }

    /**
     * Records a proposed action, then executes it if policy allows.
     *
     * @return the action id, or null if an equivalent action is already outstanding
     */
    @Transactional
    public Long propose(Long incidentId, String alertId, String action, String targetType,
                        String targetId, String reason, boolean destructive, boolean reversible,
                        Severity severity) {

        // Do not stack identical actions. A sustained attack produces an alert every window; it
        // should not produce a hundred lockout proposals for the same account.
        Integer outstanding = jdbc.queryForObject("""
                select count(*) from response_actions
                where action = ? and target_type = ? and target_id = ?
                  and status in ('proposed', 'approved', 'executed')
                """, Integer.class, action, targetType, targetId);
        if (outstanding != null && outstanding > 0) {
            return null;
        }

        boolean requiresApproval = destructive
                || Boolean.TRUE.equals(props.getResponse().getAlwaysRequireApproval().get(action));

        Long id = jdbc.queryForObject("""
                insert into response_actions (
                    incident_id, alert_id, action, target_type, target_id, reason,
                    status, requires_approval, reversible
                ) values (?, ?, ?, ?, ?, ?, 'proposed', ?, ?)
                returning id
                """, Long.class,
                incidentId, alertId, action, targetType, targetId, reason,
                requiresApproval, reversible);

        proposed.increment();
        audit.record("system", "action_proposed", targetType, targetId, "success",
                Map.of("action", action, "reason", reason, "requiresApproval", requiresApproval,
                        "actionId", String.valueOf(id)));
        log.info("Proposed {} on {}:{} ({}approval required) — {}",
                action, targetType, targetId, requiresApproval ? "" : "no ", reason);

        boolean mayAutoExecute = props.getResponse().isAutoExecute()
                && !requiresApproval
                && severity.atLeast(props.getResponse().getAutoExecuteMinSeverity());

        if (mayAutoExecute && id != null) {
            execute(id, "system(auto)");
        }
        return id;
    }

    @Transactional
    public Map<String, Object> approve(long actionId, String approver) {
        Map<String, Object> action = jdbc.queryForMap(
                "select * from response_actions where id = ?", actionId);
        if (!"proposed".equals(action.get("status"))) {
            throw new IllegalStateException(
                    "Action " + actionId + " is '" + action.get("status") + "', not 'proposed'");
        }
        jdbc.update("update response_actions set status = 'approved', approved_at = now(), "
                + "approved_by = ? where id = ?", approver, actionId);
        audit.record(approver, "action_approved", (String) action.get("target_type"),
                (String) action.get("target_id"), "success",
                Map.of("action", String.valueOf(action.get("action")), "actionId", String.valueOf(actionId)));
        return execute(actionId, approver);
    }

    @Transactional
    public void reject(long actionId, String actor, String why) {
        Map<String, Object> action = jdbc.queryForMap(
                "select * from response_actions where id = ?", actionId);
        jdbc.update("update response_actions set status = 'rejected', result = ? where id = ?",
                why, actionId);
        audit.record(actor, "action_rejected", (String) action.get("target_type"),
                (String) action.get("target_id"), "success",
                Map.of("action", String.valueOf(action.get("action")), "reason", String.valueOf(why)));
    }

    @Transactional
    public Map<String, Object> execute(long actionId, String actor) {
        Map<String, Object> row = jdbc.queryForMap(
                "select * from response_actions where id = ?", actionId);
        String action = (String) row.get("action");
        String targetId = (String) row.get("target_id");
        String targetType = (String) row.get("target_type");
        String reason = String.valueOf(row.get("reason"));

        LabIamClient.ActionOutcome outcome = switch (action) {
            case DISABLE_ACCOUNT -> iam.disableAccount(targetId, reason);
            case REVOKE_SESSIONS -> iam.revokeSessions(targetId, reason);
            // There is no firewall in this lab. Recording the action rather than pretending to
            // perform it keeps the audit trail honest: this is what *would* have been done.
            case BLOCK_SOURCE_IP -> new LabIamClient.ActionOutcome(true,
                    "recorded only — no network enforcement point exists in this environment", null);
            default -> new LabIamClient.ActionOutcome(false, null, "unknown action " + action);
        };

        if (outcome.success()) {
            executed.increment();
            jdbc.update("update response_actions set status = 'executed', executed_at = now(), "
                    + "result = ? where id = ?", outcome.result(), actionId);
            audit.record(actor, "action_executed", targetType, targetId, "success",
                    Map.of("action", action, "actionId", String.valueOf(actionId),
                            "result", String.valueOf(outcome.result())));
            log.warn("EXECUTED {} on {}:{} by {}", action, targetType, targetId, actor);
        } else {
            failed.increment();
            jdbc.update("update response_actions set status = 'failed', executed_at = now(), "
                    + "error = ? where id = ?", outcome.error(), actionId);
            audit.record(actor, "action_executed", targetType, targetId, "failure",
                    Map.of("action", action, "actionId", String.valueOf(actionId),
                            "error", String.valueOf(outcome.error())));
            log.error("FAILED {} on {}:{} — {}", action, targetType, targetId, outcome.error());
        }

        return jdbc.queryForMap("select * from response_actions where id = ?", actionId);
    }

    /**
     * Undoes an executed action.
     *
     * <p>Every automated containment needs this before it ships. Response automation without a
     * reversal path is a one-way door, and the first false positive that locks out a real user at
     * 3am is not the moment to be writing one.
     */
    @Transactional
    public Map<String, Object> revert(long actionId, String actor) {
        Map<String, Object> row = jdbc.queryForMap(
                "select * from response_actions where id = ?", actionId);
        if (!"executed".equals(row.get("status"))) {
            throw new IllegalStateException("Only executed actions can be reverted");
        }
        if (!Boolean.TRUE.equals(row.get("reversible"))) {
            throw new IllegalStateException("Action " + actionId + " is not reversible");
        }

        String action = (String) row.get("action");
        String targetId = (String) row.get("target_id");

        LabIamClient.ActionOutcome outcome = switch (action) {
            case DISABLE_ACCOUNT -> iam.enableAccount(targetId);
            // Revoked sessions cannot be un-revoked; the user simply logs in again. Marking it
            // reverted records the decision without claiming an effect that did not happen.
            case REVOKE_SESSIONS -> new LabIamClient.ActionOutcome(true,
                    "sessions cannot be restored; the user may re-authenticate", null);
            case BLOCK_SOURCE_IP -> new LabIamClient.ActionOutcome(true, "block record cleared", null);
            default -> new LabIamClient.ActionOutcome(false, null, "unknown action " + action);
        };

        if (!outcome.success()) {
            throw new IllegalStateException("Revert failed: " + outcome.error());
        }

        jdbc.update("update response_actions set status = 'reverted', reverted_at = now(), "
                + "reverted_by = ?, result = ? where id = ?", actor, outcome.result(), actionId);
        audit.record(actor, "action_reverted", (String) row.get("target_type"), targetId,
                "success", Map.of("action", action, "actionId", String.valueOf(actionId)));
        log.warn("REVERTED {} on {} by {}", action, targetId, actor);

        return jdbc.queryForMap("select * from response_actions where id = ?", actionId);
    }

    public List<Map<String, Object>> list(String status, int limit) {
        if (status == null) {
            return jdbc.queryForList(
                    "select * from response_actions order by proposed_at desc limit ?",
                    Math.min(Math.max(limit, 1), 200));
        }
        return jdbc.queryForList(
                "select * from response_actions where status = ? order by proposed_at desc limit ?",
                status, Math.min(Math.max(limit, 1), 200));
    }
}
