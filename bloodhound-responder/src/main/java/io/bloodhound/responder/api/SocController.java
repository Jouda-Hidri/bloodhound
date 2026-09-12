package io.bloodhound.responder.api;

import io.bloodhound.responder.alerts.AlertService;
import io.bloodhound.responder.audit.AuditLog;
import io.bloodhound.responder.incidents.IncidentService;
import io.bloodhound.responder.response.ResponseEngine;
import io.bloodhound.responder.risk.RiskScoreService;
import io.bloodhound.responder.security.ApiKeyAuthFilter.Role;
import io.bloodhound.responder.security.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * The analyst-facing API: alerts, risk, incidents, response.
 *
 * <p>Read operations need VIEWER, triage and incident work need ANALYST, and anything that
 * changes the outside world needs RESPONDER.
 */
@RestController
public class SocController {

    private final AlertService alerts;
    private final RiskScoreService risk;
    private final IncidentService incidents;
    private final ResponseEngine response;
    private final AuditLog audit;
    private final RequestContext context;

    public SocController(AlertService alerts, RiskScoreService risk, IncidentService incidents,
                         ResponseEngine response, AuditLog audit, RequestContext context) {
        this.alerts = alerts;
        this.risk = risk;
        this.incidents = incidents;
        this.response = response;
        this.audit = audit;
        this.context = context;
    }

    // ------------------------------------------------------------------
    // Alerts
    // ------------------------------------------------------------------

    @GetMapping("/alerts")
    public List<Map<String, Object>> listAlerts(
            HttpServletRequest request,
            @RequestParam(defaultValue = "25") int limit,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) Boolean active,
            @RequestParam(required = false) String triage) {
        context.require(request, Role.VIEWER);
        return alerts.list(limit, severity, active, triage);
    }

    /** Per-rule volume and measured precision. The input to tuning. */
    @GetMapping("/alerts/rule-stats")
    public List<Map<String, Object>> ruleStats(HttpServletRequest request) {
        context.require(request, Role.VIEWER);
        return alerts.ruleStats();
    }

    @PostMapping("/alerts/{alertId}/triage")
    public Map<String, Object> triage(HttpServletRequest request,
                                      @PathVariable String alertId,
                                      @RequestParam String verdict,
                                      @RequestParam(required = false) String note) {
        String actor = context.require(request, Role.ANALYST);
        boolean updated = alerts.triage(alertId, verdict, actor, note);
        audit.record(actor, "alert_triaged", "alert", alertId, updated ? "success" : "not_found",
                Map.of("verdict", verdict));
        return Map.of("alertId", alertId, "verdict", verdict, "updated", updated);
    }

    // ------------------------------------------------------------------
    // Risk
    // ------------------------------------------------------------------

    @GetMapping("/risk")
    public List<Map<String, Object>> topRisk(HttpServletRequest request,
                                             @RequestParam(defaultValue = "20") int limit) {
        context.require(request, Role.VIEWER);
        return risk.topRisk(limit);
    }

    // ------------------------------------------------------------------
    // Incidents
    // ------------------------------------------------------------------

    @GetMapping("/incidents")
    public List<Map<String, Object>> listIncidents(HttpServletRequest request,
                                                   @RequestParam(required = false) String status,
                                                   @RequestParam(defaultValue = "25") int limit) {
        context.require(request, Role.VIEWER);
        return incidents.list(status, limit);
    }

    @GetMapping("/incidents/{id}")
    public Map<String, Object> incident(HttpServletRequest request, @PathVariable long id) {
        context.require(request, Role.VIEWER);
        return incidents.detail(id);
    }

    @PostMapping("/incidents/{id}/status")
    public Map<String, Object> transition(HttpServletRequest request,
                                          @PathVariable long id,
                                          @RequestParam String status,
                                          @RequestParam(required = false) String note) {
        String actor = context.require(request, Role.ANALYST);
        incidents.transition(id, status, actor, note);
        return incidents.detail(id);
    }

    @PostMapping("/incidents/{id}/assign")
    public Map<String, Object> assign(HttpServletRequest request,
                                      @PathVariable long id,
                                      @RequestParam String assignee) {
        String actor = context.require(request, Role.ANALYST);
        incidents.assign(id, assignee, actor);
        return incidents.detail(id);
    }

    @PostMapping("/incidents/{id}/notes")
    public Map<String, Object> addNote(HttpServletRequest request,
                                       @PathVariable long id,
                                       @RequestParam String note) {
        String actor = context.require(request, Role.ANALYST);
        incidents.addNote(id, actor, note);
        return incidents.detail(id);
    }

    // ------------------------------------------------------------------
    // Response
    // ------------------------------------------------------------------

    @GetMapping("/actions")
    public List<Map<String, Object>> listActions(HttpServletRequest request,
                                                 @RequestParam(required = false) String status,
                                                 @RequestParam(defaultValue = "25") int limit) {
        context.require(request, Role.VIEWER);
        return response.list(status, limit);
    }

    /** Approve and execute. Requires RESPONDER — this is the call that locks a real account out. */
    @PostMapping("/actions/{id}/approve")
    public Map<String, Object> approve(HttpServletRequest request, @PathVariable long id) {
        String actor = context.require(request, Role.RESPONDER);
        return response.approve(id, actor);
    }

    @PostMapping("/actions/{id}/reject")
    public Map<String, Object> reject(HttpServletRequest request, @PathVariable long id,
                                      @RequestParam(required = false) String reason) {
        String actor = context.require(request, Role.ANALYST);
        response.reject(id, actor, reason == null ? "rejected by analyst" : reason);
        return Map.of("actionId", id, "status", "rejected");
    }

    @PostMapping("/actions/{id}/revert")
    public Map<String, Object> revert(HttpServletRequest request, @PathVariable long id) {
        String actor = context.require(request, Role.RESPONDER);
        return response.revert(id, actor);
    }

    // ------------------------------------------------------------------
    // Audit
    // ------------------------------------------------------------------

    @GetMapping("/audit")
    public List<Map<String, Object>> auditTrail(HttpServletRequest request,
                                                @RequestParam(defaultValue = "50") int limit) {
        context.require(request, Role.VIEWER);
        return audit.recent(limit);
    }

    @GetMapping("/audit/subject")
    public List<Map<String, Object>> auditForSubject(HttpServletRequest request,
                                                     @RequestParam String type,
                                                     @RequestParam String id) {
        context.require(request, Role.VIEWER);
        return audit.forSubject(type, id);
    }

    // ------------------------------------------------------------------

    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class})
    public ResponseEntity<Map<String, String>> badRequest(RuntimeException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", String.valueOf(e.getMessage())));
    }

    @ExceptionHandler(org.springframework.dao.EmptyResultDataAccessException.class)
    public ResponseEntity<Map<String, String>> notFound(RuntimeException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "not found"));
    }
}
