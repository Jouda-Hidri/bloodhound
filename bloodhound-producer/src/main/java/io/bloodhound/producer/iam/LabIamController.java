package io.bloodhound.producer.iam;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * The lab IAM API the responder calls to contain an account.
 *
 * <p>Stands in for whatever a real deployment would talk to — Okta, Entra ID, an internal user
 * service. Keeping it behind an HTTP boundary rather than an in-process call is deliberate: it
 * forces the responder to deal with the failure modes real containment has (timeouts, partial
 * success, an IAM system that is down exactly when you need it).
 */
@RestController
@RequestMapping("/iam")
public class LabIamController {

    private final LabIamService iam;

    public LabIamController(LabIamService iam) {
        this.iam = iam;
    }

    @GetMapping("/accounts/disabled")
    public Collection<LabIamService.AccountState> disabled() {
        return iam.disabledAccounts();
    }

    @GetMapping("/actions")
    public List<LabIamService.IamAction> actions() {
        return iam.actions();
    }

    @GetMapping("/accounts/{userId}")
    public Map<String, Object> account(@PathVariable String userId) {
        return Map.of("userId", userId, "disabled", iam.isDisabled(userId));
    }

    @PostMapping("/accounts/{userId}/disable")
    public LabIamService.AccountState disable(
            @PathVariable String userId,
            @RequestParam(defaultValue = "manual") String reason,
            @RequestParam(defaultValue = "operator") String actor) {
        return iam.disable(userId, reason, actor);
    }

    @PostMapping("/accounts/{userId}/enable")
    public Map<String, Object> enable(@PathVariable String userId,
                                      @RequestParam(defaultValue = "operator") String actor) {
        return Map.of("userId", userId, "wasDisabled", iam.enable(userId, actor));
    }

    @PostMapping("/accounts/{userId}/revoke-sessions")
    public Map<String, Object> revokeSessions(
            @PathVariable String userId,
            @RequestParam(defaultValue = "manual") String reason,
            @RequestParam(defaultValue = "operator") String actor) {
        iam.revokeSessions(userId, reason, actor);
        return Map.of("userId", userId, "sessionsRevoked", true);
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> refused(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
