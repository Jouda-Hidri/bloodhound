package io.bloodhound.producer.api;

import io.bloodhound.producer.iam.LabIamService;
import io.bloodhound.producer.kafka.EventPublisher;
import io.bloodhound.producer.sim.AttackSimulator;
import io.bloodhound.producer.sim.ContinuousAdversary;
import io.bloodhound.producer.sim.SimulationProperties;
import io.bloodhound.producer.sim.UserPool;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Hand controls for the simulation. Lab only — there is no auth on this, by design. */
@RestController
@RequestMapping("/sim")
public class SimulationController {

    private final AttackSimulator attacks;
    private final ContinuousAdversary adversary;
    private final UserPool users;
    private final EventPublisher publisher;
    private final SimulationProperties props;
    private final LabIamService iam;

    public SimulationController(AttackSimulator attacks, ContinuousAdversary adversary,
                                UserPool users, EventPublisher publisher,
                                SimulationProperties props, LabIamService iam) {
        this.attacks = attacks;
        this.adversary = adversary;
        this.users = users;
        this.publisher = publisher;
        this.props = props;
        this.iam = iam;
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("normalTrafficEnabled", props.isEnabled());
        status.put("eventsPerSecond", props.getEventsPerSecond());
        status.put("users", users.all().size());
        status.put("published", publisher.publishedCount());
        status.put("publishFailures", publisher.failedCount());
        status.put("adversaryEnabled", props.getAdversary().isEnabled());
        status.put("adversaryIntensity", props.getAdversary().getIntensity());
        status.put("adversaryAttacksFired", adversary.firedCount());
        status.put("disabledAccounts", iam.disabledAccounts().size());
        return status;
    }

    @GetMapping("/scenarios")
    public List<String> scenarios() {
        return AttackSimulator.SCENARIOS;
    }

    @GetMapping("/users")
    public List<Map<String, String>> sampleUsers(@RequestParam(defaultValue = "10") int limit) {
        return users.all().stream()
                .limit(Math.max(1, limit))
                .map(u -> Map.of("id", u.id(), "name", u.name(), "country", u.homeCountry()))
                .toList();
    }

    @PostMapping("/traffic")
    public Map<String, Object> setTraffic(@RequestParam(required = false) Boolean enabled,
                                          @RequestParam(required = false) Integer eventsPerSecond) {
        if (enabled != null) {
            props.setEnabled(enabled);
        }
        if (eventsPerSecond != null) {
            props.setEventsPerSecond(Math.max(0, eventsPerSecond));
        }
        return status();
    }

    // ------------------------------------------------------------------
    // Continuous adversary
    // ------------------------------------------------------------------

    @PostMapping("/adversary")
    public Map<String, Object> setAdversary(@RequestParam(required = false) Boolean enabled,
                                            @RequestParam(required = false) Double intensity) {
        if (enabled != null) {
            props.getAdversary().setEnabled(enabled);
        }
        if (intensity != null) {
            props.getAdversary().setIntensity(intensity);
        }
        return status();
    }

    @GetMapping("/adversary/recent")
    public List<ContinuousAdversary.AdversaryRun> adversaryHistory(
            @RequestParam(defaultValue = "20") int limit) {
        return adversary.recent(limit);
    }

    // ------------------------------------------------------------------
    // Hand-fired scenarios
    // ------------------------------------------------------------------

    @PostMapping("/attack/brute-force")
    public AttackSimulator.ScenarioResult bruteForce(
            @RequestParam(required = false) String userId,
            @RequestParam(defaultValue = "25") int attempts,
            @RequestParam(defaultValue = "1") int sources,
            @RequestParam(defaultValue = "false") boolean succeed) {
        return attacks.bruteForce(userId, attempts, sources, succeed);
    }

    @PostMapping("/attack/credential-stuffing")
    public AttackSimulator.ScenarioResult credentialStuffing(
            @RequestParam(defaultValue = "150") int targetUsers,
            @RequestParam(defaultValue = "3") int sources) {
        return attacks.credentialStuffing(targetUsers, sources);
    }

    @PostMapping("/attack/password-spray")
    public AttackSimulator.ScenarioResult passwordSpray(
            @RequestParam(defaultValue = "60") int targetUsers,
            @RequestParam(defaultValue = "2") int attemptsPerUser,
            @RequestParam(defaultValue = "6") int sources,
            @RequestParam(defaultValue = "20") int spreadMinutes) {
        return attacks.passwordSpray(targetUsers, attemptsPerUser, sources, spreadMinutes);
    }

    @PostMapping("/attack/impossible-travel")
    public AttackSimulator.ScenarioResult impossibleTravel(
            @RequestParam(required = false) String userId,
            @RequestParam(defaultValue = "4") int minutesApart) {
        return attacks.impossibleTravel(userId, minutesApart);
    }

    @PostMapping("/attack/session-hijack")
    public AttackSimulator.ScenarioResult sessionHijack(
            @RequestParam(required = false) String userId,
            @RequestParam(defaultValue = "15") int apiCalls) {
        return attacks.sessionHijack(userId, apiCalls);
    }

    @PostMapping("/attack/dormant-reactivation")
    public AttackSimulator.ScenarioResult dormantReactivation(
            @RequestParam(required = false) String userId) {
        return attacks.dormantReactivation(userId);
    }

    @PostMapping("/attack/privilege-escalation")
    public AttackSimulator.ScenarioResult privilegeEscalation(
            @RequestParam(required = false) String userId,
            @RequestParam(defaultValue = "12") int probes,
            @RequestParam(defaultValue = "true") boolean succeed) {
        return attacks.privilegeEscalation(userId, probes, succeed);
    }

    @PostMapping("/attack/api-key-abuse")
    public AttackSimulator.ScenarioResult apiKeyAbuse(
            @RequestParam(required = false) String userId,
            @RequestParam(defaultValue = "50") int calls) {
        return attacks.apiKeyAbuse(userId, calls);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
