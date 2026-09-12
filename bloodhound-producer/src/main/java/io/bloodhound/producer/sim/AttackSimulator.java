package io.bloodhound.producer.sim;

import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.producer.kafka.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fires labelled attack scenarios into the stream.
 *
 * <p>Every event produced here carries {@code labels.scenario}, {@code labels.run_id} and
 * {@code labels.attack_technique}: that is the ground truth a detection is scored against.
 * Detection logic must never read these labels — only the scoring job does.
 *
 * <p>Scenarios are all back-dated: emitted at once, but timestamped across the seconds they
 * would really have taken. Stamping forward from {@code now()} would put event time ahead of
 * ingest time, making pipeline lag negative and quietly corrupting every window calculation.
 *
 * <p>All addresses used are RFC 5737 documentation ranges. Nothing here touches a real host.
 */
@Service
public class AttackSimulator {

    private static final Logger log = LoggerFactory.getLogger(AttackSimulator.class);

    private static final String[] HOSTILE_PREFIXES = {"203.0.113", "198.51.100", "192.0.2"};

    private static final String ATTACK_UA = "python-requests/2.32.3";
    private static final String HEADLESS_UA =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "HeadlessChrome/126.0.0.0 Safari/537.36";

    private final UserPool users;
    private final EventFactory events;
    private final EventPublisher publisher;
    private final AtomicLong runCounter = new AtomicLong();

    public AttackSimulator(UserPool users, EventFactory events, EventPublisher publisher) {
        this.users = users;
        this.events = events;
        this.publisher = publisher;
    }

    // ------------------------------------------------------------------
    // Credential attacks
    // ------------------------------------------------------------------

    /**
     * Many password guesses against one account. Signal: failure count per user per short window.
     * MITRE ATT&CK T1110.001.
     *
     * @param sourceCount   1 is naive; more than 1 spreads the attempts to evade per-IP limits
     * @param succeedAtEnd  whether the last attempt succeeds, turning this into a compromise
     */
    public ScenarioResult bruteForce(String userId, int attempts, int sourceCount, boolean succeedAtEnd) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        SimulatedUser target = resolveTarget(userId, rng);
        String runId = nextRunId("bf");
        List<String> sources = hostileIps(Math.max(1, sourceCount), rng);
        Map<String, String> labels = labels("brute_force", runId, "T1110.001");

        Instant now = Instant.now();
        Instant start = now.minusMillis(attempts * 250L);

        for (int i = 0; i < attempts; i++) {
            publisher.publish(events.forUser(target)
                    .at(start.plusMillis(i * 250L))
                    .category(EventCategory.AUTHENTICATION)
                    .action(EventAction.USER_LOGIN)
                    .outcome(Outcome.FAILURE)
                    .reason("invalid password")
                    .from(sources.get(i % sources.size()), randomPort(rng))
                    .geo("RU", "Moscow")
                    .userAgent(ATTACK_UA)
                    .labels(labels)
                    .build());
        }

        if (succeedAtEnd) {
            publisher.publish(events.forUser(target)
                    .at(now)
                    .category(EventCategory.AUTHENTICATION)
                    .action(EventAction.USER_LOGIN)
                    .outcome(Outcome.SUCCESS)
                    .from(sources.get(0), randomPort(rng))
                    .geo("RU", "Moscow")
                    .userAgent(ATTACK_UA)
                    .labels(labels)
                    .build());
        }

        int total = attempts + (succeedAtEnd ? 1 : 0);
        return finish("brute_force", runId, List.of(target.id()), total, sources);
    }

    /**
     * One password tried against many accounts from the same infrastructure. Inverted signal:
     * failures per source IP across distinct users. MITRE ATT&CK T1110.004.
     */
    public ScenarioResult credentialStuffing(int targetUsers, int sourceCount) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        String runId = nextRunId("cs");
        List<String> sources = hostileIps(Math.max(1, sourceCount), rng);
        Map<String, String> labels = labels("credential_stuffing", runId, "T1110.004");

        Instant start = Instant.now().minusMillis(targetUsers * 120L);
        List<String> touched = new ArrayList<>();

        for (int i = 0; i < targetUsers; i++) {
            SimulatedUser victim = users.uniformRandom(rng);
            touched.add(victim.id());
            publisher.publish(events.forUser(victim)
                    .at(start.plusMillis(i * 120L))
                    .category(EventCategory.AUTHENTICATION)
                    .action(EventAction.USER_LOGIN)
                    // A few stuffed credentials actually work. That is the point of the attack.
                    .outcome(rng.nextDouble() < 0.03 ? Outcome.SUCCESS : Outcome.FAILURE)
                    .reason("invalid password")
                    .from(sources.get(i % sources.size()), randomPort(rng))
                    .geo("NL", "Amsterdam")
                    .userAgent(ATTACK_UA)
                    .labels(labels)
                    .build());
        }

        return finish("credential_stuffing", runId, touched, targetUsers, sources);
    }

    /**
     * Password spraying: one common password, many accounts, deliberately slow and spread across
     * many source IPs so that no single account and no single IP crosses a naive threshold.
     * MITRE ATT&CK T1110.003.
     *
     * <p>This is the scenario that exposes threshold-only detection. A rule counting failures per
     * user will never fire — two failures per account is indistinguishable from a bad morning.
     * Catching it needs an aggregate view: total failure rate across the estate, or distinct
     * accounts touched per source over a long window.
     */
    public ScenarioResult passwordSpray(int targetUsers, int attemptsPerUser, int sourceCount,
                                        int spreadMinutes) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        String runId = nextRunId("ps");
        List<String> sources = hostileIps(Math.max(1, sourceCount), rng);
        Map<String, String> labels = labels("password_spray", runId, "T1110.003");

        long spreadMs = Math.max(1, spreadMinutes) * 60_000L;
        int total = targetUsers * attemptsPerUser;
        Instant start = Instant.now().minusMillis(spreadMs);
        List<String> touched = new ArrayList<>();
        int emitted = 0;

        for (int i = 0; i < targetUsers; i++) {
            SimulatedUser victim = users.uniformRandom(rng);
            touched.add(victim.id());
            for (int attempt = 0; attempt < attemptsPerUser; attempt++) {
                publisher.publish(events.forUser(victim)
                        .at(start.plusMillis((long) (spreadMs * ((double) emitted / total))))
                        .category(EventCategory.AUTHENTICATION)
                        .action(EventAction.USER_LOGIN)
                        .outcome(Outcome.FAILURE)
                        .reason("invalid password")
                        .from(sources.get(rng.nextInt(sources.size())), randomPort(rng))
                        .geo("US", "Ashburn")
                        .userAgent(HEADLESS_UA)
                        .labels(labels)
                        .build());
                emitted++;
            }
        }

        return finish("password_spray", runId, touched, emitted, sources);
    }

    // ------------------------------------------------------------------
    // Account takeover
    // ------------------------------------------------------------------

    /**
     * A successful login from the user's normal location, then another from far away moments
     * later. No single event is suspicious; only the pair is. MITRE ATT&CK T1078.
     */
    public ScenarioResult impossibleTravel(String userId, int minutesApart) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        SimulatedUser target = resolveTarget(userId, rng);
        String runId = nextRunId("it");
        Map<String, String> labels = labels("impossible_travel", runId, "T1078");

        Instant second = Instant.now();
        Instant first = second.minusSeconds(Math.max(1, minutesApart) * 60L);

        publisher.publish(events.forUser(target)
                .at(first)
                .category(EventCategory.AUTHENTICATION)
                .action(EventAction.USER_LOGIN)
                .outcome(Outcome.SUCCESS)
                .from(target.randomHomeIp(rng), randomPort(rng))
                .labels(labels)
                .build());

        String hostileIp = hostileIps(1, rng).get(0);
        publisher.publish(events.forUser(target)
                .at(second)
                .category(EventCategory.AUTHENTICATION)
                .action(EventAction.USER_LOGIN)
                .outcome(Outcome.SUCCESS)
                .from(hostileIp, randomPort(rng))
                .geo("SG", "Singapore")
                .userAgent(ATTACK_UA)
                .labels(labels)
                .build());

        return finish("impossible_travel", runId, List.of(target.id()), 2, List.of(hostileIp));
    }

    /**
     * A stolen session token used from somewhere else. No failed logins at all — the attacker
     * never touches the login endpoint, so every credential-based detection is blind to this.
     * The signal is a live session changing its source IP and user agent mid-flight.
     * MITRE ATT&CK T1539.
     */
    public ScenarioResult sessionHijack(String userId, int apiCalls) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        SimulatedUser target = resolveTarget(userId, rng);
        String runId = nextRunId("sh");
        Map<String, String> labels = labels("session_hijack", runId, "T1539");
        String hostileIp = hostileIps(1, rng).get(0);

        Instant start = Instant.now().minusSeconds(apiCalls * 3L + 30);

        // The legitimate session begins, from the user's real machine.
        publisher.publish(events.forUser(target)
                .at(start)
                .category(EventCategory.AUTHENTICATION)
                .action(EventAction.TOKEN_ISSUED)
                .outcome(Outcome.SUCCESS)
                .from(target.randomHomeIp(rng), randomPort(rng))
                .labels(labels)
                .build());

        // The same session, now driven from somewhere else entirely.
        for (int i = 0; i < apiCalls; i++) {
            publisher.publish(events.forUser(target)
                    .at(start.plusSeconds(30 + i * 3L))
                    .category(EventCategory.API)
                    .action(EventAction.PERMISSION_CHECK)
                    .outcome(rng.nextDouble() < 0.25 ? Outcome.FAILURE : Outcome.SUCCESS)
                    .reason("probing scopes")
                    .from(hostileIp, randomPort(rng))
                    .geo("BR", "Sao Paulo")
                    .userAgent(ATTACK_UA)
                    .labels(labels)
                    .build());
        }

        return finish("session_hijack", runId, List.of(target.id()), apiCalls + 1, List.of(hostileIp));
    }

    /**
     * An account that has been silent for a long time suddenly active again. Weak on its own,
     * valuable as a risk-score contributor. MITRE ATT&CK T1078.
     *
     * <p>The dormancy here is asserted via a label rather than produced by genuinely holding an
     * account silent for 90 days — a compromise the baseline job (Week 7) papers over by
     * computing real last-seen times from the stored history.
     */
    public ScenarioResult dormantReactivation(String userId) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        SimulatedUser target = resolveTarget(userId, rng);
        String runId = nextRunId("dr");
        Map<String, String> labels = Map.of(
                "scenario", "dormant_reactivation", "run_id", runId,
                "attack_technique", "T1078", "dormant_days", "94");
        String hostileIp = hostileIps(1, rng).get(0);
        Instant now = Instant.now();

        publisher.publish(events.forUser(target)
                .at(now.minusSeconds(20))
                .category(EventCategory.AUTHENTICATION)
                .action(EventAction.USER_LOGIN)
                .outcome(Outcome.SUCCESS)
                .from(hostileIp, randomPort(rng))
                .geo("TR", "Istanbul")
                .userAgent(HEADLESS_UA)
                .labels(labels)
                .build());

        publisher.publish(events.forUser(target)
                .at(now)
                .category(EventCategory.IAM)
                .action(EventAction.PASSWORD_CHANGE)
                .outcome(Outcome.SUCCESS)
                .from(hostileIp, randomPort(rng))
                .geo("TR", "Istanbul")
                .userAgent(HEADLESS_UA)
                .labels(labels)
                .build());

        return finish("dormant_reactivation", runId, List.of(target.id()), 2, List.of(hostileIp));
    }

    // ------------------------------------------------------------------
    // Post-compromise
    // ------------------------------------------------------------------

    /**
     * An authenticated attacker probing what they can reach, then granting themselves more.
     * Signal: a burst of authorization denials followed by a successful role change.
     * MITRE ATT&CK T1068.
     */
    public ScenarioResult privilegeEscalation(String userId, int probes, boolean succeed) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        SimulatedUser target = resolveTarget(userId, rng);
        String runId = nextRunId("pe");
        Map<String, String> labels = labels("privilege_escalation", runId, "T1068");
        String hostileIp = hostileIps(1, rng).get(0);

        String[] scopes = {"admin:write", "payments:refund", "users:delete", "keys:create",
                "audit:read", "billing:admin"};

        Instant now = Instant.now();
        Instant start = now.minusMillis(probes * 400L);

        for (int i = 0; i < probes; i++) {
            publisher.publish(events.forUser(target)
                    .at(start.plusMillis(i * 400L))
                    .category(EventCategory.API)
                    .action(EventAction.PERMISSION_CHECK)
                    .outcome(Outcome.FAILURE)
                    .reason("missing scope " + scopes[i % scopes.length])
                    .from(hostileIp, randomPort(rng))
                    .geo("SG", "Singapore")
                    .userAgent(ATTACK_UA)
                    .labels(labels)
                    .build());
        }

        if (succeed) {
            publisher.publish(events.forUser(target)
                    .at(now)
                    .category(EventCategory.IAM)
                    .action(EventAction.ROLE_CHANGE)
                    .outcome(Outcome.SUCCESS)
                    .reason("granted role platform-admin")
                    .from(hostileIp, randomPort(rng))
                    .geo("SG", "Singapore")
                    .userAgent(ATTACK_UA)
                    .labels(labels)
                    .build());
        }

        int total = probes + (succeed ? 1 : 0);
        return finish("privilege_escalation", runId, List.of(target.id()), total, List.of(hostileIp));
    }

    /**
     * A leaked long-lived API key being exercised hard from unfamiliar infrastructure.
     * No interactive login is involved at all. MITRE ATT&CK T1552.001.
     */
    public ScenarioResult apiKeyAbuse(String userId, int calls) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        SimulatedUser target = resolveTarget(userId, rng);
        String runId = nextRunId("ak");
        Map<String, String> labels = labels("api_key_abuse", runId, "T1552.001");
        String hostileIp = hostileIps(1, rng).get(0);

        Instant start = Instant.now().minusMillis(calls * 150L);
        for (int i = 0; i < calls; i++) {
            publisher.publish(events.forUser(target)
                    .at(start.plusMillis(i * 150L))
                    .category(EventCategory.API)
                    .action(EventAction.API_KEY_USED)
                    .outcome(Outcome.SUCCESS)
                    .from(hostileIp, randomPort(rng))
                    .geo("US", "Ashburn")
                    .userAgent("Go-http-client/2.0")
                    .labels(labels)
                    .build());
        }

        return finish("api_key_abuse", runId, List.of(target.id()), calls, List.of(hostileIp));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** The scenarios the continuous adversary is allowed to pick from. */
    public ScenarioResult runNamed(String scenario, ThreadLocalRandom rng) {
        return switch (scenario) {
            case "brute_force" -> bruteForce(null, 12 + rng.nextInt(25), 1 + rng.nextInt(3),
                    rng.nextDouble() < 0.25);
            case "credential_stuffing" -> credentialStuffing(60 + rng.nextInt(120), 2 + rng.nextInt(3));
            case "password_spray" -> passwordSpray(40 + rng.nextInt(60), 2, 4 + rng.nextInt(4),
                    10 + rng.nextInt(20));
            case "impossible_travel" -> impossibleTravel(null, 2 + rng.nextInt(10));
            case "session_hijack" -> sessionHijack(null, 10 + rng.nextInt(20));
            case "dormant_reactivation" -> dormantReactivation(null);
            case "privilege_escalation" -> privilegeEscalation(null, 8 + rng.nextInt(15),
                    rng.nextDouble() < 0.4);
            case "api_key_abuse" -> apiKeyAbuse(null, 30 + rng.nextInt(60));
            default -> throw new IllegalArgumentException("Unknown scenario: " + scenario);
        };
    }

    public static final List<String> SCENARIOS = List.of(
            "brute_force", "credential_stuffing", "password_spray", "impossible_travel",
            "session_hijack", "dormant_reactivation", "privilege_escalation", "api_key_abuse");

    private SimulatedUser resolveTarget(String userId, ThreadLocalRandom rng) {
        if (userId == null || userId.isBlank()) {
            return users.uniformRandom(rng);
        }
        return users.byId(userId).orElseThrow(
                () -> new IllegalArgumentException("No simulated user with id " + userId));
    }

    private static Map<String, String> labels(String scenario, String runId, String technique) {
        return Map.of("scenario", scenario, "run_id", runId, "attack_technique", technique);
    }

    private String nextRunId(String prefix) {
        return prefix + "-" + runCounter.incrementAndGet();
    }

    private static int randomPort(ThreadLocalRandom rng) {
        return 1024 + rng.nextInt(64000);
    }

    private static List<String> hostileIps(int count, ThreadLocalRandom rng) {
        List<String> ips = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            ips.add(HOSTILE_PREFIXES[rng.nextInt(HOSTILE_PREFIXES.length)] + "." + (1 + rng.nextInt(254)));
        }
        return List.copyOf(ips);
    }

    private ScenarioResult finish(String scenario, String runId, List<String> targets,
                                  int emitted, List<String> sources) {
        log.info("Scenario {} run={} targets={} events={} sources={}",
                scenario, runId, targets.size(), emitted, sources.size());
        return new ScenarioResult(scenario, runId, List.copyOf(targets), emitted, List.copyOf(sources));
    }

    /** What a triggered scenario did, so you can go look for it in the data. */
    public record ScenarioResult(
            String scenario,
            String runId,
            List<String> targetUserIds,
            int eventsEmitted,
            List<String> sourceIps
    ) {}
}
