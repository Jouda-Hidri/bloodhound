package io.bloodhound.producer.sim;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * An adversary that keeps working while you are not watching.
 *
 * <p>Firing scenarios by hand proves a detection can fire. It does not tell you what the platform
 * looks like after eight hours of mixed attack and normal traffic — which alerts drown the
 * others, which rules fire constantly, whether risk scores saturate. That only shows up when
 * attacks arrive unpredictably and overlap.
 *
 * <p>Intensity is a probability per tick rather than a fixed rate, so gaps between attacks vary.
 * Evenly-spaced attacks are easy to detect for reasons that have nothing to do with the attacks.
 */
@Component
public class ContinuousAdversary {

    private static final Logger log = LoggerFactory.getLogger(ContinuousAdversary.class);

    /** Keep a bounded history so the endpoint can show recent activity without growing forever. */
    private static final int HISTORY_LIMIT = 200;

    private final SimulationProperties props;
    private final AttackSimulator attacks;
    private final List<AdversaryRun> history = new CopyOnWriteArrayList<>();
    private final AtomicLong firedCount = new AtomicLong();

    public ContinuousAdversary(SimulationProperties props, AttackSimulator attacks) {
        this.props = props;
        this.attacks = attacks;
    }

    @Scheduled(fixedRateString = "${bloodhound.sim.adversary.tick-millis:20000}")
    public void tick() {
        if (!props.getAdversary().isEnabled()) {
            return;
        }
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        if (rng.nextDouble() >= props.getAdversary().getIntensity()) {
            return;
        }

        List<String> pool = enabledScenarios();
        if (pool.isEmpty()) {
            return;
        }
        String scenario = pool.get(rng.nextInt(pool.size()));

        try {
            AttackSimulator.ScenarioResult result = attacks.runNamed(scenario, rng);
            firedCount.incrementAndGet();
            remember(new AdversaryRun(Instant.now(), result.scenario(), result.runId(),
                    result.eventsEmitted(), null));
        } catch (RuntimeException e) {
            // A failing scenario must not kill the scheduler thread and silently stop the
            // adversary — that would look exactly like "the attacks stopped".
            log.warn("Adversary scenario {} failed: {}", scenario, e.toString());
            remember(new AdversaryRun(Instant.now(), scenario, null, 0, e.toString()));
        }
    }

    private List<String> enabledScenarios() {
        List<String> configured = props.getAdversary().getScenarios();
        if (configured == null || configured.isEmpty()) {
            return AttackSimulator.SCENARIOS;
        }
        List<String> valid = new ArrayList<>();
        for (String scenario : configured) {
            if (AttackSimulator.SCENARIOS.contains(scenario)) {
                valid.add(scenario);
            } else {
                log.warn("Ignoring unknown adversary scenario '{}'", scenario);
            }
        }
        return valid;
    }

    private void remember(AdversaryRun run) {
        history.add(run);
        while (history.size() > HISTORY_LIMIT) {
            history.remove(0);
        }
    }

    public long firedCount() {
        return firedCount.get();
    }

    public List<AdversaryRun> recent(int limit) {
        int from = Math.max(0, history.size() - Math.max(1, limit));
        return List.copyOf(history.subList(from, history.size()));
    }

    public record AdversaryRun(Instant at, String scenario, String runId, int events, String error) {}
}
