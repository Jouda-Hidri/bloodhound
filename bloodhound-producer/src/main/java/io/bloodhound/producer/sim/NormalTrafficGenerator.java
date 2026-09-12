package io.bloodhound.producer.sim;

import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.producer.iam.LabIamService;
import io.bloodhound.producer.kafka.EventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Background "business as usual" traffic.
 *
 * <p>This is the noise floor. Without it a brute-force detection trivially scores 100% precision,
 * which teaches nothing — the hard part of detection engineering is separating an attack from a
 * busy Monday morning.
 */
@Component
public class NormalTrafficGenerator {

    private static final String[] FAILURE_REASONS = {
            "invalid password", "expired password", "mfa timeout", "account locked"
    };

    private static final int TICKS_PER_SECOND = 10;

    private final SimulationProperties props;
    private final UserPool users;
    private final EventFactory events;
    private final EventPublisher publisher;
    private final LabIamService iam;

    public NormalTrafficGenerator(SimulationProperties props, UserPool users, EventFactory events,
                                  EventPublisher publisher, LabIamService iam) {
        this.props = props;
        this.users = users;
        this.events = events;
        this.publisher = publisher;
        this.iam = iam;
    }

    @Scheduled(fixedRate = 1000L / TICKS_PER_SECOND)
    public void tick() {
        if (!props.isEnabled()) {
            return;
        }
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        int perTick = props.getEventsPerSecond() / TICKS_PER_SECOND;
        // Carry the remainder probabilistically so a rate of 25/s does not silently become 20/s.
        int remainder = props.getEventsPerSecond() % TICKS_PER_SECOND;
        int count = perTick + (rng.nextInt(TICKS_PER_SECOND) < remainder ? 1 : 0);

        for (int i = 0; i < count; i++) {
            publisher.publish(nextEvent(rng));
        }
    }

    private SecurityEvent nextEvent(ThreadLocalRandom rng) {
        SimulatedUser user = users.weightedRandom(rng);
        Instant now = Instant.now();
        String ip = user.randomHomeIp(rng);
        int port = 1024 + rng.nextInt(64000);

        // A contained account keeps trying and keeps failing. This is what makes response
        // automation visible in the data: disable an account and its stream changes within
        // seconds, with a reason a detection can distinguish from a real password failure.
        if (iam.isDisabled(user.id())) {
            return events.forUser(user)
                    .at(now)
                    .category(EventCategory.AUTHENTICATION)
                    .action(EventAction.USER_LOGIN)
                    .outcome(Outcome.FAILURE)
                    .reason("account disabled")
                    .from(ip, port)
                    .build();
        }

        double roll = rng.nextDouble();
        if (roll < 0.55) {
            boolean failed = rng.nextDouble() < props.getBaselineFailureRate();
            return events.forUser(user)
                    .at(now)
                    .category(EventCategory.AUTHENTICATION)
                    .action(EventAction.USER_LOGIN)
                    .outcome(failed ? Outcome.FAILURE : Outcome.SUCCESS)
                    .reason(failed ? FAILURE_REASONS[rng.nextInt(FAILURE_REASONS.length)] : null)
                    .from(ip, port)
                    .build();
        }
        if (roll < 0.70) {
            return events.forUser(user)
                    .at(now)
                    .category(EventCategory.AUTHENTICATION)
                    .action(EventAction.TOKEN_ISSUED)
                    .outcome(Outcome.SUCCESS)
                    .from(ip, port)
                    .build();
        }
        if (roll < 0.90) {
            boolean denied = rng.nextDouble() < 0.04;
            return events.forUser(user)
                    .at(now)
                    .category(EventCategory.API)
                    .action(EventAction.PERMISSION_CHECK)
                    .outcome(denied ? Outcome.FAILURE : Outcome.SUCCESS)
                    .reason(denied ? "missing scope payments:write" : null)
                    .from(ip, port)
                    .build();
        }
        if (roll < 0.97) {
            return events.forUser(user)
                    .at(now)
                    .category(EventCategory.SESSION)
                    .action(EventAction.USER_LOGOUT)
                    .outcome(Outcome.SUCCESS)
                    .from(ip, port)
                    .build();
        }
        return events.forUser(user)
                .at(now)
                .category(EventCategory.IAM)
                .action(EventAction.PASSWORD_CHANGE)
                .outcome(Outcome.SUCCESS)
                .from(ip, port)
                .build();
    }
}
