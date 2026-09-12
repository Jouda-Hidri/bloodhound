package io.bloodhound.producer.iam;

import io.bloodhound.producer.sim.SimulatedUser;
import io.bloodhound.producer.sim.UserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The account directory of the simulated application — and the thing response automation acts on.
 *
 * <p>This is what makes containment observable rather than theoretical. When the responder
 * disables an account here, the traffic generator starts failing that account's logins with
 * "account disabled", and the effect shows up in the event stream within seconds. Without a real
 * target, "response automation" is just a row written to a table.
 *
 * <p><b>Safety.</b> Every mutation is refused unless the account is part of the simulated
 * population in the {@code bloodhound.lab} domain. There is no code path from an alert to
 * anything outside this JVM.
 */
@Service
public class LabIamService {

    private static final Logger log = LoggerFactory.getLogger(LabIamService.class);

    /** The only domain this service will ever act on. */
    public static final String LAB_DOMAIN = "bloodhound.lab";

    private final UserPool users;
    private final Map<String, AccountState> disabled = new ConcurrentHashMap<>();
    private final Map<String, Instant> revokedSessions = new ConcurrentHashMap<>();
    private final List<IamAction> actionLog = new CopyOnWriteArrayList<>();

    public LabIamService(UserPool users) {
        this.users = users;
    }

    public boolean isDisabled(String userId) {
        return disabled.containsKey(userId);
    }

    /** True if the account's sessions were revoked after the given moment. */
    public boolean sessionsRevokedSince(String userId, Instant since) {
        Instant revoked = revokedSessions.get(userId);
        return revoked != null && revoked.isAfter(since);
    }

    public AccountState disable(String userId, String reason, String actor) {
        SimulatedUser user = requireLabAccount(userId);
        AccountState state = new AccountState(userId, user.name(), Instant.now(), reason, actor);
        disabled.put(userId, state);
        record("disable_account", userId, reason, actor, true, null);
        log.warn("CONTAINMENT account {} disabled by {} — {}", userId, actor, reason);
        return state;
    }

    public boolean enable(String userId, String actor) {
        requireLabAccount(userId);
        boolean wasDisabled = disabled.remove(userId) != null;
        record("enable_account", userId, "re-enabled", actor, wasDisabled, null);
        if (wasDisabled) {
            log.info("Account {} re-enabled by {}", userId, actor);
        }
        return wasDisabled;
    }

    /**
     * Invalidate active sessions without locking the account out.
     *
     * <p>The lighter-touch containment option, and usually the right first move: it evicts an
     * attacker holding a stolen token while leaving the legitimate owner able to log back in.
     * Disabling the account contains the attacker by also denying the victim.
     */
    public void revokeSessions(String userId, String reason, String actor) {
        requireLabAccount(userId);
        revokedSessions.put(userId, Instant.now());
        record("revoke_sessions", userId, reason, actor, true, null);
        log.warn("CONTAINMENT sessions revoked for {} by {} — {}", userId, actor, reason);
    }

    public Collection<AccountState> disabledAccounts() {
        return disabled.values();
    }

    public List<IamAction> actions() {
        return List.copyOf(actionLog);
    }

    private SimulatedUser requireLabAccount(String userId) {
        SimulatedUser user = users.byId(userId).orElseThrow(() -> new IllegalArgumentException(
                "Refusing to act on unknown account '" + userId + "'"));
        if (!LAB_DOMAIN.equals(user.domain())) {
            // Unreachable with the current population, and deliberately kept anyway: this is the
            // check that would matter the day this code ever pointed at a real directory.
            throw new IllegalArgumentException(
                    "Refusing to act on account outside " + LAB_DOMAIN);
        }
        return user;
    }

    private void record(String action, String userId, String reason, String actor,
                        boolean effective, String error) {
        actionLog.add(new IamAction(Instant.now(), action, userId, reason, actor, effective, error));
    }

    /** A disabled account and why. */
    public record AccountState(String userId, String userName, Instant disabledAt,
                               String reason, String disabledBy) {}

    /** Local record of what was done to this directory, mirroring the responder's audit log. */
    public record IamAction(Instant at, String action, String userId, String reason,
                            String actor, boolean effective, String error) {}
}
