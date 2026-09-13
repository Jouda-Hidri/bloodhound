package io.bloodhound.detector.streams;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.detector.config.DetectorProperties;
import org.apache.kafka.streams.processor.PunctuationType;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.ProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.KeyValueStore;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Detects a live session being used from somewhere it was not established.
 *
 * <p><b>This closes a gap the scoring job had been reporting honestly for weeks.</b> Every
 * credential-focused rule was blind to session hijack, because the attack never touches the login
 * endpoint: the attacker starts with a stolen token. No failed logins, no new authentication, no
 * threshold to cross. `make score` reported 50% recall for the scenario and named it.
 *
 * <p>The signal is a <em>sequence</em>, not a count. A session is established from one place, and
 * subsequently used from another, with no intervening authentication. That is not expressible in
 * the YAML rule format — which asks "how many things happened in a window" — and bending the DSL
 * to cover it would have meant inventing a sequence language. Thirty lines of processor was the
 * smaller cost. Same boundary as the impossible-travel processor, for the same reason.
 *
 * <p><b>Why it is not just impossible travel.</b> Impossible travel compares two logins and needs
 * a country change. This compares a token issuance against later API activity, catches a move
 * within one country, and fires on a session that never re-authenticated at all.
 */
public class SessionHijackProcessor
        implements Processor<String, SecurityEvent, String, Alert> {

    public static final String STORE_NAME = "active-sessions";
    public static final String RULE_ID = "session-hijack";

    private final Duration sessionTtl;
    private final Duration graceAfterIssue;

    private ProcessorContext<String, Alert> context;
    private KeyValueStore<String, SessionFingerprint> sessions;

    public SessionHijackProcessor(DetectorProperties.SessionHijack config) {
        this.sessionTtl = config.getSessionTtl();
        this.graceAfterIssue = config.getGraceAfterIssue();
    }

    @Override
    public void init(ProcessorContext<String, Alert> context) {
        this.context = context;
        this.sessions = context.getStateStore(STORE_NAME);

        // A KeyValueStore has no retention of its own, so without this sweep it grows by one
        // entry per account that has ever authenticated and never shrinks.
        context.schedule(Duration.ofMinutes(30), PunctuationType.WALL_CLOCK_TIME, this::evict);
    }

    @Override
    public void process(Record<String, SecurityEvent> record) {
        SecurityEvent event = record.value();
        String userId = record.key();
        if (event == null || userId == null || event.event() == null
                || event.event().action() == null || event.timestamp() == null) {
            return;
        }

        String action = event.event().action().value();
        boolean succeeded = event.event().outcome() != null
                && "success".equals(event.event().outcome().value());

        String ip = event.source() != null ? event.source().ip() : null;
        String agent = event.userAgent() != null ? event.userAgent().original() : null;

        boolean isAuthentication = "token-issued".equals(action) || "user-login".equals(action);

        // Establishing or re-establishing a session resets the fingerprint. This is what stops
        // an ordinary "user moved to their phone and logged in again" from ever firing: the new
        // authentication legitimises the new address.
        if (isAuthentication) {
            if (succeeded) {
                sessions.put(userId, new SessionFingerprint(ip, agent, event.timestamp()));
            }
            // A *failed* login is not a session being used — it is somebody trying to create
            // one, which the brute-force and credential-stuffing rules already cover.
            //
            // Falling through to the session-use branch here was a real bug, and a costly one:
            // a credential-stuffing run against 150 accounts produced a session-hijack alert for
            // every victim who happened to have a live session, because the attacker's address
            // differed from where that session was established. 52 alerts from one attack, all
            // describing an attack that a different rule had already reported correctly.
            //
            // The general shape is worth remembering: *one attack manufacturing false positives
            // in an unrelated rule* is the same failure the impossible-travel rule has with
            // credential stuffing, and it is invisible unless scenarios are run together.
            return;
        }

        // Anything else genuinely requires an existing session: an API call, a scope check,
        // a credential change.
        SessionFingerprint session = sessions.get(userId);
        if (session == null || ip == null) {
            return;
        }

        Duration age = Duration.between(session.establishedAt(), event.timestamp());
        if (age.isNegative() || age.compareTo(sessionTtl) > 0) {
            // Older than a session could plausibly live: not evidence, just stale state.
            return;
        }
        if (age.compareTo(graceAfterIssue) < 0) {
            // Immediately after issuance a client can legitimately appear to shift — a proxy
            // hop, an IPv4/IPv6 switch, a mobile network handover. Without this grace the rule
            // fires on ordinary clients constantly.
            return;
        }

        boolean agentChanged = agent != null && session.userAgent() != null
                && !agent.equals(session.userAgent());

        // Tuned against measurement, not taste.
        //
        // The first version fired on any address change at all, and produced 130 alerts of which
        // 126 (97%) were a user moving between two addresses in their own /24 — a phone dropping
        // to wifi, a DHCP lease, a second NIC. Precision about 3%, which is a rule nobody would
        // keep switched on for a week.
        //
        // Requiring the *network* to change, rather than the address, removes all 126 without
        // touching any of the 4 real hijacks: an attacker with a stolen token is not on the
        // victim's subnet. That is the whole tuning, and it is one comparison.
        if (!networkChanged(session.ip(), ip)) {
            return;
        }

        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("session_established_ip", String.valueOf(session.ip()));
        evidence.put("session_established_at", session.establishedAt().toString());
        evidence.put("observed_ip", ip);
        evidence.put("seconds_into_session", String.valueOf(age.toSeconds()));
        evidence.put("action", action);
        if (agentChanged) {
            evidence.put("session_established_user_agent", session.userAgent());
            evidence.put("observed_user_agent", agent);
        }

        boolean crossedNetworkClass = isPrivate(session.ip()) != isPrivate(ip);
        if (crossedNetworkClass) {
            evidence.put("network_class_change",
                    isPrivate(session.ip()) ? "internal_to_external" : "external_to_internal");
        }

        // Network *and* client changing together is far stronger than either alone: a roaming
        // user keeps their browser, and a browser upgrade keeps its network. A session that
        // moves from inside the estate to outside it is the same kind of double signal.
        Severity severity = (agentChanged || crossedNetworkClass) ? Severity.HIGH : Severity.MEDIUM;

        context.forward(record.withValue(new Alert(
                UUID.randomUUID().toString(),
                Instant.now(),
                session.establishedAt(),
                event.timestamp(),
                RULE_ID,
                agentChanged
                        ? "Session used from a new address and a new client"
                        : "Session used from a new address",
                severity,
                "T1539",
                EntityType.USER,
                userId,
                age.toSeconds(),
                graceAfterIssue.toSeconds(),
                evidence,
                List.of(event.event().id()))));
    }

    /**
     * Did the session move to a different network, as opposed to a different address?
     *
     * <p>A /24 is a crude proxy for "the same place" — it is not what a routing table thinks, and
     * two addresses in one /24 can belong to different organisations. It is nonetheless the right
     * granularity here: it captures the DHCP and multi-homing noise that dominates ordinary
     * traffic, without needing an ASN lookup or a list of corporate ranges.
     *
     * <p>The better version enriches each event with its ASN at ingest and compares that, which
     * is the same lesson as the wildcard-policy gap in ADR 0008: <b>enrichment at ingest beats
     * cleverness in the rule.</b> Noted, not built.
     */
    private static boolean networkChanged(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return !prefix24(a).equals(prefix24(b));
    }

    private static String prefix24(String ip) {
        int last = ip.lastIndexOf('.');
        // IPv6, or anything else without dotted quads: compare whole. Conservative — it means
        // an IPv6 session move always counts as a network change.
        return last < 0 ? ip : ip.substring(0, last);
    }

    /** RFC 1918 space. Crossing between private and public is a stronger signal than either. */
    private static boolean isPrivate(String ip) {
        if (ip == null) {
            return false;
        }
        return ip.startsWith("10.") || ip.startsWith("192.168.")
                || ip.matches("^172\\.(1[6-9]|2[0-9]|3[01])\\..*");
    }

    private void evict(long wallClockMillis) {
        Instant cutoff = Instant.ofEpochMilli(wallClockMillis).minus(sessionTtl);
        try (var iterator = sessions.all()) {
            while (iterator.hasNext()) {
                var entry = iterator.next();
                if (entry.value != null && entry.value.establishedAt().isBefore(cutoff)) {
                    sessions.delete(entry.key);
                }
            }
        }
    }

    /** Where and with what a session was established. */
    public record SessionFingerprint(
            @JsonProperty("ip") String ip,
            @JsonProperty("user_agent") String userAgent,
            @JsonProperty("established_at") Instant establishedAt
    ) {}
}
