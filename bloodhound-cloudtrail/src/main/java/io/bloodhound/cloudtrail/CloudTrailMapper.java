package io.bloodhound.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Maps an AWS CloudTrail record into the platform's ECS event schema.
 *
 * <p>This class is the whole of Week 20's real lesson. Connecting to a log source is a
 * configuration exercise; <em>mapping</em> it is where the engineering is, because every source
 * models identity, outcome and time differently, and each mismatch is a detection that silently
 * stops working.
 *
 * <p>The traps below are real, and each one was worth finding here rather than in production.
 */
@Component
public class CloudTrailMapper {

    private static final Logger log = LoggerFactory.getLogger(CloudTrailMapper.class);

    /**
     * CloudTrail puts a <em>service principal</em> in {@code sourceIPAddress} for AWS-initiated
     * calls — literally the string {@code "cloudtrail.amazonaws.com"} where an address belongs.
     *
     * <p>Left alone, that value reaches a Postgres {@code inet} column and the insert fails, so
     * the whole batch dead-letters. The events are not malformed; AWS is telling the truth in a
     * shape the schema does not model. They are routed to {@code service.name} instead, and the
     * source address is left null.
     */
    private static final Set<String> AWS_SERVICE_SUFFIXES = Set.of(".amazonaws.com", ".aws.internal");

    /**
     * Console sign-ins do not report failure through {@code errorCode}.
     *
     * <p>A failed console login has no error code at all — the result lives in
     * {@code responseElements.ConsoleLogin}, which is the string "Success" or "Failure". A mapper
     * that only checks {@code errorCode} therefore records every failed console login as a
     * success, which is precisely backwards for the one event type most worth alerting on.
     */
    private static final String CONSOLE_LOGIN = "ConsoleLogin";

    public SecurityEvent map(JsonNode record) {
        if (record == null || !record.hasNonNull("eventName")) {
            return null;
        }

        String eventName = record.path("eventName").asText();
        String eventSource = record.path("eventSource").asText("");

        Identity identity = resolveIdentity(record.path("userIdentity"));
        Outcome outcome = resolveOutcome(record, eventName);
        SourceAddress source = resolveSource(record.path("sourceIPAddress").asText(null));

        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("cloud_provider", "aws");
        labels.put("cloud_event_name", eventName);
        labels.put("cloud_event_source", eventSource);
        if (!record.path("awsRegion").asText("").isEmpty()) {
            labels.put("cloud_region", record.path("awsRegion").asText());
        }
        if (!identity.accountId().isEmpty()) {
            labels.put("cloud_account_id", identity.accountId());
        }
        if (identity.assumedRole() != null) {
            labels.put("assumed_role", identity.assumedRole());
        }

        return new SecurityEvent(
                parseTime(record.path("eventTime").asText(null)),
                new SecurityEvent.EventInfo(
                        // CloudTrail's eventID is a UUID and is stable across redelivery — which
                        // matters, because CloudTrail delivery is at-least-once. Using it as the
                        // dedupe key means an S3 object processed twice is absorbed by the
                        // primary key rather than double-counted by a threshold rule.
                        record.path("eventID").asText(null),
                        categoryOf(eventSource, eventName),
                        actionOf(eventName),
                        outcome,
                        reasonOf(record, outcome)),
                new SecurityEvent.UserInfo(identity.id(), identity.name(), identity.domain()),
                new SecurityEvent.SourceInfo(source.ip(), null, null),
                new SecurityEvent.ServiceInfo(
                        source.serviceName() != null ? source.serviceName() : eventSource,
                        record.path("eventVersion").asText(null),
                        "aws"),
                new SecurityEvent.UserAgentInfo(record.path("userAgent").asText(null)),
                labels);
    }

    // ------------------------------------------------------------------
    // Identity
    // ------------------------------------------------------------------

    /**
     * CloudTrail models identity five different ways, and {@code user.id} has to mean the same
     * thing across all of them or every per-user detection quietly splits one actor into several.
     *
     * <ul>
     *   <li>{@code IAMUser} — {@code userName} is present and is what a human recognises.</li>
     *   <li>{@code AssumedRole} — {@code userName} is absent. The useful identity is the role,
     *       under {@code sessionContext.sessionIssuer.userName}. Falling back to
     *       {@code principalId} here would produce a different id for every session of the same
     *       role, and a threshold rule counting per user would never reach it.</li>
     *   <li>{@code Root} — no name at all. Named explicitly, because root usage is the single
     *       highest-signal event in an AWS account.</li>
     *   <li>{@code AWSService} — a service acting on its own; there is no user.</li>
     *   <li>{@code AWSAccount} / federated — cross-account, identified by the ARN.</li>
     * </ul>
     */
    private Identity resolveIdentity(JsonNode userIdentity) {
        String type = userIdentity.path("type").asText("Unknown");
        String accountId = userIdentity.path("accountId").asText("");
        String principalId = userIdentity.path("principalId").asText("");
        String arn = userIdentity.path("arn").asText("");

        return switch (type) {
            case "IAMUser" -> new Identity(
                    userIdentity.path("userName").asText(principalId),
                    userIdentity.path("userName").asText(principalId),
                    "aws:" + accountId, accountId, null);

            case "AssumedRole" -> {
                JsonNode issuer = userIdentity.path("sessionContext").path("sessionIssuer");
                String roleName = issuer.path("userName").asText("");
                if (roleName.isEmpty()) {
                    roleName = lastArnSegment(issuer.path("arn").asText(arn));
                }
                // The session id, kept as a label rather than folded into the identity, so the
                // role is one actor across all its sessions while the session remains visible.
                String session = principalId.contains(":")
                        ? principalId.substring(principalId.indexOf(':') + 1) : null;
                yield new Identity("role:" + roleName, roleName, "aws:" + accountId,
                        accountId, session);
            }

            case "Root" -> new Identity("root:" + accountId, "root", "aws:" + accountId,
                    accountId, null);

            case "AWSService" -> new Identity(
                    "service:" + userIdentity.path("invokedBy").asText("aws"),
                    userIdentity.path("invokedBy").asText("aws"),
                    "aws:service", accountId, null);

            default -> {
                String fallback = !arn.isEmpty() ? arn
                        : (!principalId.isEmpty() ? principalId : "unknown");
                yield new Identity(fallback, lastArnSegment(fallback), "aws:" + accountId,
                        accountId, null);
            }
        };
    }

    private static String lastArnSegment(String arn) {
        if (arn == null || arn.isEmpty()) {
            return "unknown";
        }
        int slash = arn.lastIndexOf('/');
        return slash >= 0 && slash < arn.length() - 1 ? arn.substring(slash + 1) : arn;
    }

    // ------------------------------------------------------------------
    // Outcome
    // ------------------------------------------------------------------

    private Outcome resolveOutcome(JsonNode record, String eventName) {
        if (CONSOLE_LOGIN.equals(eventName)) {
            String result = record.path("responseElements").path("ConsoleLogin").asText("");
            if (!result.isEmpty()) {
                return "Success".equalsIgnoreCase(result) ? Outcome.SUCCESS : Outcome.FAILURE;
            }
        }
        // For every other API call, the presence of errorCode is the signal. An authorization
        // denial (AccessDenied / UnauthorizedOperation) is a failure and, on a cloud account,
        // one of the more interesting things that can happen.
        return record.hasNonNull("errorCode") ? Outcome.FAILURE : Outcome.SUCCESS;
    }

    private String reasonOf(JsonNode record, Outcome outcome) {
        if (outcome != Outcome.FAILURE) {
            return null;
        }
        String code = record.path("errorCode").asText("");
        String message = record.path("errorMessage").asText("");
        if (!code.isEmpty()) {
            return message.isEmpty() ? code : code + ": " + truncate(message);
        }
        return "console login failed";
    }

    // ------------------------------------------------------------------
    // Action and category
    // ------------------------------------------------------------------

    /**
     * Maps a CloudTrail API name onto the platform's action vocabulary.
     *
     * <p>The vocabulary was designed for an application's own auth events, and AWS has thousands
     * of API names. Only the ones that genuinely mean the same thing are mapped; everything else
     * becomes {@link EventAction#UNKNOWN} and keeps its exact API name in
     * {@code labels.cloud_event_name}.
     *
     * <p>The temptation is to force a mapping for everything so that no event looks unhandled.
     * That would be worse: a rule matching {@code permission-check} would start firing on
     * unrelated AWS calls, and nobody would be able to tell which. Unmapped and labelled is
     * honest; mis-mapped is a detection that lies.
     */
    private EventAction actionOf(String eventName) {
        return switch (eventName) {
            case CONSOLE_LOGIN -> EventAction.USER_LOGIN;
            case "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
                 "GetSessionToken", "GetFederationToken" -> EventAction.TOKEN_ISSUED;
            case "CreateAccessKey", "UpdateAccessKey" -> EventAction.API_KEY_USED;
            case "DeleteAccessKey", "DeactivateMFADevice" -> EventAction.TOKEN_REVOKED;
            case "ChangePassword", "UpdateLoginProfile", "CreateLoginProfile"
                    -> EventAction.PASSWORD_CHANGE;
            case "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
                 "AttachGroupPolicy", "CreatePolicyVersion", "AddUserToGroup"
                    -> EventAction.ROLE_CHANGE;
            case "CreateUser", "DeleteUser", "CreateRole", "DeleteRole"
                    -> EventAction.ACCOUNT_LIFECYCLE;
            default -> EventAction.UNKNOWN;
        };
    }

    private EventCategory categoryOf(String eventSource, String eventName) {
        if ("signin.amazonaws.com".equals(eventSource)) {
            return EventCategory.AUTHENTICATION;
        }
        if ("sts.amazonaws.com".equals(eventSource)) {
            return EventCategory.AUTHENTICATION;
        }
        if ("iam.amazonaws.com".equals(eventSource)) {
            return EventCategory.IAM;
        }
        return EventCategory.API;
    }

    // ------------------------------------------------------------------
    // Source address
    // ------------------------------------------------------------------

    private SourceAddress resolveSource(String raw) {
        if (raw == null || raw.isBlank()) {
            return new SourceAddress(null, null);
        }
        String value = raw.trim();
        for (String suffix : AWS_SERVICE_SUFFIXES) {
            if (value.endsWith(suffix)) {
                return new SourceAddress(null, value);
            }
        }
        // Anything else that is plainly not an address is also kept out of the ip field rather
        // than failing the insert downstream.
        if (!value.matches("[0-9a-fA-F:.]+")) {
            log.debug("Non-address sourceIPAddress '{}', keeping as service name", value);
            return new SourceAddress(null, value);
        }
        return new SourceAddress(value, null);
    }

    private static Instant parseTime(String eventTime) {
        if (eventTime == null) {
            return Instant.now();
        }
        try {
            // CloudTrail emits ISO-8601 with a Z suffix. Always UTC, which is one fewer thing
            // to get wrong than a source reporting local time.
            return Instant.parse(eventTime);
        } catch (DateTimeParseException e) {
            log.warn("Unparseable eventTime '{}', falling back to now", eventTime);
            return Instant.now();
        }
    }

    private static String truncate(String value) {
        return value.length() <= 200 ? value : value.substring(0, 200) + "…";
    }

    private record Identity(String id, String name, String domain, String accountId,
                            String assumedRole) {}

    private record SourceAddress(String ip, String serviceName) {}
}
