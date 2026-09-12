package io.bloodhound.common.event;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * ECS {@code event.action} — the specific thing that happened.
 *
 * <p>ECS treats this as free text, but constraining it to an enum keeps detection rules
 * honest: a typo in a rule fails at parse time rather than silently matching nothing.
 * Unknown values arriving from outside our own services map to {@link #UNKNOWN} rather
 * than blowing up the consumer.
 */
public enum EventAction {

    /** Credentials presented at the login endpoint. Pair with {@link Outcome}. */
    USER_LOGIN("user-login"),
    /** Session ended by the user. */
    USER_LOGOUT("user-logout"),
    /** Second factor requested or answered. */
    MFA_CHALLENGE("mfa-challenge"),
    /** Access or refresh token minted. */
    TOKEN_ISSUED("token-issued"),
    /** Token explicitly invalidated. */
    TOKEN_REVOKED("token-revoked"),
    /** An authorization decision was made on a resource. */
    PERMISSION_CHECK("permission-check"),
    /** Credential material changed. */
    PASSWORD_CHANGE("password-change"),
    /** Roles or entitlements changed. */
    ROLE_CHANGE("role-change"),
    /** Account created, disabled, or deleted. */
    ACCOUNT_LIFECYCLE("account-lifecycle"),
    /** A long-lived API credential was used. */
    API_KEY_USED("api-key-used"),

    UNKNOWN("unknown");

    private final String value;

    EventAction(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static EventAction from(String raw) {
        if (raw == null) {
            return UNKNOWN;
        }
        for (EventAction action : values()) {
            if (action.value.equalsIgnoreCase(raw)) {
                return action;
            }
        }
        return UNKNOWN;
    }
}
