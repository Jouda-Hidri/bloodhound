package io.bloodhound.common.event;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** ECS {@code event.outcome}. ECS defines exactly these three values. */
public enum Outcome {

    SUCCESS("success"),
    FAILURE("failure"),
    UNKNOWN("unknown");

    private final String value;

    Outcome(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static Outcome from(String raw) {
        if (raw == null) {
            return UNKNOWN;
        }
        for (Outcome outcome : values()) {
            if (outcome.value.equalsIgnoreCase(raw)) {
                return outcome;
            }
        }
        return UNKNOWN;
    }
}
