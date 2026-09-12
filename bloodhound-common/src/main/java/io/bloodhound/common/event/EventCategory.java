package io.bloodhound.common.event;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * ECS {@code event.category} — the coarse bucket an event falls into.
 * Detection rules usually filter on category first, then action.
 */
public enum EventCategory {

    AUTHENTICATION("authentication"),
    IAM("iam"),
    SESSION("session"),
    API("api"),
    UNKNOWN("unknown");

    private final String value;

    EventCategory(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static EventCategory from(String raw) {
        if (raw == null) {
            return UNKNOWN;
        }
        for (EventCategory category : values()) {
            if (category.value.equalsIgnoreCase(raw)) {
                return category;
            }
        }
        return UNKNOWN;
    }
}
