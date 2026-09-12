package io.bloodhound.common.alert;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Alert severity, with the risk weight each level contributes to an entity's score.
 *
 * <p>The weights are deliberately non-linear. Ten low-severity alerts should not add up to the
 * same score as one critical: "lots of small things" and "one very bad thing" are different
 * situations, and a linear scale conflates them.
 */
public enum Severity {

    INFO("info", 1),
    LOW("low", 5),
    MEDIUM("medium", 15),
    HIGH("high", 40),
    CRITICAL("critical", 100);

    private final String value;
    private final int riskWeight;

    Severity(String value, int riskWeight) {
        this.value = value;
        this.riskWeight = riskWeight;
    }

    @JsonValue
    public String value() {
        return value;
    }

    public int riskWeight() {
        return riskWeight;
    }

    @JsonCreator
    public static Severity from(String raw) {
        if (raw == null) {
            return INFO;
        }
        for (Severity severity : values()) {
            if (severity.value.equalsIgnoreCase(raw)) {
                return severity;
            }
        }
        return INFO;
    }

    public boolean atLeast(Severity other) {
        return ordinal() >= other.ordinal();
    }
}
