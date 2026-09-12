package io.bloodhound.common.alert;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * What an alert is *about*.
 *
 * <p>This matters more than it looks. A brute-force alert is about an account under attack;
 * a credential-stuffing alert is about hostile infrastructure. Responding to them identically —
 * say, by locking something — would mean locking the victim in one case and the attacker in the
 * other. Risk therefore accumulates per entity, not globally.
 */
public enum EntityType {

    USER("user"),
    SOURCE_IP("source_ip");

    private final String value;

    EntityType(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static EntityType from(String raw) {
        for (EntityType type : values()) {
            if (type.value.equalsIgnoreCase(raw)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown entity type: " + raw);
    }
}
