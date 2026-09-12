package io.bloodhound.common;

/** Kafka topic names, shared so a rename is a compile error rather than a silent no-op. */
public final class Topics {

    /** Raw security events as emitted by applications. Keyed by {@code user.id}. */
    public static final String RAW_EVENTS = "security.events.raw";

    /** Events the consumer could not parse or persist, with the failure reason attached. */
    public static final String RAW_EVENTS_DLQ = "security.events.raw.dlq";

    /** Detections fired by the rule engine. Keyed by the entity the alert is about. */
    public static final String ALERTS = "security.alerts";

    /** Alerts the responder could not process. */
    public static final String ALERTS_DLQ = "security.alerts.dlq";

    private Topics() {
    }
}
