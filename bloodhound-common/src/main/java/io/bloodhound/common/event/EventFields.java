package io.bloodhound.common.event;

import java.util.Set;

/**
 * Reads a {@link SecurityEvent} field by its ECS dotted path, e.g. {@code "source.geo.country_iso_code"}.
 *
 * <p>This is what lets detection rules be written as data. A YAML rule says
 * {@code group_by: user.id} and the engine resolves it here.
 *
 * <p>Deliberately a switch rather than reflection or a JSON round-trip. Reflection is slower and
 * silently accepts paths that do not exist; this version rejects an unknown path loudly, at rule
 * load time, so a typo in a rule fails on startup instead of producing a rule that matches
 * nothing forever.
 */
public final class EventFields {

    /** Every path a rule is allowed to reference. */
    public static final Set<String> SUPPORTED = Set.of(
            "event.category", "event.action", "event.outcome", "event.reason",
            "user.id", "user.name", "user.domain",
            "source.ip", "source.geo.country_iso_code", "source.geo.city_name",
            "service.name", "service.environment",
            "user_agent.original");

    private EventFields() {
    }

    public static boolean isSupported(String path) {
        return SUPPORTED.contains(path);
    }

    /** @return the field value, or null if the event does not carry it. */
    public static String get(SecurityEvent e, String path) {
        if (e == null) {
            return null;
        }
        return switch (path) {
            case "event.category" -> e.event() == null || e.event().category() == null
                    ? null : e.event().category().value();
            case "event.action" -> e.event() == null || e.event().action() == null
                    ? null : e.event().action().value();
            case "event.outcome" -> e.event() == null || e.event().outcome() == null
                    ? null : e.event().outcome().value();
            case "event.reason" -> e.event() == null ? null : e.event().reason();

            case "user.id" -> e.user() == null ? null : e.user().id();
            case "user.name" -> e.user() == null ? null : e.user().name();
            case "user.domain" -> e.user() == null ? null : e.user().domain();

            case "source.ip" -> e.source() == null ? null : e.source().ip();
            case "source.geo.country_iso_code" -> e.source() == null || e.source().geo() == null
                    ? null : e.source().geo().countryIsoCode();
            case "source.geo.city_name" -> e.source() == null || e.source().geo() == null
                    ? null : e.source().geo().cityName();

            case "service.name" -> e.service() == null ? null : e.service().name();
            case "service.environment" -> e.service() == null ? null : e.service().environment();

            case "user_agent.original" -> e.userAgent() == null ? null : e.userAgent().original();

            default -> throw new IllegalArgumentException(
                    "Unsupported field path '" + path + "'. Supported: " + SUPPORTED);
        };
    }
}
