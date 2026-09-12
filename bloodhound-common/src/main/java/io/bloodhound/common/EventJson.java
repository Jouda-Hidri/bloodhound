package io.bloodhound.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * The single JSON configuration used on both sides of the topic.
 *
 * <p>Producer and consumer must agree byte-for-byte on how events are encoded, so the
 * mapper lives here rather than being configured twice. Timestamps are ISO-8601 strings,
 * not epoch numbers, because humans read raw Kafka messages during incidents.
 */
public final class EventJson {

    private EventJson() {
    }

    public static ObjectMapper mapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                // Tolerate fields we do not know about yet: a producer adding a field
                // must never break an older consumer. See schema compatibility, Week 3.
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }
}
