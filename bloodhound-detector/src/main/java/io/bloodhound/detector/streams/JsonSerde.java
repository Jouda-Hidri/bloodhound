package io.bloodhound.detector.streams;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;

import java.nio.charset.StandardCharsets;

/**
 * JSON serde for Kafka Streams state stores and topics.
 *
 * <p>Deserialisation returns null rather than throwing on bad bytes. In a Streams topology an
 * exception here kills the stream thread, and one malformed record on the input topic would take
 * the entire detection engine offline — a trivially available denial of service against your own
 * security monitoring. Nulls are filtered out immediately downstream instead.
 */
public class JsonSerde<T> implements Serde<T> {

    private final ObjectMapper mapper;
    private final Class<T> type;
    private final java.util.function.Consumer<Exception> onError;

    public JsonSerde(ObjectMapper mapper, Class<T> type) {
        this(mapper, type, e -> { });
    }

    public JsonSerde(ObjectMapper mapper, Class<T> type, java.util.function.Consumer<Exception> onError) {
        this.mapper = mapper;
        this.type = type;
        this.onError = onError;
    }

    @Override
    public Serializer<T> serializer() {
        return (topic, data) -> {
            if (data == null) {
                return null;
            }
            try {
                return mapper.writeValueAsBytes(data);
            } catch (Exception e) {
                throw new IllegalStateException("Could not serialise " + type.getSimpleName(), e);
            }
        };
    }

    @Override
    public Deserializer<T> deserializer() {
        return (topic, bytes) -> {
            if (bytes == null || bytes.length == 0) {
                return null;
            }
            try {
                return mapper.readValue(bytes, type);
            } catch (Exception e) {
                onError.accept(e);
                return null;
            }
        };
    }

    public static String asString(byte[] bytes) {
        return bytes == null ? null : new String(bytes, StandardCharsets.UTF_8);
    }
}
