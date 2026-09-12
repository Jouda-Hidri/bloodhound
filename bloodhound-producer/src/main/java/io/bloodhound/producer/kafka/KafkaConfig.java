package io.bloodhound.producer.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KafkaConfig {

    /**
     * The producer serialises events to JSON itself and publishes plain strings, rather than
     * using Spring's JsonSerializer. Two reasons: the bytes on the topic are exactly what
     * {@link EventJson} produces (no hidden type headers to confuse other consumers), and the
     * serialisation step is somewhere we can see it when it goes wrong.
     */
    @Bean
    public ObjectMapper eventObjectMapper() {
        return EventJson.mapper();
    }
}
