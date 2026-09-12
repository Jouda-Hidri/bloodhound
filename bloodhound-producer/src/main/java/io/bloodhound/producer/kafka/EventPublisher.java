package io.bloodhound.producer.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.Topics;
import io.bloodhound.common.event.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.LongAdder;

/** Publishes security events to the raw topic, keyed so one user's events stay ordered. */
@Component
public class EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(EventPublisher.class);

    private final KafkaTemplate<String, String> kafka;
    private final ObjectMapper mapper;
    private final LongAdder published = new LongAdder();
    private final LongAdder failed = new LongAdder();

    public EventPublisher(KafkaTemplate<String, String> kafka, ObjectMapper eventObjectMapper) {
        this.kafka = kafka;
        this.mapper = eventObjectMapper;
    }

    /**
     * Partition key is {@code user.id}. Every event about one user lands on one partition,
     * which is what makes per-user windowed detection (Week 6) possible without a shuffle.
     * The cost is skew: a single very busy account is a hot partition. Noted, not yet solved.
     */
    public void publish(SecurityEvent event) {
        String key = event.user() != null ? event.user().id() : null;
        String payload;
        try {
            payload = mapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            failed.increment();
            log.error("Could not serialise event {}", event.event().id(), e);
            return;
        }

        kafka.send(Topics.RAW_EVENTS, key, payload)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        failed.increment();
                        log.warn("Publish failed for event {}: {}", event.event().id(), ex.toString());
                    } else {
                        published.increment();
                    }
                });
    }

    public long publishedCount() {
        return published.sum();
    }

    public long failedCount() {
        return failed.sum();
    }
}
