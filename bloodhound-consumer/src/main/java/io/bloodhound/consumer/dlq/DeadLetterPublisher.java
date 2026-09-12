package io.bloodhound.consumer.dlq;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.DeadLetter;
import io.bloodhound.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;

/** Sends messages the consumer gave up on to the dead letter topic. */
@Component
public class DeadLetterPublisher {

    private static final Logger log = LoggerFactory.getLogger(DeadLetterPublisher.class);
    private static final String CONSUMER_NAME = "bloodhound-consumer";

    private final KafkaTemplate<String, String> kafka;
    private final ObjectMapper mapper;
    private final Counter published;

    public DeadLetterPublisher(KafkaTemplate<String, String> kafka,
                               ObjectMapper eventObjectMapper,
                               MeterRegistry meters) {
        this.kafka = kafka;
        this.mapper = eventObjectMapper;
        this.published = Counter.builder("bloodhound.deadletters.published")
                .description("Messages routed to the dead letter topic").register(meters);
    }

    public void send(ConsumerRecord<String, String> record, String failureType, String reason) {
        DeadLetter letter = new DeadLetter(
                Instant.now(),
                record.topic(), record.partition(), record.offset(), record.key(),
                failureType, truncate(reason), CONSUMER_NAME, record.value());

        try {
            // Keyed by source partition so one bad partition's failures stay ordered together.
            kafka.send(Topics.RAW_EVENTS_DLQ,
                    record.topic() + "-" + record.partition(),
                    mapper.writeValueAsString(letter));
            published.increment();
            log.warn("Dead-lettered {}-{}@{}: {} — {}",
                    record.topic(), record.partition(), record.offset(), failureType, reason);
        } catch (Exception e) {
            // If the DLQ itself is unavailable we must not swallow the original message silently.
            // Throwing keeps the offset uncommitted, so the batch is redelivered and nothing is
            // lost — at the cost of blocking until the DLQ recovers. That is the right trade for
            // security telemetry.
            log.error("Could not write to the dead letter topic; refusing to drop the message", e);
            throw new IllegalStateException("Dead letter topic unavailable", e);
        }
    }

    private static String truncate(String reason) {
        if (reason == null) {
            return null;
        }
        return reason.length() <= 500 ? reason : reason.substring(0, 500) + "…";
    }
}
