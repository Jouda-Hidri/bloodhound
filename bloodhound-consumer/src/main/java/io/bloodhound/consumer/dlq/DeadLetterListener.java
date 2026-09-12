package io.bloodhound.consumer.dlq;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.DeadLetter;
import io.bloodhound.common.Topics;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.util.List;

/**
 * Mirrors the dead letter topic into Postgres so the backlog is inspectable and replayable.
 *
 * <p>A DLQ nobody looks at is a slow data loss with extra steps. Putting it in the database means
 * it sits next to the events, is queryable with the same tools, and can be alerted on.
 */
@Component
public class DeadLetterListener {

    private static final Logger log = LoggerFactory.getLogger(DeadLetterListener.class);

    private static final String INSERT = """
            insert into dead_letters (
                failed_at, source_topic, source_partition, source_offset, source_key,
                failure_type, failure_reason, consumer, payload
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (source_topic, source_partition, source_offset) do nothing
            """;

    private final ObjectMapper mapper;
    private final JdbcTemplate jdbc;

    public DeadLetterListener(ObjectMapper eventObjectMapper, JdbcTemplate jdbc) {
        this.mapper = eventObjectMapper;
        this.jdbc = jdbc;
    }

    @KafkaListener(
            topics = Topics.RAW_EVENTS_DLQ,
            groupId = "${bloodhound.ingest.dlq-group-id:bloodhound-dlq-archive}",
            containerFactory = "batchListenerFactory")
    public void onBatch(List<ConsumerRecord<String, String>> records, Acknowledgment ack) {
        for (ConsumerRecord<String, String> record : records) {
            try {
                DeadLetter letter = mapper.readValue(record.value(), DeadLetter.class);
                jdbc.update(INSERT,
                        Timestamp.from(letter.failedAt()),
                        letter.sourceTopic(), letter.sourcePartition(), letter.sourceOffset(),
                        letter.sourceKey(), letter.failureType(), letter.failureReason(),
                        letter.consumer(), letter.payload());
            } catch (Exception e) {
                // A malformed dead letter is the end of the line — there is no DLQ for the DLQ.
                // Log loudly and move on rather than blocking the archive forever.
                log.error("Could not archive dead letter at {}-{}@{}",
                        record.topic(), record.partition(), record.offset(), e);
            }
        }
        ack.acknowledge();
    }
}
