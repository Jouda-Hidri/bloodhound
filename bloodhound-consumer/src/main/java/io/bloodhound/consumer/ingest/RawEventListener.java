package io.bloodhound.consumer.ingest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.DeadLetter;
import io.bloodhound.common.Topics;
import io.bloodhound.common.event.SecurityEvent;
import io.bloodhound.consumer.dlq.DeadLetterPublisher;
import io.bloodhound.consumer.search.EventIndexer;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Reads raw events off Kafka in batches, persists them, and dead-letters whatever it cannot.
 *
 * <p>The failure strategy in one sentence: <em>a bad message must never block a good one, and a
 * good message must never be lost.</em> Those pull in opposite directions, and the batch/retry/
 * split logic below is where the tension gets resolved.
 */
@Component
public class RawEventListener {

    private static final Logger log = LoggerFactory.getLogger(RawEventListener.class);

    private final ObjectMapper mapper;
    private final RawEventRepository repository;
    private final DeadLetterPublisher deadLetters;
    private final EventIndexer indexer;
    private final Counter ingested;
    private final Counter duplicates;
    private final Counter rejected;
    private final Timer batchTimer;

    public RawEventListener(ObjectMapper eventObjectMapper,
                            RawEventRepository repository,
                            DeadLetterPublisher deadLetters,
                            EventIndexer indexer,
                            MeterRegistry meters) {
        this.mapper = eventObjectMapper;
        this.repository = repository;
        this.deadLetters = deadLetters;
        this.indexer = indexer;
        this.ingested = Counter.builder("bloodhound.events.ingested")
                .description("Events written to Postgres").register(meters);
        this.duplicates = Counter.builder("bloodhound.events.duplicates")
                .description("Events already present, absorbed by the dedupe key").register(meters);
        this.rejected = Counter.builder("bloodhound.events.rejected")
                .description("Events routed to the dead letter topic").register(meters);
        this.batchTimer = Timer.builder("bloodhound.ingest.batch")
                .description("Time to parse and persist one Kafka batch").register(meters);
    }

    @KafkaListener(
            topics = Topics.RAW_EVENTS,
            groupId = "${bloodhound.ingest.group-id:bloodhound-ingest}",
            containerFactory = "batchListenerFactory")
    public void onBatch(List<ConsumerRecord<String, String>> records, Acknowledgment ack) {
        Timer.Sample sample = Timer.start();

        List<ConsumerRecord<String, String>> parsedRecords = new ArrayList<>(records.size());
        List<SecurityEvent> parsed = new ArrayList<>(records.size());

        for (ConsumerRecord<String, String> record : records) {
            SecurityEvent event = parse(record);
            if (event != null) {
                parsedRecords.add(record);
                parsed.add(event);
            }
        }

        if (!parsed.isEmpty()) {
            persist(parsedRecords, parsed);
            indexer.index(parsed);
        }

        // Only acknowledged once every record in the batch has either been stored or
        // deliberately dead-lettered. Anything else would commit past a lost event.
        ack.acknowledge();
        sample.stop(batchTimer);
    }

    /**
     * Batch insert first, because it is an order of magnitude faster. If the batch fails, fall
     * back to one row at a time so that a single poison record is isolated rather than taking
     * 499 healthy events down with it.
     *
     * <p>Retrying the batch once before splitting matters: most batch failures are transient
     * (a connection reset, a lock timeout), and splitting a 500-record batch into 500 individual
     * inserts on every blip would be a self-inflicted performance collapse.
     */
    private void persist(List<ConsumerRecord<String, String>> records, List<SecurityEvent> events) {
        try {
            recordInserts(repository.insertBatch(events), events.size());
            return;
        } catch (RuntimeException first) {
            log.warn("Batch insert of {} events failed, retrying once: {}",
                    events.size(), first.toString());
        }

        try {
            recordInserts(repository.insertBatch(events), events.size());
            return;
        } catch (RuntimeException second) {
            log.warn("Batch insert failed again, splitting to isolate the bad record(s): {}",
                    second.toString());
        }

        for (int i = 0; i < events.size(); i++) {
            try {
                recordInserts(repository.insertBatch(List.of(events.get(i))), 1);
            } catch (RuntimeException individual) {
                rejected.increment();
                deadLetters.send(records.get(i), DeadLetter.PERSIST_ERROR, individual.toString());
            }
        }
    }

    private void recordInserts(int inserted, int attempted) {
        ingested.increment(inserted);
        duplicates.increment(Math.max(0, attempted - inserted));
    }

    private SecurityEvent parse(ConsumerRecord<String, String> record) {
        SecurityEvent event;
        try {
            event = mapper.readValue(record.value(), SecurityEvent.class);
        } catch (Exception e) {
            rejected.increment();
            deadLetters.send(record, DeadLetter.PARSE_ERROR, e.getMessage());
            return null;
        }

        String missing = validate(event);
        if (missing != null) {
            rejected.increment();
            deadLetters.send(record, DeadLetter.VALIDATION_ERROR, missing);
            return null;
        }
        return event;
    }

    /** @return a description of what is missing, or null if the event is usable. */
    private static String validate(SecurityEvent event) {
        if (event.timestamp() == null) {
            return "missing required field @timestamp";
        }
        if (event.event() == null || event.event().id() == null) {
            return "missing required field event.id";
        }
        if (event.user() == null || event.user().id() == null) {
            // Without a subject there is nothing to attribute the event to, and every per-user
            // detection would silently skip it. Better to reject loudly.
            return "missing required field user.id";
        }
        return null;
    }
}
