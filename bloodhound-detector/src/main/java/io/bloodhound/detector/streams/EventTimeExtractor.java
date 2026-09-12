package io.bloodhound.detector.streams;

import io.bloodhound.common.event.SecurityEvent;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.streams.processor.TimestampExtractor;

/**
 * Uses {@code @timestamp} — when the event happened — as the stream time.
 *
 * <p>The default extractor uses the Kafka record timestamp, which is when the event was
 * <em>published</em>. For detection that is the wrong clock: a burst of 30 login failures spread
 * over 8 seconds but published in one batch would all land in the same millisecond, and a rule
 * asking "10 failures within 5 minutes" would be measuring the producer's batching behaviour
 * rather than the attacker's.
 *
 * <p>Trusting event time does mean trusting the producer's clock. A source with a skewed clock
 * can push its events into a window where nobody is looking — a real evasion technique, and the
 * reason `ingested_at` is stored alongside `ts` so the skew is at least visible.
 */
public class EventTimeExtractor implements TimestampExtractor {

    @Override
    public long extract(ConsumerRecord<Object, Object> record, long partitionTime) {
        if (record.value() instanceof SecurityEvent event && event.timestamp() != null) {
            return event.timestamp().toEpochMilli();
        }
        // Unparseable or timestamp-less: fall back to the current stream time rather than
        // returning -1, which would make Streams drop the record without explanation.
        return partitionTime >= 0 ? partitionTime : record.timestamp();
    }
}
