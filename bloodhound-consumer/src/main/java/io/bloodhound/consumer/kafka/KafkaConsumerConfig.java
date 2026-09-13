package io.bloodhound.consumer.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties;

import java.util.Map;

@Configuration
public class KafkaConsumerConfig {

    @Bean
    public ObjectMapper eventObjectMapper() {
        return EventJson.mapper();
    }

    @Bean
    public ConsumerFactory<String, String> consumerFactory(KafkaProperties properties) {
        Map<String, Object> config = properties.buildConsumerProperties(null);
        config.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        config.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        return new DefaultKafkaConsumerFactory<>(config);
    }

    /**
     * Batch listener with manual acknowledgement.
     *
     * <p>Auto-commit would advance the offset on a timer, independently of whether the rows ever
     * reached Postgres — a crash then loses events silently. Committing by hand, after the write
     * succeeds, converts that silent loss into at-least-once delivery: on a crash we reprocess a
     * batch and rely on the {@code ON CONFLICT DO NOTHING} dedupe to make the replay harmless.
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> batchListenerFactory(
            ConsumerFactory<String, String> consumerFactory,
            @org.springframework.beans.factory.annotation.Value(
                    "${bloodhound.ingest.concurrency:6}") int concurrency) {

        ConcurrentKafkaListenerContainerFactory<String, String> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory);
        factory.setBatchListener(true);
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);

        // One thread per partition. Threads beyond the topic's partition count sit idle, so
        // this is capped by the 6 partitions on security.events.raw.
        //
        // Was 3, which left half the partitions unserved. Load testing (Week 16) made the cost
        // concrete: the ingest bottleneck is the Postgres batch insert at ~474ms per 500 rows,
        // and throughput is therefore almost exactly
        //     concurrency x (batch size / batch latency)
        // — so the thread count was directly halving the ceiling for no reason.
        factory.setConcurrency(concurrency);
        return factory;
    }
}
