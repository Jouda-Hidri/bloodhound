package io.bloodhound.responder.config;

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
public class KafkaConfig {

    @Bean
    public ObjectMapper eventObjectMapper() {
        return EventJson.mapper();
    }

    @Bean
    public ConsumerFactory<String, String> alertConsumerFactory(KafkaProperties properties) {
        Map<String, Object> config = properties.buildConsumerProperties(null);
        config.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        config.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        return new DefaultKafkaConsumerFactory<>(config);
    }

    /**
     * Single-threaded on purpose.
     *
     * <p>Alert volume is orders of magnitude below event volume, so there is nothing to gain from
     * concurrency — and plenty to lose. Two threads handling alerts for the same entity would race
     * on incident creation and risk updates. The database constraints would hold, but the
     * resulting retries and duplicate proposals are complexity bought for no throughput.
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> alertListenerFactory(
            ConsumerFactory<String, String> alertConsumerFactory) {
        ConcurrentKafkaListenerContainerFactory<String, String> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(alertConsumerFactory);
        factory.setBatchListener(true);
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
        factory.setConcurrency(1);
        return factory;
    }
}
