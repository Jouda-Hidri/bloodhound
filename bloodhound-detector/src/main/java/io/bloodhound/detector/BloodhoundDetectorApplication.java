package io.bloodhound.detector;

import io.bloodhound.detector.config.DetectorProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.kafka.annotation.EnableKafkaStreams;

@SpringBootApplication
@EnableKafkaStreams
@EnableConfigurationProperties(DetectorProperties.class)
public class BloodhoundDetectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(BloodhoundDetectorApplication.class, args);
    }
}
