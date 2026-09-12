package io.bloodhound.consumer;

import io.bloodhound.consumer.ingest.IngestProperties;
import io.bloodhound.consumer.search.SearchProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({IngestProperties.class, SearchProperties.class})
public class BloodhoundConsumerApplication {

    public static void main(String[] args) {
        SpringApplication.run(BloodhoundConsumerApplication.class, args);
    }
}
