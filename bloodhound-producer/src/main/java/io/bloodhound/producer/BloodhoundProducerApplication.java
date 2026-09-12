package io.bloodhound.producer;

import io.bloodhound.producer.schema.SchemaRegistryProperties;
import io.bloodhound.producer.sim.SimulationProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({SimulationProperties.class, SchemaRegistryProperties.class})
public class BloodhoundProducerApplication {

    public static void main(String[] args) {
        SpringApplication.run(BloodhoundProducerApplication.class, args);
    }
}
