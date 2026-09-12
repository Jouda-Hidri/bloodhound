package io.bloodhound.responder;

import io.bloodhound.responder.config.ResponderProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableScheduling
@EnableTransactionManagement
@EnableConfigurationProperties(ResponderProperties.class)
public class BloodhoundResponderApplication {

    public static void main(String[] args) {
        SpringApplication.run(BloodhoundResponderApplication.class, args);
    }
}
