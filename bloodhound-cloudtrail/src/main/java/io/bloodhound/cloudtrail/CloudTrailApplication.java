package io.bloodhound.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@SpringBootApplication
public class CloudTrailApplication {

    public static void main(String[] args) {
        SpringApplication.run(CloudTrailApplication.class, args);
    }

    @Bean
    public ObjectMapper eventObjectMapper() {
        return EventJson.mapper();
    }
}

/**
 * Ingest endpoints.
 *
 * <p>In a real deployment CloudTrail lands in S3 and this would be driven by an S3 event
 * notification or an SQS queue. An HTTP endpoint is the same mapping logic with a simpler
 * trigger, and it means the pipeline can be exercised without an AWS account.
 */
@RestController
@RequestMapping("/cloudtrail")
class CloudTrailController {

    private final CloudTrailIngestService ingest;
    private final ObjectMapper json;

    CloudTrailController(CloudTrailIngestService ingest, ObjectMapper eventObjectMapper) {
        this.ingest = ingest;
        this.json = eventObjectMapper;
    }

    @PostMapping("/ingest")
    public CloudTrailIngestService.IngestResult ingest(@RequestBody JsonNode payload) {
        return ingest.ingest(payload);
    }

    /** Replays the bundled sample delivery — real CloudTrail record shapes, fake account ids. */
    @PostMapping("/replay-sample")
    public ResponseEntity<?> replaySample() {
        try (var in = new ClassPathResource("samples/cloudtrail-events.json").getInputStream()) {
            return ResponseEntity.ok(ingest.ingest(json.readTree(in)));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }
}
