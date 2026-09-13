package io.bloodhound.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.Topics;
import io.bloodhound.common.event.SecurityEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads CloudTrail and publishes the result onto the same topic the application events use.
 *
 * <p>That is the design decision worth noting: CloudTrail events do not get their own pipeline,
 * their own storage or their own rules. They are translated at the edge into ECS and join the
 * existing stream, so every detection, the risk model and the incident workflow apply to them
 * without modification.
 *
 * <p>The alternative — a parallel pipeline per source — is how SIEM deployments end up with
 * rules that work on one log source and not another, and why "we have CloudTrail" so often means
 * "we store CloudTrail".
 */
@Service
public class CloudTrailIngestService {

    private static final Logger log = LoggerFactory.getLogger(CloudTrailIngestService.class);

    private final CloudTrailMapper mapper;
    private final ObjectMapper json;
    private final KafkaTemplate<String, String> kafka;
    private final Counter mapped;
    private final Counter skipped;

    public CloudTrailIngestService(CloudTrailMapper mapper, ObjectMapper eventObjectMapper,
                                   KafkaTemplate<String, String> kafka, MeterRegistry meters) {
        this.mapper = mapper;
        this.json = eventObjectMapper;
        this.kafka = kafka;
        this.mapped = Counter.builder("bloodhound.cloudtrail.mapped").register(meters);
        this.skipped = Counter.builder("bloodhound.cloudtrail.skipped").register(meters);
    }

    /**
     * Ingest one CloudTrail delivery.
     *
     * <p>Accepts either the wrapper CloudTrail actually delivers — {@code {"Records": [...]}} —
     * or a bare array, because both turn up depending on whether you are reading an S3 object,
     * a Kinesis stream, or something a colleague pasted into a file.
     */
    public IngestResult ingest(JsonNode payload) {
        List<JsonNode> records = new ArrayList<>();
        if (payload.has("Records") && payload.get("Records").isArray()) {
            payload.get("Records").forEach(records::add);
        } else if (payload.isArray()) {
            payload.forEach(records::add);
        } else if (payload.isObject()) {
            records.add(payload);
        }

        int published = 0;
        Map<String, Integer> byAction = new LinkedHashMap<>();
        List<String> unmapped = new ArrayList<>();

        for (JsonNode record : records) {
            SecurityEvent event = mapper.map(record);
            if (event == null || event.event() == null || event.event().id() == null) {
                skipped.increment();
                continue;
            }
            try {
                kafka.send(Topics.RAW_EVENTS, event.user().id(), json.writeValueAsString(event));
                published++;
                mapped.increment();

                String action = event.event().action().value();
                byAction.merge(action, 1, Integer::sum);
                if ("unknown".equals(action)) {
                    String name = event.labels().get("cloud_event_name");
                    if (name != null && !unmapped.contains(name)) {
                        unmapped.add(name);
                    }
                }
            } catch (Exception e) {
                skipped.increment();
                log.warn("Could not publish CloudTrail event {}", event.event().id(), e);
            }
        }

        // Reporting which API names fell through to `unknown` is the feedback loop that keeps
        // the mapping honest. Without it, coverage silently decays as AWS adds services.
        if (!unmapped.isEmpty()) {
            log.info("CloudTrail API names with no action mapping: {}", unmapped);
        }
        log.info("Ingested {} of {} CloudTrail record(s): {}", published, records.size(), byAction);

        return new IngestResult(records.size(), published, records.size() - published,
                byAction, unmapped);
    }

    public record IngestResult(int received, int published, int skipped,
                               Map<String, Integer> byAction, List<String> unmappedApiNames) {}
}
