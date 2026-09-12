package io.bloodhound.detector.api;

import io.bloodhound.detector.rules.DetectionRule;
import io.bloodhound.detector.sigma.SigmaExporter;
import io.bloodhound.detector.streams.DetectionTopology;
import org.apache.kafka.streams.KafkaStreams;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.config.StreamsBuilderFactoryBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Inspect the loaded rules, the ATT&CK coverage they give, and the state of the topology. */
@RestController
@RequestMapping("/rules")
public class RulesController {

    private final DetectionTopology topology;
    private final SigmaExporter sigma;
    private final StreamsBuilderFactoryBean streams;

    public RulesController(DetectionTopology topology, SigmaExporter sigma,
                           StreamsBuilderFactoryBean streams) {
        this.topology = topology;
        this.sigma = sigma;
        this.streams = streams;
    }

    @GetMapping
    public List<Map<String, Object>> list() {
        return topology.rules().stream().map(rule -> {
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("id", rule.id());
            summary.put("name", rule.name());
            summary.put("severity", rule.severity().value());
            summary.put("technique", rule.technique());
            summary.put("enabled", rule.isEnabled());
            summary.put("groupBy", rule.groupBy());
            summary.put("entityType", rule.entityType().value());
            summary.put("window", rule.window().toString());
            summary.put("threshold", rule.threshold());
            summary.put("distinct", rule.distinct());
            return summary;
        }).toList();
    }

    /** Which ATT&CK techniques the rule set covers, and how many rules address each. */
    @GetMapping("/coverage")
    public Map<String, Object> coverage() {
        Map<String, List<String>> byTechnique = new LinkedHashMap<>();
        for (DetectionRule rule : topology.rules()) {
            if (rule.isEnabled() && rule.technique() != null) {
                byTechnique.computeIfAbsent(rule.technique(), t -> new java.util.ArrayList<>())
                        .add(rule.id());
            }
        }
        return Map.of(
                "techniques", byTechnique,
                "techniqueCount", byTechnique.size(),
                "enabledRules", topology.rules().stream().filter(DetectionRule::isEnabled).count());
    }

    @GetMapping(value = "/{id}/sigma", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> asSigma(@PathVariable String id) {
        return topology.rules().stream()
                .filter(rule -> rule.id().equals(id))
                .findFirst()
                .map(rule -> ResponseEntity.ok(sigma.toSigma(rule)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping(value = "/sigma", produces = MediaType.TEXT_PLAIN_VALUE)
    public String allAsSigma() {
        return topology.rules().stream()
                .filter(DetectionRule::isEnabled)
                .map(sigma::toSigma)
                .reduce((a, b) -> a + "---\n" + b)
                .orElse("");
    }

    /** Streams state — RUNNING means detections are live; REBALANCING means they are briefly not. */
    @GetMapping("/topology/state")
    public Map<String, Object> state() {
        KafkaStreams kafkaStreams = streams.getKafkaStreams();
        return Map.of(
                "state", kafkaStreams == null ? "NOT_STARTED" : kafkaStreams.state().name(),
                "rules", topology.rules().size());
    }

    @GetMapping(value = "/topology/describe", produces = MediaType.TEXT_PLAIN_VALUE)
    public String describe() {
        return streams.getTopology() == null ? "not built" : streams.getTopology().describe().toString();
    }
}
