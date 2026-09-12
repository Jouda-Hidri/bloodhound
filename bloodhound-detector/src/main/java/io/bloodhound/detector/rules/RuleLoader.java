package io.bloodhound.detector.rules;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Loads detection rules from YAML — bundled defaults plus an optional external directory.
 *
 * <p>The external directory is what makes rules editable without a rebuild: point
 * {@code bloodhound.detector.rules-dir} at a folder, drop in a YAML file, restart the detector.
 * Hot reloading is deliberately not implemented, because a rule that changes under a running
 * Kafka Streams topology would change the meaning of state stores that are already populated.
 */
@Component
public class RuleLoader {

    private static final Logger log = LoggerFactory.getLogger(RuleLoader.class);

    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory())
            .registerModule(new JavaTimeModule())
            // Strict: an unrecognised key in a rule file is a typo, and silently ignoring it
            // would produce a rule that does not do what its author plainly intended.
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    public List<DetectionRule> load(String externalDirectory) {
        List<DetectionRule> rules = new ArrayList<>(loadFromClasspath());

        if (externalDirectory != null && !externalDirectory.isBlank()) {
            rules.addAll(loadFromDirectory(new File(externalDirectory)));
        }

        Set<String> ids = new HashSet<>();
        for (DetectionRule rule : rules) {
            rule.validate();
            if (!ids.add(rule.id())) {
                throw new IllegalStateException("Duplicate rule id: " + rule.id());
            }
        }

        List<DetectionRule> enabled = rules.stream().filter(DetectionRule::isEnabled).toList();
        log.info("Loaded {} detection rules ({} enabled): {}",
                rules.size(), enabled.size(), enabled.stream().map(DetectionRule::id).toList());
        return rules;
    }

    private List<DetectionRule> loadFromClasspath() {
        try {
            Resource[] resources = new PathMatchingResourcePatternResolver()
                    .getResources("classpath*:rules/*.yaml");
            List<DetectionRule> rules = new ArrayList<>(resources.length);
            for (Resource resource : resources) {
                try (InputStream in = resource.getInputStream()) {
                    rules.add(parse(in, resource.getFilename()));
                }
            }
            return rules;
        } catch (IOException e) {
            throw new IllegalStateException("Could not read bundled rules", e);
        }
    }

    private List<DetectionRule> loadFromDirectory(File directory) {
        if (!directory.isDirectory()) {
            log.warn("Rules directory {} does not exist; using bundled rules only", directory);
            return List.of();
        }
        File[] files = directory.listFiles((dir, name) ->
                name.endsWith(".yaml") || name.endsWith(".yml"));
        if (files == null) {
            return List.of();
        }
        List<DetectionRule> rules = new ArrayList<>(files.length);
        for (File file : files) {
            try (InputStream in = new java.io.FileInputStream(file)) {
                rules.add(parse(in, file.getName()));
            } catch (IOException e) {
                throw new IllegalStateException("Could not read rule file " + file, e);
            }
        }
        log.info("Loaded {} rules from {}", rules.size(), directory);
        return rules;
    }

    private DetectionRule parse(InputStream in, String filename) throws IOException {
        try {
            return yaml.readValue(in, DetectionRule.class);
        } catch (IOException e) {
            // The filename is the only thing that makes a YAML parse error actionable.
            throw new IllegalStateException("Invalid rule file '" + filename + "': " + e.getMessage(), e);
        }
    }
}
