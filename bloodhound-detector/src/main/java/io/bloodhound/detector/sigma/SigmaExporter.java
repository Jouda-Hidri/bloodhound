package io.bloodhound.detector.sigma;

import io.bloodhound.detector.rules.DetectionRule;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Renders a rule as a Sigma document.
 *
 * <p><a href="https://sigmahq.io">Sigma</a> is the interchange format the detection community
 * actually uses: thousands of public rules are published in it, and every major SIEM has a
 * converter. Exporting to it is what makes these detections legible to a security engineer who
 * has never seen this project.
 *
 * <p><b>The export is lossy, and the lossy part is the interesting part.</b> Sigma describes
 * <em>what to match</em> very well and <em>aggregation over time</em> barely at all — its
 * {@code condition} syntax has an informal {@code | count() by field > N} extension that most
 * backends ignore. So a Sigma rule produced here matches the right events but will not reproduce
 * the windowing, and a Sigma rule imported from elsewhere generally needs a threshold invented
 * for it. That gap is exactly why this project has its own engine rather than running Sigma
 * directly, and it is worth understanding before choosing one over the other.
 */
@Component
public class SigmaExporter {

    /** Sigma's ECS-flavoured field names match ours already, which is the payoff for using ECS. */
    public String toSigma(DetectionRule rule) {
        StringBuilder yaml = new StringBuilder();

        yaml.append("title: ").append(rule.name()).append('\n');
        yaml.append("id: ").append(rule.id()).append('\n');
        yaml.append("status: experimental\n");
        yaml.append("description: |\n");
        for (String line : String.valueOf(rule.description()).strip().split("\n")) {
            yaml.append("    ").append(line.strip()).append('\n');
        }
        yaml.append("author: bloodhound\n");
        yaml.append("logsource:\n");
        yaml.append("    product: bloodhound\n");
        yaml.append("    service: ").append(categoryOf(rule)).append('\n');
        yaml.append("detection:\n");
        yaml.append("    selection:\n");

        List<String> conditions = new ArrayList<>();
        if (rule.match() != null) {
            for (Map.Entry<String, String> entry : rule.match().entrySet()) {
                yaml.append("        ").append(entry.getKey()).append(": ")
                        .append(quote(entry.getValue())).append('\n');
            }
        }
        if (rule.matchAny() != null) {
            for (Map.Entry<String, List<String>> entry : rule.matchAny().entrySet()) {
                yaml.append("        ").append(entry.getKey()).append(":\n");
                for (String value : entry.getValue()) {
                    yaml.append("            - ").append(quote(value)).append('\n');
                }
            }
        }
        conditions.add("selection");

        // The non-standard part. Emitted anyway because dropping it would make the rule look like
        // it fires on a single event, which would be actively misleading.
        String aggregation = rule.isDistinctRule()
                ? " | count(%s) by %s > %d".formatted(
                        rule.distinct(), rule.groupBy(), rule.threshold() - 1)
                : " | count() by %s > %d".formatted(rule.groupBy(), rule.threshold() - 1);

        yaml.append("    condition: ").append(String.join(" and ", conditions))
                .append(aggregation).append('\n');
        yaml.append("    timeframe: ").append(toSigmaTimeframe(rule)).append('\n');

        yaml.append("falsepositives:\n");
        yaml.append("    - Unknown — see the rule description and the scoring report\n");
        yaml.append("level: ").append(rule.severity().value()).append('\n');
        yaml.append("tags:\n");
        if (rule.technique() != null) {
            yaml.append("    - attack.").append(rule.technique().toLowerCase()).append('\n');
        }
        return yaml.toString();
    }

    private static String categoryOf(DetectionRule rule) {
        if (rule.match() != null && rule.match().containsKey("event.category")) {
            return rule.match().get("event.category");
        }
        return "authentication";
    }

    /** Sigma timeframes are written as 5m / 2h / 1d, not ISO-8601. */
    private static String toSigmaTimeframe(DetectionRule rule) {
        long seconds = rule.window().toSeconds();
        if (seconds % 86400 == 0) {
            return (seconds / 86400) + "d";
        }
        if (seconds % 3600 == 0) {
            return (seconds / 3600) + "h";
        }
        return Math.max(1, seconds / 60) + "m";
    }

    private static String quote(String value) {
        return value.matches("[A-Za-z0-9._:@/-]+") ? value : "'" + value.replace("'", "''") + "'";
    }
}
