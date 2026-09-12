package io.bloodhound.detector.sigma;

import io.bloodhound.detector.rules.DetectionRule;
import io.bloodhound.detector.rules.RuleLoader;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigmaExporterTest {

    private final SigmaExporter exporter = new SigmaExporter();
    private final RuleLoader loader = new RuleLoader();

    @Test
    void exportsTheFieldsSigmaConsumersExpect() {
        DetectionRule rule = loader.load(null).stream()
                .filter(r -> r.id().equals("brute-force-single-account"))
                .findFirst().orElseThrow();

        String sigma = exporter.toSigma(rule);

        assertThat(sigma).contains("title: Brute force against a single account");
        assertThat(sigma).contains("id: brute-force-single-account");
        assertThat(sigma).contains("level: high");
        // ECS field names carry straight through — the payoff for not inventing our own.
        assertThat(sigma).contains("event.action: user-login");
        assertThat(sigma).contains("event.outcome: failure");
        assertThat(sigma).contains("timeframe: 5m");
        assertThat(sigma).contains("attack.t1110.001");
    }

    /** Distinct-count rules must export count(field) rather than a bare count(). */
    @Test
    void distinctRulesExportTheCountedField() {
        DetectionRule rule = loader.load(null).stream()
                .filter(r -> r.id().equals("credential-stuffing-source"))
                .findFirst().orElseThrow();

        assertThat(exporter.toSigma(rule)).contains("count(user.id) by source.ip");
    }

    @Test
    void everyBundledRuleExportsWithoutError() {
        for (DetectionRule rule : loader.load(null)) {
            String sigma = exporter.toSigma(rule);
            assertThat(sigma).as("rule %s", rule.id())
                    .contains("title:").contains("detection:").contains("condition:");
        }
    }
}
