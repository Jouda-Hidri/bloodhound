package io.bloodhound.detector.rules;

import io.bloodhound.common.alert.EntityType;
import io.bloodhound.common.alert.Severity;
import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RuleLoaderTest {

    private final RuleLoader loader = new RuleLoader();

    private static SecurityEvent event(EventAction action, Outcome outcome, String userAgent) {
        return new SecurityEvent(
                Instant.now(),
                new SecurityEvent.EventInfo("e1", EventCategory.AUTHENTICATION, action, outcome, null),
                new SecurityEvent.UserInfo("u-1", "a.b", "bloodhound.lab"),
                new SecurityEvent.SourceInfo("203.0.113.1", 443,
                        new SecurityEvent.GeoInfo("GR", "Athens")),
                new SecurityEvent.ServiceInfo("payment-api", "0.1.0", "lab"),
                new SecurityEvent.UserAgentInfo(userAgent),
                Map.of());
    }

    /**
     * The bundled rules must all load and validate. This is the test that catches a typo'd field
     * in a YAML file before it becomes a rule that matches nothing in production.
     */
    @Test
    void bundledRulesAllLoadAndValidate() {
        List<DetectionRule> rules = loader.load(null);

        assertThat(rules).isNotEmpty();
        assertThat(rules).allSatisfy(rule -> {
            assertThat(rule.id()).isNotBlank();
            assertThat(rule.severity()).isNotNull();
            assertThat(rule.entityType()).isNotNull();
            assertThat(rule.threshold()).isPositive();
        });
        assertThat(rules).extracting(DetectionRule::id).doesNotHaveDuplicates();
    }

    /** Every rule should claim an ATT&CK technique — that mapping is what makes coverage legible. */
    @Test
    void everyEnabledRuleMapsToAnAttackTechnique() {
        assertThat(loader.load(null))
                .filteredOn(DetectionRule::isEnabled)
                .allSatisfy(rule -> assertThat(rule.technique())
                        .as("rule %s must declare an ATT&CK technique", rule.id())
                        .isNotBlank()
                        .matches("T\\d{4}(\\.\\d{3})?"));
    }

    @Test
    void matchRequiresEveryConditionToHold() {
        DetectionRule rule = bruteForceRule();

        assertThat(rule.matches(event(EventAction.USER_LOGIN, Outcome.FAILURE, "curl"))).isTrue();
        // right action, wrong outcome
        assertThat(rule.matches(event(EventAction.USER_LOGIN, Outcome.SUCCESS, "curl"))).isFalse();
        // right outcome, wrong action
        assertThat(rule.matches(event(EventAction.TOKEN_ISSUED, Outcome.FAILURE, "curl"))).isFalse();
    }

    @Test
    void matchAnyAcceptsAnyListedValue() {
        DetectionRule rule = new DetectionRule(
                "ua-rule", "Scripted agents", "d", Severity.MEDIUM, "T1098", true,
                Map.of("event.action", "password-change"),
                Map.of("user_agent.original", List.of("curl/8.6.0", "python-requests/2.32.3")),
                "user.id", EntityType.USER, Duration.ofMinutes(5), Duration.ofMinutes(1), 1,
                null, List.of());

        assertThat(rule.matches(event(EventAction.PASSWORD_CHANGE, Outcome.SUCCESS, "curl/8.6.0"))).isTrue();
        assertThat(rule.matches(event(EventAction.PASSWORD_CHANGE, Outcome.SUCCESS, "python-requests/2.32.3"))).isTrue();
        assertThat(rule.matches(event(EventAction.PASSWORD_CHANGE, Outcome.SUCCESS, "Firefox"))).isFalse();
    }

    @Test
    void validationRejectsAnUnknownGroupByField() {
        DetectionRule rule = new DetectionRule(
                "bad", "Bad", "d", Severity.LOW, "T0000", true,
                Map.of(), null, "user.emial", EntityType.USER,
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3, null, List.of());

        assertThatThrownBy(rule::validate)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown group_by field");
    }

    @Test
    void validationRejectsAnUnknownMatchField() {
        DetectionRule rule = new DetectionRule(
                "bad2", "Bad", "d", Severity.LOW, "T0000", true,
                Map.of("event.acton", "user-login"), null, "user.id", EntityType.USER,
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3, null, List.of());

        assertThatThrownBy(rule::validate)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown match field");
    }

    /** Grace longer than the window keeps state stores alive far past their usefulness. */
    @Test
    void validationRejectsGraceLongerThanWindow() {
        DetectionRule rule = new DetectionRule(
                "bad3", "Bad", "d", Severity.LOW, "T0000", true,
                Map.of(), null, "user.id", EntityType.USER,
                Duration.ofMinutes(5), Duration.ofMinutes(30), 3, null, List.of());

        assertThatThrownBy(rule::validate)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("grace must not exceed the window");
    }

    @Test
    void validationRejectsNonPositiveThreshold() {
        DetectionRule rule = new DetectionRule(
                "bad4", "Bad", "d", Severity.LOW, "T0000", true,
                Map.of(), null, "user.id", EntityType.USER,
                Duration.ofMinutes(5), Duration.ofMinutes(1), 0, null, List.of());

        assertThatThrownBy(rule::validate)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("threshold must be > 0");
    }

    static DetectionRule bruteForceRule() {
        return new DetectionRule(
                "brute-force-test", "Brute force", "d", Severity.HIGH, "T1110.001", true,
                Map.of("event.action", "user-login", "event.outcome", "failure"),
                null, "user.id", EntityType.USER,
                Duration.ofMinutes(5), Duration.ofMinutes(1), 3, null,
                List.of("source.ip"));
    }
}
