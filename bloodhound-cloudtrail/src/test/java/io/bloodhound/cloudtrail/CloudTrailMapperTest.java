package io.bloodhound.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.EventJson;
import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mapping is the contract between AWS's model of the world and this platform's. Each test
 * here pins down a place where the two disagree, because every one of those is a detection that
 * would otherwise fail silently.
 */
class CloudTrailMapperTest {

    private final CloudTrailMapper mapper = new CloudTrailMapper();
    private final ObjectMapper json = EventJson.mapper();

    private JsonNode records() throws IOException {
        try (var in = new ClassPathResource("samples/cloudtrail-events.json").getInputStream()) {
            return json.readTree(in).get("Records");
        }
    }

    private SecurityEvent mapNth(int index) throws IOException {
        return mapper.map(records().get(index));
    }

    /**
     * The trap that matters most. A failed console login carries no errorCode — the result is in
     * responseElements.ConsoleLogin. A mapper that only checks errorCode records every failed
     * console login as a success, which is exactly backwards for the highest-signal event type
     * AWS produces.
     */
    @Test
    void failedConsoleLoginIsAFailureDespiteHavingNoErrorCode() throws IOException {
        SecurityEvent event = mapNth(0);

        assertThat(event.event().outcome()).isEqualTo(Outcome.FAILURE);
        assertThat(event.event().action()).isEqualTo(EventAction.USER_LOGIN);
        assertThat(event.event().category()).isEqualTo(EventCategory.AUTHENTICATION);
        assertThat(event.user().id()).isEqualTo("alice");
        assertThat(event.source().ip()).isEqualTo("203.0.113.45");
    }

    @Test
    void successfulConsoleLoginIsASuccess() throws IOException {
        assertThat(mapNth(1).event().outcome()).isEqualTo(Outcome.SUCCESS);
    }

    /** Root has no userName at all. It is the highest-signal identity in an AWS account. */
    @Test
    void rootIsIdentifiedExplicitly() throws IOException {
        SecurityEvent event = mapNth(2);

        assertThat(event.user().id()).isEqualTo("root:123456789012");
        assertThat(event.user().name()).isEqualTo("root");
    }

    /**
     * AssumedRole has no userName either, and its principalId embeds a per-session suffix.
     * Keying on principalId would give the same role a different user.id every session, so a
     * threshold rule counting per user would never reach its threshold.
     */
    @Test
    void assumedRoleIsOneIdentityAcrossSessions() throws IOException {
        SecurityEvent assumeRole = mapNth(3);
        SecurityEvent putPolicy = mapNth(4);
        SecurityEvent createKey = mapNth(5);

        assertThat(assumeRole.user().id()).isEqualTo("role:platform-deploy");
        assertThat(putPolicy.user().id()).isEqualTo("role:platform-deploy");
        assertThat(createKey.user().id()).isEqualTo("role:platform-deploy");

        // The session is preserved as evidence rather than folded into the identity.
        assertThat(assumeRole.labels()).containsEntry("assumed_role", "deploy-session-9931");
    }

    @Test
    void iamActionsMapOntoThePlatformVocabulary() throws IOException {
        assertThat(mapNth(3).event().action()).isEqualTo(EventAction.TOKEN_ISSUED);
        assertThat(mapNth(4).event().action()).isEqualTo(EventAction.ROLE_CHANGE);
        assertThat(mapNth(5).event().action()).isEqualTo(EventAction.API_KEY_USED);
        assertThat(mapNth(4).event().category()).isEqualTo(EventCategory.IAM);
    }

    /** An AccessDenied is a failure, and the reason carries the error code. */
    @Test
    void accessDeniedBecomesAFailureWithTheReasonAttached() throws IOException {
        SecurityEvent event = mapNth(6);

        assertThat(event.event().outcome()).isEqualTo(Outcome.FAILURE);
        assertThat(event.event().reason()).startsWith("AccessDenied");
        assertThat(event.event().reason()).contains("customer-pii");
    }

    /**
     * CloudTrail puts a service principal where an address belongs. Left in place it reaches a
     * Postgres `inet` column, the insert fails, and the whole batch dead-letters — on events
     * that are not malformed at all.
     */
    @Test
    void servicePrincipalIsNotTreatedAsASourceAddress() throws IOException {
        SecurityEvent event = mapNth(7);

        assertThat(event.source().ip()).isNull();
        assertThat(event.service().name()).isEqualTo("config.amazonaws.com");
        assertThat(event.user().id()).isEqualTo("service:config.amazonaws.com");
    }

    /**
     * An unmapped API name stays UNKNOWN and keeps its exact name in labels. Forcing a mapping
     * would make rules fire on unrelated AWS calls with no way to tell which.
     */
    @Test
    void unmappedApiNamesStayUnknownAndKeepTheirName() throws IOException {
        SecurityEvent event = mapNth(8);

        assertThat(event.event().action()).isEqualTo(EventAction.UNKNOWN);
        assertThat(event.labels()).containsEntry("cloud_event_name", "DeleteTrail");
    }

    @Test
    void everySampleRecordProducesAnEventTheConsumerWillAccept() throws IOException {
        List<JsonNode> all = new java.util.ArrayList<>();
        records().forEach(all::add);

        assertThat(all).isNotEmpty();
        for (JsonNode record : all) {
            SecurityEvent event = mapper.map(record);
            // The consumer's validation rules: timestamp, event.id and user.id are required,
            // and anything missing them is dead-lettered.
            assertThat(event).isNotNull();
            assertThat(event.event().id()).isNotBlank();
            assertThat(event.user().id()).isNotBlank();
            assertThat(event.labels()).containsEntry("cloud_provider", "aws");

            // The timestamp must be the record's eventTime exactly — not the ingest time.
            // Substituting now() when parsing fails would be far worse than dead-lettering:
            // the event would land in the wrong detection window and look perfectly fine.
            //
            // Deliberately not asserting the time is in the past. These are fixed sample
            // records, and a real trail can legitimately deliver an event stamped slightly
            // ahead of the consumer's clock.
            assertThat(event.timestamp())
                    .isEqualTo(Instant.parse(record.get("eventTime").asText()));
        }
    }

    @Test
    void cloudTrailEventIdIsUsedAsTheDedupeKey() throws IOException {
        // CloudTrail delivery is at-least-once, so an S3 object processed twice must dedupe
        // rather than double-count.
        assertThat(mapNth(0).event().id()).isEqualTo("b1a7e1c4-0001-4f1a-9c11-1a2b3c4d5e01");
    }

    @Test
    void returnsNullForRecordsThatAreNotCloudTrailAtAll() {
        assertThat(mapper.map(null)).isNull();
        assertThat(mapper.map(json.createObjectNode())).isNull();
    }
}
