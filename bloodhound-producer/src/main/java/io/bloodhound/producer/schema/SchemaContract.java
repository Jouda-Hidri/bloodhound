package io.bloodhound.producer.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.Topics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Registers the event schema and refuses to start if it breaks the existing contract.
 *
 * <p><b>What this buys.</b> A producer and a consumer that deploy independently have an implicit
 * contract, and implicit contracts are broken by accident. Renaming {@code user.id} is a one-line
 * change that compiles cleanly, passes tests, and silently blinds every per-user detection in
 * production. The registry turns that into a startup failure on the machine of the person who
 * made the change.
 *
 * <p><b>BACKWARD compatibility</b> is the mode set here: a consumer running the previous schema
 * must still be able to read data written under the new one. That permits adding optional fields
 * and forbids removing or renaming required ones — exactly the asymmetry you want when consumers
 * upgrade after producers.
 *
 * <p><b>The schema is a closed content model</b> ({@code additionalProperties: false} on every
 * object), and that is load-bearing rather than stylistic. With an open model the compatibility
 * checker inverts:
 *
 * <pre>
 *   additionalProperties: true         additionalProperties: false
 *   ---------------------------        ---------------------------
 *   add optional field  → BREAKING     add optional field  → compatible
 *   remove required     → compatible   remove required     → BREAKING
 * </pre>
 *
 * <p>The open-model results are technically correct and completely useless: an open schema already
 * accepts anything, so adding a typed property <em>narrows</em> what it will accept, while
 * dropping a requirement widens it. Left open, the check would wave through exactly the change
 * that blinds every downstream detection, and reject the harmless one. This is the sharpest edge
 * in JSON Schema compatibility and it is entirely silent — the registry answers confidently
 * either way.
 *
 * <p>Note the deliberate asymmetry with the consumer, which sets
 * {@code FAIL_ON_UNKNOWN_PROPERTIES = false} and happily ignores fields it does not know. That is
 * not a contradiction: the registry is a <em>deploy-time</em> gate on what we agree to publish,
 * while the consumer is <em>runtime</em>-lenient so that a misbehaving producer cannot take
 * ingestion down. Strict about what you send, tolerant in what you accept.
 *
 * <p><b>Why JSON Schema rather than Avro.</b> Avro is more compact and stricter, and the honest
 * reason it is not used here is debuggability: {@code rpk topic consume} on an Avro topic prints
 * binary, and during development being able to read the wire format by eye is worth more than the
 * bytes saved. The registry enforces the contract either way; the encoding is a separable choice,
 * and switching later touches only the serialiser. See docs/decisions/0003-schema-contracts.md.
 *
 * <p>Failing to reach the registry is a warning, not a failure. The registry is a development-time
 * guardrail; making it a hard runtime dependency would mean a registry outage stops security
 * telemetry, which is a far worse failure than an unverified schema.
 */
@Component
public class SchemaContract {

    private static final Logger log = LoggerFactory.getLogger(SchemaContract.class);

    /** Confluent/Redpanda convention: one subject per topic, suffixed by which half it describes. */
    private static final String SUBJECT = Topics.RAW_EVENTS + "-value";

    private final SchemaRegistryProperties props;
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public SchemaContract(SchemaRegistryProperties props) {
        this.props = props;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void registerAndVerify() {
        if (!props.isEnabled()) {
            log.info("Schema registry check disabled");
            return;
        }

        String schema;
        try {
            schema = new String(new ClassPathResource("schema/security-event.schema.json")
                    .getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Could not read the bundled event schema", e);
        }

        String body;
        try {
            body = mapper.writeValueAsString(Map.of("schemaType", "JSON", "schema", schema));
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the registry request", e);
        }

        try {
            setCompatibilityMode();

            if (!isCompatible(body)) {
                // This is the whole point of the exercise. Starting anyway would publish events
                // that older consumers cannot read, and the damage would only surface downstream,
                // hours later, as detections quietly matching nothing.
                throw new IllegalStateException(
                        "Event schema is INCOMPATIBLE with the registered version of subject '"
                        + SUBJECT + "'. Backward compatibility allows adding optional fields; it "
                        + "forbids removing or renaming required ones. Either restore the field, "
                        + "or register a new subject and migrate consumers first.");
            }

            int version = register(body);
            log.info("Event schema registered as {} version {} (compatibility: {})",
                    SUBJECT, version, props.getCompatibility());

        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Schema registry at {} unreachable ({}). Publishing without contract "
                    + "verification — this is a development guardrail, not a runtime dependency.",
                    props.getUrl(), e.toString());
        }
    }

    private void setCompatibilityMode() throws Exception {
        send(HttpRequest.newBuilder()
                .uri(URI.create(props.getUrl() + "/config/" + SUBJECT))
                .header("Content-Type", "application/vnd.schemaregistry.v1+json")
                .PUT(HttpRequest.BodyPublishers.ofString(
                        "{\"compatibility\":\"" + props.getCompatibility() + "\"}"))
                .build());
    }

    private boolean isCompatible(String body) throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(props.getUrl()
                        + "/compatibility/subjects/" + SUBJECT + "/versions/latest"))
                .header("Content-Type", "application/vnd.schemaregistry.v1+json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());

        // 404 means nothing is registered yet — the first deploy is compatible by definition.
        if (response.statusCode() == 404) {
            return true;
        }
        if (response.statusCode() / 100 != 2) {
            log.warn("Compatibility check returned {}: {}", response.statusCode(), response.body());
            return true;
        }
        JsonNode json = mapper.readTree(response.body());
        return !json.has("is_compatible") || json.get("is_compatible").asBoolean();
    }

    private int register(String body) throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(props.getUrl() + "/subjects/" + SUBJECT + "/versions"))
                .header("Content-Type", "application/vnd.schemaregistry.v1+json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());

        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    "Registry rejected the schema (" + response.statusCode() + "): " + response.body());
        }
        JsonNode json = mapper.readTree(response.body());
        return json.has("id") ? json.get("id").asInt() : -1;
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
