package io.bloodhound.responder.response;

import io.bloodhound.responder.config.ResponderProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Calls the lab IAM service to actually contain something.
 *
 * <p>This is the only code in the platform that changes the outside world. Everything else reads,
 * scores, and records. Keeping that boundary to one small class is deliberate: it is the class to
 * read first when asking "what can this system actually do to me?"
 */
@Component
public class LabIamClient {

    private static final Logger log = LoggerFactory.getLogger(LabIamClient.class);

    private final ResponderProperties props;
    private final HttpClient http;

    public LabIamClient(ResponderProperties props) {
        this.props = props;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(props.getResponse().getIamTimeoutSeconds()))
                .build();
    }

    public ActionOutcome disableAccount(String userId, String reason) {
        return post("/iam/accounts/" + enc(userId) + "/disable", reason);
    }

    public ActionOutcome enableAccount(String userId) {
        return post("/iam/accounts/" + enc(userId) + "/enable", "reverted by responder");
    }

    public ActionOutcome revokeSessions(String userId, String reason) {
        return post("/iam/accounts/" + enc(userId) + "/revoke-sessions", reason);
    }

    private ActionOutcome post(String path, String reason) {
        String url = props.getResponse().getIamUrl() + path
                + "?reason=" + enc(reason) + "&actor=bloodhound-responder";
        try {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .timeout(Duration.ofSeconds(props.getResponse().getIamTimeoutSeconds()))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 == 2) {
                return new ActionOutcome(true, response.body(), null);
            }
            // A 4xx from IAM usually means it refused — an account outside the lab domain, or one
            // that does not exist. That is the safety check working, not a transport failure, and
            // it must not be retried.
            return new ActionOutcome(false, null,
                    "IAM returned " + response.statusCode() + ": " + response.body());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ActionOutcome(false, null, "interrupted");
        } catch (Exception e) {
            // Containment that fails silently is worse than no containment: the operator believes
            // the account is locked. Surfacing the error keeps the action in a failed state where
            // somebody has to deal with it.
            log.error("IAM call to {} failed", path, e);
            return new ActionOutcome(false, null, e.toString());
        }
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public record ActionOutcome(boolean success, String result, String error) {}
}
