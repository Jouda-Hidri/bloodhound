package io.bloodhound.responder.config;

import io.bloodhound.common.alert.Severity;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "bloodhound.responder")
public class ResponderProperties {

    private Alerts alerts = new Alerts();
    private Risk risk = new Risk();
    private Response response = new Response();
    private Auth auth = new Auth();

    public Alerts getAlerts() {
        return alerts;
    }

    public void setAlerts(Alerts alerts) {
        this.alerts = alerts;
    }

    public Risk getRisk() {
        return risk;
    }

    public void setRisk(Risk risk) {
        this.risk = risk;
    }

    public Response getResponse() {
        return response;
    }

    public void setResponse(Response response) {
        this.response = response;
    }

    public Auth getAuth() {
        return auth;
    }

    public void setAuth(Auth auth) {
        this.auth = auth;
    }

    public static class Alerts {

        /**
         * Repeats of the same rule/entity within this window fold into the existing alert.
         * Too short and the console fills with duplicates; too long and a genuinely new attack
         * hides inside an old alert's occurrence count.
         */
        private Duration suppressionWindow = Duration.ofMinutes(30);

        public Duration getSuppressionWindow() {
            return suppressionWindow;
        }

        public void setSuppressionWindow(Duration suppressionWindow) {
            this.suppressionWindow = suppressionWindow;
        }
    }

    public static class Risk {

        /**
         * Time for a risk score to halve with no new alerts.
         *
         * <p>Decay is what stops risk being a permanent mark against an entity. An account that
         * looked bad last Tuesday and has been quiet since should not still be treated as
         * suspicious — otherwise every score converges on "maximum" and the ranking stops
         * distinguishing anything.
         */
        private Duration halfLife = Duration.ofHours(6);

        /** Above this, an incident is opened. */
        private double incidentThreshold = 50;

        /** Above this, containment is proposed. */
        private double containmentThreshold = 90;

        /** Scores are capped so one noisy rule cannot push an entity permanently off the scale. */
        private double maxScore = 300;

        public Duration getHalfLife() {
            return halfLife;
        }

        public void setHalfLife(Duration halfLife) {
            this.halfLife = halfLife;
        }

        public double getIncidentThreshold() {
            return incidentThreshold;
        }

        public void setIncidentThreshold(double incidentThreshold) {
            this.incidentThreshold = incidentThreshold;
        }

        public double getContainmentThreshold() {
            return containmentThreshold;
        }

        public void setContainmentThreshold(double containmentThreshold) {
            this.containmentThreshold = containmentThreshold;
        }

        public double getMaxScore() {
            return maxScore;
        }

        public void setMaxScore(double maxScore) {
            this.maxScore = maxScore;
        }
    }

    public static class Response {

        /** Master switch. Off means actions are proposed and recorded but never executed. */
        private boolean enabled = true;

        /**
         * Execute approved-by-policy actions without a human.
         *
         * <p>Off by default, and that default is the important part. Automation that locks
         * accounts on its own is a denial-of-service primitive handed to anyone who can work out
         * what triggers it — spoof enough failed logins against a competitor's admin account and
         * the platform does the attacking for you.
         */
        private boolean autoExecute = false;

        /** Actions of at least this severity may be auto-executed when autoExecute is on. */
        private Severity autoExecuteMinSeverity = Severity.HIGH;

        /** Base URL of the lab IAM service that containment acts against. */
        private String iamUrl = "http://localhost:8101";

        private int iamTimeoutSeconds = 5;

        /**
         * Actions that never auto-execute regardless of configuration. Belt and braces: a
         * misconfiguration should not be able to enable unattended account lockout.
         */
        private Map<String, Boolean> alwaysRequireApproval = new LinkedHashMap<>(
                Map.of("disable_account", true));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isAutoExecute() {
            return autoExecute;
        }

        public void setAutoExecute(boolean autoExecute) {
            this.autoExecute = autoExecute;
        }

        public Severity getAutoExecuteMinSeverity() {
            return autoExecuteMinSeverity;
        }

        public void setAutoExecuteMinSeverity(Severity autoExecuteMinSeverity) {
            this.autoExecuteMinSeverity = autoExecuteMinSeverity;
        }

        public String getIamUrl() {
            return iamUrl;
        }

        public void setIamUrl(String iamUrl) {
            this.iamUrl = iamUrl;
        }

        public int getIamTimeoutSeconds() {
            return iamTimeoutSeconds;
        }

        public void setIamTimeoutSeconds(int iamTimeoutSeconds) {
            this.iamTimeoutSeconds = iamTimeoutSeconds;
        }

        public Map<String, Boolean> getAlwaysRequireApproval() {
            return alwaysRequireApproval;
        }

        public void setAlwaysRequireApproval(Map<String, Boolean> alwaysRequireApproval) {
            this.alwaysRequireApproval = alwaysRequireApproval;
        }
    }

    public static class Auth {

        /** Off makes every endpoint open — acceptable on a laptop, never anywhere else. */
        private boolean enabled = true;

        /**
         * API key → role. Lab-grade authentication: keys in config, compared in constant time,
         * no rotation, no expiry, no identity provider.
         *
         * <p>What it does get right is the part that matters for learning: least privilege.
         * Reading alerts and disabling an account are different capabilities, and the person
         * doing the first should not automatically be able to do the second.
         */
        private Map<String, String> keys = new LinkedHashMap<>(Map.of(
                "bh-viewer-key", "VIEWER",
                "bh-analyst-key", "ANALYST",
                "bh-responder-key", "RESPONDER"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Map<String, String> getKeys() {
            return keys;
        }

        public void setKeys(Map<String, String> keys) {
            this.keys = keys;
        }
    }
}
