package io.bloodhound.detector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "bloodhound.detector")
public class DetectorProperties {

    /** Optional directory of extra rule YAML files, loaded on top of the bundled ones. */
    private String rulesDir;

    /** Countries a login from is treated as a travel anomaly regardless of speed. */
    private ImpossibleTravel impossibleTravel = new ImpossibleTravel();

    private SessionHijack sessionHijack = new SessionHijack();

    private BaselineDeviation baselineDeviation = new BaselineDeviation();

    public String getRulesDir() {
        return rulesDir;
    }

    public void setRulesDir(String rulesDir) {
        this.rulesDir = rulesDir;
    }

    public ImpossibleTravel getImpossibleTravel() {
        return impossibleTravel;
    }

    public void setImpossibleTravel(ImpossibleTravel impossibleTravel) {
        this.impossibleTravel = impossibleTravel;
    }

    public SessionHijack getSessionHijack() {
        return sessionHijack;
    }

    public void setSessionHijack(SessionHijack sessionHijack) {
        this.sessionHijack = sessionHijack;
    }

    public BaselineDeviation getBaselineDeviation() {
        return baselineDeviation;
    }

    public void setBaselineDeviation(BaselineDeviation baselineDeviation) {
        this.baselineDeviation = baselineDeviation;
    }

    /** Settings for the session-hijack sequence detection. */
    public static class SessionHijack {

        private boolean enabled = true;

        /**
         * How long a session fingerprint stays comparable. Beyond this the stored address is
         * stale state rather than evidence.
         */
        private Duration sessionTtl = Duration.ofHours(8);

        /**
         * Activity within this long of issuance is ignored.
         *
         * <p>Clients legitimately appear to move immediately after authenticating — a proxy hop,
         * an IPv4/IPv6 switch, a mobile handover. Without a grace period this rule fires on
         * ordinary traffic constantly, which is the fastest way to get a detection muted.
         */
        private Duration graceAfterIssue = Duration.ofSeconds(20);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getSessionTtl() {
            return sessionTtl;
        }

        public void setSessionTtl(Duration sessionTtl) {
            this.sessionTtl = sessionTtl;
        }

        public Duration getGraceAfterIssue() {
            return graceAfterIssue;
        }

        public void setGraceAfterIssue(Duration graceAfterIssue) {
            this.graceAfterIssue = graceAfterIssue;
        }
    }

    /** Settings for baseline-relative detection. */
    public static class BaselineDeviation {

        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    public static class ImpossibleTravel {

        private boolean enabled = true;

        /**
         * Two successful logins from different countries closer together than this are treated as
         * impossible. One hour is crude — real implementations compute a required velocity from
         * geo-coordinates — and it is crude in a specific, documented direction: it flags VPN use
         * and corporate egress changes as travel.
         */
        private Duration maxPlausibleGap = Duration.ofHours(1);

        /** How long a user's last-login state is kept before it is forgotten. */
        private Duration stateRetention = Duration.ofDays(2);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getMaxPlausibleGap() {
            return maxPlausibleGap;
        }

        public void setMaxPlausibleGap(Duration maxPlausibleGap) {
            this.maxPlausibleGap = maxPlausibleGap;
        }

        public Duration getStateRetention() {
            return stateRetention;
        }

        public void setStateRetention(Duration stateRetention) {
            this.stateRetention = stateRetention;
        }
    }
}
