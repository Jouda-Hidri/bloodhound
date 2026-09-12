package io.bloodhound.detector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "bloodhound.detector")
public class DetectorProperties {

    /** Optional directory of extra rule YAML files, loaded on top of the bundled ones. */
    private String rulesDir;

    /** Countries a login from is treated as a travel anomaly regardless of speed. */
    private ImpossibleTravel impossibleTravel = new ImpossibleTravel();

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
