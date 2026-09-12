package io.bloodhound.producer.sim;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.List;

/** Knobs for the traffic simulator, bound from {@code bloodhound.sim.*}. */
@ConfigurationProperties(prefix = "bloodhound.sim")
public class SimulationProperties {

    /** Whether background "normal" traffic is generated at all. */
    private boolean enabled = true;

    /** Size of the synthetic user population. */
    private int userCount = 200;

    /** Roughly how many events per second the normal-traffic generator emits. */
    private int eventsPerSecond = 20;

    /** Share of login attempts that fail for ordinary reasons (fat fingers, expired passwords). */
    private double baselineFailureRate = 0.06;

    /** Deterministic seed so two runs produce the same population. Change it to reshuffle. */
    private long seed = 1337L;

    /** Name reported in {@code service.name}. */
    private String serviceName = "payment-api";

    /** Name reported in {@code service.environment}. */
    private String environment = "lab";

    @NestedConfigurationProperty
    private Adversary adversary = new Adversary();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getUserCount() {
        return userCount;
    }

    public void setUserCount(int userCount) {
        this.userCount = userCount;
    }

    public int getEventsPerSecond() {
        return eventsPerSecond;
    }

    public void setEventsPerSecond(int eventsPerSecond) {
        this.eventsPerSecond = eventsPerSecond;
    }

    public double getBaselineFailureRate() {
        return baselineFailureRate;
    }

    public void setBaselineFailureRate(double baselineFailureRate) {
        this.baselineFailureRate = baselineFailureRate;
    }

    public long getSeed() {
        return seed;
    }

    public void setSeed(long seed) {
        this.seed = seed;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    public Adversary getAdversary() {
        return adversary;
    }

    public void setAdversary(Adversary adversary) {
        this.adversary = adversary;
    }

    /** Settings for the background attacker. */
    public static class Adversary {

        /** Off by default: a fresh clone should produce clean traffic until you ask for attacks. */
        private boolean enabled = false;

        /**
         * Probability that any given tick fires a scenario. 0.25 at the default 20s tick works
         * out to roughly one attack every 80 seconds, unevenly spaced.
         */
        private double intensity = 0.25;

        /** How often to consider firing. Also settable via bloodhound.sim.adversary.tick-millis. */
        private long tickMillis = 20_000L;

        /** Restrict to a subset of scenarios. Empty means all of them. */
        private List<String> scenarios = List.of();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public double getIntensity() {
            return intensity;
        }

        public void setIntensity(double intensity) {
            this.intensity = Math.max(0.0, Math.min(1.0, intensity));
        }

        public long getTickMillis() {
            return tickMillis;
        }

        public void setTickMillis(long tickMillis) {
            this.tickMillis = tickMillis;
        }

        public List<String> getScenarios() {
            return scenarios;
        }

        public void setScenarios(List<String> scenarios) {
            this.scenarios = scenarios;
        }
    }
}
