package io.bloodhound.producer.sim;

import io.bloodhound.common.event.EventAction;
import io.bloodhound.common.event.EventCategory;
import io.bloodhound.common.event.Outcome;
import io.bloodhound.common.event.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Builds well-formed {@link SecurityEvent}s. The only place events are constructed. */
@Component
public class EventFactory {

    private final SimulationProperties props;

    public EventFactory(SimulationProperties props) {
        this.props = props;
    }

    public Builder forUser(SimulatedUser user) {
        return new Builder(user, props);
    }

    public static final class Builder {

        private final SimulationProperties props;
        private final SimulatedUser user;

        private Instant timestamp = Instant.now();
        private EventCategory category = EventCategory.AUTHENTICATION;
        private EventAction action = EventAction.USER_LOGIN;
        private Outcome outcome = Outcome.SUCCESS;
        private String reason;
        private String sourceIp;
        private Integer sourcePort;
        private String country;
        private String city;
        private String userAgent;
        private Map<String, String> labels;

        private Builder(SimulatedUser user, SimulationProperties props) {
            this.user = user;
            this.props = props;
            this.country = user.homeCountry();
            this.city = user.homeCity();
            this.userAgent = user.userAgent();
        }

        public Builder at(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder category(EventCategory category) {
            this.category = category;
            return this;
        }

        public Builder action(EventAction action) {
            this.action = action;
            return this;
        }

        public Builder outcome(Outcome outcome) {
            this.outcome = outcome;
            return this;
        }

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder from(String ip, Integer port) {
            this.sourceIp = ip;
            this.sourcePort = port;
            return this;
        }

        public Builder geo(String country, String city) {
            this.country = country;
            this.city = city;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        /**
         * Ground truth for evaluating detections. A simulated attack tags its events
         * {@code scenario=...}; detections never read these labels, but the precision/recall
         * scoring in Week 11 does.
         */
        public Builder labels(Map<String, String> labels) {
            this.labels = labels;
            return this;
        }

        public SecurityEvent build() {
            return new SecurityEvent(
                    timestamp,
                    new SecurityEvent.EventInfo(
                            UUID.randomUUID().toString(), category, action, outcome, reason),
                    new SecurityEvent.UserInfo(user.id(), user.name(), user.domain()),
                    new SecurityEvent.SourceInfo(
                            sourceIp, sourcePort, new SecurityEvent.GeoInfo(country, city)),
                    new SecurityEvent.ServiceInfo(
                            props.getServiceName(), "0.1.0", props.getEnvironment()),
                    new SecurityEvent.UserAgentInfo(userAgent),
                    labels);
        }
    }
}
