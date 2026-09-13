package io.bloodhound.common.baseline;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * What normal looks like for one account.
 *
 * <p>Threshold rules ask "is this a lot?". A baseline lets a rule ask "is this a lot
 * <em>for them</em>", which is the difference between a detection that works on the median
 * account and one that works on the whole population. Measured on this data, the 95th percentile
 * account is 4.2× the median — so any single fixed threshold is either blind for the busy
 * accounts or noisy for the quiet ones.
 *
 * <p>Computed as a batch job (analytics/baseline.py) and published to a compacted Kafka topic.
 * Deliberately <em>not</em> queried from Postgres at detection time: a per-event database lookup
 * on the hot path is how a stream processor acquires a latency problem it cannot debug.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserBaseline(

        @JsonProperty("user_id") String userId,
        @JsonProperty("computed_at") Instant computedAt,
        @JsonProperty("window_days") Integer windowDays,

        @JsonProperty("total_events") Long totalEvents,
        @JsonProperty("logins") Long logins,
        @JsonProperty("login_failures") Long loginFailures,
        @JsonProperty("failure_rate") Double failureRate,
        @JsonProperty("events_per_day") Double eventsPerDay,

        /** Every country this account has been seen from in the baseline window. */
        @JsonProperty("countries") Set<String> countries,
        @JsonProperty("primary_country") String primaryCountry,

        @JsonProperty("distinct_source_ips") Integer distinctSourceIps,

        /** Every user agent seen. Small for a person, larger for a service account. */
        @JsonProperty("user_agents") Set<String> userAgents,

        /** UTC hours in which this account is normally active. */
        @JsonProperty("active_hours") List<Integer> activeHours,
        @JsonProperty("peak_hour") Integer peakHour,

        @JsonProperty("dormant_days") Double dormantDays
) {

    /**
     * Is this country one the account has been seen from before?
     *
     * <p>Returns true when the baseline has no country data at all. An account with no history
     * is unknown, not anomalous, and treating "we have never computed a baseline for you" as
     * evidence of compromise would flag every new joiner on their first day.
     */
    public boolean isKnownCountry(String country) {
        if (country == null || countries == null || countries.isEmpty()) {
            return true;
        }
        return countries.contains(country);
    }

    public boolean isKnownUserAgent(String userAgent) {
        if (userAgent == null || userAgents == null || userAgents.isEmpty()) {
            return true;
        }
        return userAgents.contains(userAgent);
    }

    /** Is this hour one the account is normally active in? */
    public boolean isActiveHour(int hourUtc) {
        return activeHours == null || activeHours.isEmpty() || activeHours.contains(hourUtc);
    }

    /**
     * How many times the account's usual daily volume a given count represents.
     *
     * <p>Guarded against a zero or missing baseline: an account with no history returns 1.0
     * (entirely normal) rather than infinity.
     */
    public double volumeRatio(long eventsToday) {
        if (eventsPerDay == null || eventsPerDay <= 0.5) {
            return 1.0;
        }
        return eventsToday / eventsPerDay;
    }

    /** Dormant accounts reactivating are a classic takeover signal. */
    public boolean isDormant(double thresholdDays) {
        return dormantDays != null && dormantDays >= thresholdDays;
    }
}
