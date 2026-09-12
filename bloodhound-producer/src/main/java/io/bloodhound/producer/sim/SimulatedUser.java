package io.bloodhound.producer.sim;

import java.util.List;
import java.util.random.RandomGenerator;

/**
 * One synthetic account with a stable "normal" — home country, usual addresses, usual browser.
 *
 * <p>Detections in Month 3 are only meaningful if there is a baseline to deviate from, so the
 * population is generated once with a fixed seed and never changes within a run.
 */
public record SimulatedUser(
        String id,
        String name,
        String domain,
        String homeCountry,
        String homeCity,

        /**
         * The small set of addresses this account normally connects from — home, phone, office.
         *
         * <p>This started out as a single /24 with a fresh random host picked per event, which was
         * wrong in a way that took a detection firing to notice: it made every account look like
         * it was connecting from a new address every few seconds, and the distributed-brute-force
         * rule (5+ distinct sources against one account) fired constantly on ordinary users.
         *
         * <p>Real people have one or two addresses that change rarely. Simulated data that is
         * wrong in this direction does not just add noise — it makes source-diversity detections
         * untestable, because the baseline already looks like an attack.
         */
        List<String> homeIps,

        String userAgent,

        /** 0.0–1.0: how chatty this account is relative to the others. */
        double activityWeight
) {

    /** Probability that a given event comes from somewhere new — a café, a new phone, DHCP. */
    private static final double NEW_ADDRESS_CHANCE = 0.01;

    public String randomHomeIp(RandomGenerator rng) {
        if (rng.nextDouble() < NEW_ADDRESS_CHANCE) {
            // Same network, new host. Keeps a little genuine churn in the baseline so that
            // "this account used an address it has never used before" is not a perfect signal.
            String prefix = homeIps.get(0).substring(0, homeIps.get(0).lastIndexOf('.'));
            return prefix + "." + (1 + rng.nextInt(254));
        }
        return homeIps.get(rng.nextInt(homeIps.size()));
    }

    public String primaryIp() {
        return homeIps.get(0);
    }
}
