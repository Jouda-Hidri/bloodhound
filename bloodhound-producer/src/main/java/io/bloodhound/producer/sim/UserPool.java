package io.bloodhound.producer.sim;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Collectors;

/** The synthetic account population. Built once at startup from a fixed seed. */
@Component
public class UserPool {

    private static final Logger log = LoggerFactory.getLogger(UserPool.class);

    private static final String[][] LOCATIONS = {
            {"DE", "Berlin"}, {"DE", "Munich"}, {"GR", "Athens"}, {"GR", "Thessaloniki"},
            {"NL", "Amsterdam"}, {"GB", "London"}, {"US", "New York"}, {"US", "Austin"},
            {"FR", "Paris"}, {"PL", "Warsaw"}
    };

    private static final String[] USER_AGENTS = {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1"
    };

    private static final String[] FIRST_NAMES = {
            "anna", "boris", "chloe", "dimitris", "elena", "felix", "giorgos", "hanna",
            "ilias", "julia", "kostas", "lena", "marek", "nora", "omar", "petra",
            "rafael", "sofia", "tomas", "vera"
    };

    private static final String[] LAST_NAMES = {
            "adams", "beck", "costa", "dupont", "engel", "fischer", "grant", "hoffman",
            "iverson", "jansen", "koch", "lambert", "moreau", "novak", "ortiz", "pappas"
    };

    private final SimulationProperties props;
    private List<SimulatedUser> users = List.of();
    private Map<String, SimulatedUser> byId = Map.of();
    private double[] cumulativeWeights = new double[0];

    public UserPool(SimulationProperties props) {
        this.props = props;
    }

    @PostConstruct
    void build() {
        Random rng = new Random(props.getSeed());
        List<SimulatedUser> generated = new ArrayList<>(props.getUserCount());

        for (int i = 0; i < props.getUserCount(); i++) {
            String[] location = LOCATIONS[rng.nextInt(LOCATIONS.length)];
            String name = FIRST_NAMES[rng.nextInt(FIRST_NAMES.length)]
                    + "." + LAST_NAMES[rng.nextInt(LAST_NAMES.length)];

            // One to three stable addresses — home, phone, maybe the office. Not a fresh address
            // per event: see the note on SimulatedUser.homeIps for why that mattered.
            // RFC 1918 space throughout: these are clearly lab addresses, never a real target.
            String prefix = "10.%d.%d".formatted(rng.nextInt(64), rng.nextInt(256));
            int addressCount = 1 + rng.nextInt(3);
            List<String> homeIps = new ArrayList<>(addressCount);
            for (int a = 0; a < addressCount; a++) {
                homeIps.add(prefix + "." + (1 + rng.nextInt(254)));
            }

            generated.add(new SimulatedUser(
                    "u-%05d".formatted(i),
                    name,
                    "bloodhound.lab",
                    location[0],
                    location[1],
                    List.copyOf(homeIps),
                    USER_AGENTS[rng.nextInt(USER_AGENTS.length)],
                    // Most accounts are quiet, a few are very busy. Real populations look like this,
                    // and a detection tuned on a uniform population falls apart on a skewed one.
                    Math.pow(rng.nextDouble(), 2.5) + 0.01
            ));
        }

        this.users = List.copyOf(generated);
        this.byId = users.stream().collect(Collectors.toMap(SimulatedUser::id, Function.identity()));
        this.cumulativeWeights = buildCumulativeWeights(users);

        log.info("Built simulated population: {} users, seed {}", users.size(), props.getSeed());
    }

    private static double[] buildCumulativeWeights(List<SimulatedUser> users) {
        double[] cumulative = new double[users.size()];
        double running = 0;
        for (int i = 0; i < users.size(); i++) {
            running += users.get(i).activityWeight();
            cumulative[i] = running;
        }
        return cumulative;
    }

    public List<SimulatedUser> all() {
        return users;
    }

    public Optional<SimulatedUser> byId(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    /** Picks a user weighted by how active they are, so traffic is realistically lopsided. */
    public SimulatedUser weightedRandom(java.util.random.RandomGenerator rng) {
        double total = cumulativeWeights[cumulativeWeights.length - 1];
        double target = rng.nextDouble() * total;
        int index = java.util.Arrays.binarySearch(cumulativeWeights, target);
        if (index < 0) {
            index = -index - 1;
        }
        return users.get(Math.min(index, users.size() - 1));
    }

    public SimulatedUser uniformRandom(java.util.random.RandomGenerator rng) {
        return users.get(rng.nextInt(users.size()));
    }
}
