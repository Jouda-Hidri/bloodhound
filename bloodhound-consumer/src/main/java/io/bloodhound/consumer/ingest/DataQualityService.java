package io.bloodhound.consumer.ingest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Periodic assertions about the data itself, recorded as a time series.
 *
 * <p>Pipelines rarely fail loudly. They fail by quietly delivering less, or delivering nulls, or
 * delivering yesterday's data — all of which look like "working" on a throughput dashboard. These
 * checks are the difference between a pipeline that is up and a pipeline that is correct.
 *
 * <p>Results are stored rather than only logged, because a single failing check is ambiguous and
 * a trend is not: "null rate has been climbing for three days" is actionable in a way that
 * "null rate is 4%" never is.
 */
@Service
public class DataQualityService {

    private static final Logger log = LoggerFactory.getLogger(DataQualityService.class);

    private static final String RECORD = """
            insert into data_quality_checks
                (check_name, category, passed, observed, threshold, detail)
            values (?, ?, ?, ?, ?, ?)
            """;

    private final JdbcTemplate jdbc;

    public DataQualityService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Scheduled(fixedRateString = "${bloodhound.ingest.quality-check-millis:300000}",
            initialDelay = 60_000L)
    public void runChecks() {
        List<Result> results = new ArrayList<>();

        // Freshness. The most important check there is: a pipeline that stopped an hour ago looks
        // perfectly healthy to any query that does not ask "how new is the newest row".
        results.add(check("freshness_seconds", Category.LIVENESS,
                scalar("select coalesce(extract(epoch from (now() - max(ts))), 999999) from raw_events"),
                BigDecimal.valueOf(300), Comparison.AT_MOST,
                "Seconds since the most recent event"));

        // Pipeline lag. Distinct from freshness: events can be arriving while being badly delayed.
        //
        // Simulated attacks are excluded. The attack simulator deliberately back-dates a burst
        // across the minutes it would really have taken — a 20-minute password spray is emitted
        // at once but timestamped over 20 minutes, which looks identical to 20 minutes of
        // pipeline lag. Including them made this check fail every time an attack was fired,
        // which is the worst kind of monitoring: a red light that means nothing, so nobody
        // looks at it. Measuring lag on organic traffic only keeps the signal honest.
        //
        // The `labels is null` predicate is the one place outside the scoring job that reads
        // simulation ground truth, and it is measuring the pipeline rather than detecting.
        results.add(check("max_lag_seconds", Category.LIVENESS,
                scalar("""
                        select coalesce(max(extract(epoch from (ingested_at - ts))), 0)
                        from raw_events
                        where ingested_at > now() - interval '10 minutes'
                          and labels is null
                        """),
                BigDecimal.valueOf(120), Comparison.AT_MOST,
                "Worst event-time to ingest-time gap in the last 10 minutes, organic traffic only"));

        // Attribution. An event with no user cannot be attributed, so per-user detections skip it
        // silently — the most dangerous kind of data loss, because nothing errors.
        results.add(check("null_user_rate", Category.CORRECTNESS,
                scalar("""
                        select coalesce(count(*) filter (where user_id is null)::numeric
                               / nullif(count(*), 0), 0)
                        from raw_events where ts > now() - interval '1 hour'
                        """),
                BigDecimal.valueOf(0.001), Comparison.AT_MOST,
                "Share of recent events with no user.id"));

        results.add(check("null_source_ip_rate", Category.CORRECTNESS,
                scalar("""
                        select coalesce(count(*) filter (where source_ip is null)::numeric
                               / nullif(count(*), 0), 0)
                        from raw_events where ts > now() - interval '1 hour'
                        """),
                BigDecimal.valueOf(0.01), Comparison.AT_MOST,
                "Share of recent events with no source.ip"));

        // Cardinality. A collapse here means a producer started sending a constant — for example
        // every event attributed to one service account after a bad deploy.
        //
        // Classified as liveness rather than correctness: with the producer stopped there are
        // simply no recent accounts, which says nothing about whether yesterday's stored data
        // is trustworthy. Treating it as correctness blocked the nightly archive every time
        // the simulator was paused.
        results.add(check("distinct_users_hourly", Category.LIVENESS,
                scalar("""
                        select count(distinct user_id)
                        from raw_events where ts > now() - interval '1 hour'
                        """),
                BigDecimal.valueOf(10), Comparison.AT_LEAST,
                "Distinct accounts seen in the last hour"));

        // Unknown actions. A steady trickle is fine; a spike means a producer is emitting
        // something the schema does not model, and detections are blind to it.
        results.add(check("unknown_action_rate", Category.CORRECTNESS,
                scalar("""
                        select coalesce(count(*) filter (where event_action = 'unknown')::numeric
                               / nullif(count(*), 0), 0)
                        from raw_events where ts > now() - interval '1 hour'
                        """),
                BigDecimal.valueOf(0.01), Comparison.AT_MOST,
                "Share of recent events whose action did not map to a known value"));

        // The dead letter backlog is itself a data quality signal.
        results.add(check("dead_letters_last_hour", Category.CORRECTNESS,
                scalar("select count(*) from dead_letters where failed_at > now() - interval '1 hour'"),
                BigDecimal.ZERO, Comparison.AT_MOST,
                "Messages dead-lettered in the last hour"));

        // Rows stranded in the default partition block that day from ever being partitioned.
        results.add(check("default_partition_rows", Category.CORRECTNESS,
                scalar("select count(*) from raw_events_default"),
                BigDecimal.ZERO, Comparison.AT_MOST,
                "Events whose timestamp fell outside every daily partition"));

        for (Result result : results) {
            jdbc.update(RECORD, result.name(), result.category().value(), result.passed(),
                    result.observed(), result.threshold(), result.detail());
        }

        List<String> failures = results.stream().filter(r -> !r.passed()).map(Result::name).toList();
        if (!failures.isEmpty()) {
            log.warn("Data quality checks failing: {}", failures);
        }
    }

    public List<Map<String, Object>> latest() {
        return jdbc.queryForList("""
                select distinct on (check_name)
                    check_name, category, checked_at, passed, observed, threshold, detail
                from data_quality_checks
                order by check_name, checked_at desc
                """);
    }

    private BigDecimal scalar(String sql) {
        BigDecimal value = jdbc.queryForObject(sql, BigDecimal.class);
        return value == null ? BigDecimal.ZERO : value;
    }

    private static Result check(String name, Category category, BigDecimal observed,
                                BigDecimal threshold, Comparison comparison, String detail) {
        boolean passed = comparison == Comparison.AT_MOST
                ? observed.compareTo(threshold) <= 0
                : observed.compareTo(threshold) >= 0;
        return new Result(name, category, passed, observed, threshold, detail);
    }

    private enum Comparison { AT_MOST, AT_LEAST }

    /**
     * What kind of question a check answers.
     *
     * <p>The distinction is what lets automation act on the results. {@link #LIVENESS} failing
     * means data is not arriving — an incident, but no reason to stop archiving yesterday, which
     * is complete either way. {@link #CORRECTNESS} failing means the data that did arrive cannot
     * be trusted, and archiving it only makes a permanent copy of the problem.
     *
     * <p>Without this, the orchestrator has to hard-code which check names to ignore, and that
     * list goes stale the moment somebody adds a check.
     */
    public enum Category {
        LIVENESS("liveness"),
        CORRECTNESS("correctness");

        private final String value;

        Category(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    private record Result(String name, Category category, boolean passed, BigDecimal observed,
                          BigDecimal threshold, String detail) {}
}
