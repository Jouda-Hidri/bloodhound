package io.bloodhound.consumer.api;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Read-only views over the raw store, so the pipeline can be checked without opening psql.
 *
 * <p>These are not detections. They are the queries you would write by hand while exploring the
 * data — the ones that turn into detections in Month 3 once you know what normal looks like.
 */
@RestController
@RequestMapping("/events")
public class EventQueryController {

    private final JdbcTemplate jdbc;

    public EventQueryController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Overall ingest health: volume, time span, and pipeline lag. */
    @GetMapping("/stats")
    public Map<String, Object> stats() {
        return jdbc.queryForMap("""
                select
                    count(*)                                            as total_events,
                    count(distinct user_id)                             as distinct_users,
                    count(distinct source_ip)                           as distinct_source_ips,
                    min(ts)                                             as earliest_event,
                    max(ts)                                             as latest_event,
                    round(avg(extract(epoch from (ingested_at - ts)))::numeric, 3) as avg_lag_seconds
                from raw_events
                where ts > now() - interval '24 hours'
                """);
    }

    /** Most recent events, newest first. */
    @GetMapping("/recent")
    public List<Map<String, Object>> recent(@RequestParam(defaultValue = "20") int limit) {
        return jdbc.queryForList("""
                -- source_ip is cast to text: the JDBC driver hands `inet` back as a PGobject,
                -- which serialises to JSON as a type wrapper rather than an address string.
                select ts, user_id, event_action, event_outcome,
                       host(source_ip) as source_ip, source_country, event_reason
                from raw_events
                where ts > now() - interval '24 hours'
                order by ts desc
                limit ?
                """, Math.min(Math.max(limit, 1), 500));
    }

    /**
     * Failed logins grouped by account over a sliding window — the raw material of a brute-force
     * detection. Note it counts distinct source IPs too: one IP is a stuck client, many IPs
     * against one account is something else.
     */
    @GetMapping("/failed-logins")
    public List<Map<String, Object>> failedLogins(@RequestParam(defaultValue = "15") int minutes,
                                                  @RequestParam(defaultValue = "5") int threshold) {
        return jdbc.queryForList("""
                select
                    user_id,
                    count(*)                  as failures,
                    count(distinct source_ip) as distinct_sources,
                    min(ts)                   as first_attempt,
                    max(ts)                   as last_attempt,
                    -- string_agg, not array_agg: the driver returns a SQL array as a PgArray
                    -- that holds a live ResultSet, and serialising it drags in the whole
                    -- JDBC connection. host() strips the /32 that inet::text appends.
                    string_agg(distinct host(source_ip), ',') as sources
                from raw_events
                where event_action = 'user-login'
                  and event_outcome = 'failure'
                  and ts > now() - make_interval(mins => ?)
                group by user_id
                having count(*) >= ?
                order by failures desc
                limit 50
                """, Math.max(minutes, 1), Math.max(threshold, 1));
    }

    /**
     * The credential-stuffing view: one source touching many distinct accounts.
     * Same underlying data as above, pivoted on source instead of user.
     */
    @GetMapping("/noisy-sources")
    public List<Map<String, Object>> noisySources(@RequestParam(defaultValue = "15") int minutes,
                                                  @RequestParam(defaultValue = "10") int threshold) {
        return jdbc.queryForList("""
                select
                    host(source_ip)                    as source_ip,
                    source_country,
                    count(*)                           as attempts,
                    count(distinct user_id)            as distinct_users,
                    count(*) filter (where event_outcome = 'success') as successes,
                    max(ts)                            as last_seen
                from raw_events
                where event_action = 'user-login'
                  and ts > now() - make_interval(mins => ?)
                group by source_ip, source_country
                having count(distinct user_id) >= ?
                order by distinct_users desc
                limit 50
                """, Math.max(minutes, 1), Math.max(threshold, 1));
    }

    /** Storage layout: confirms partitioning is doing what you think it is. */
    @GetMapping("/partitions")
    public List<Map<String, Object>> partitions() {
        return jdbc.queryForList("""
                select
                    c.relname                                   as partition,
                    pg_size_pretty(pg_total_relation_size(c.oid)) as size,
                    c.reltuples::bigint                         as approx_rows
                from pg_class c
                join pg_inherits i on i.inhrelid = c.oid
                join pg_class p on p.oid = i.inhparent
                where p.relname = 'raw_events'
                order by c.relname
                """);
    }
}
