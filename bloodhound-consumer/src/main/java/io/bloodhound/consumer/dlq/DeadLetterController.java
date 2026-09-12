package io.bloodhound.consumer.dlq;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Inspect and replay dead letters. */
@RestController
@RequestMapping("/dlq")
public class DeadLetterController {

    private static final Logger log = LoggerFactory.getLogger(DeadLetterController.class);

    private final JdbcTemplate jdbc;
    private final KafkaTemplate<String, String> kafka;

    public DeadLetterController(JdbcTemplate jdbc, KafkaTemplate<String, String> kafka) {
        this.jdbc = jdbc;
        this.kafka = kafka;
    }

    @GetMapping("/summary")
    public List<Map<String, Object>> summary() {
        return jdbc.queryForList("""
                select failure_type,
                       count(*)              as messages,
                       min(failed_at)        as first_seen,
                       max(failed_at)        as last_seen,
                       count(*) filter (where replayed_at is not null) as replayed
                from dead_letters
                group by failure_type
                order by messages desc
                """);
    }

    @GetMapping
    public List<Map<String, Object>> list(@RequestParam(defaultValue = "20") int limit,
                                          @RequestParam(required = false) String failureType) {
        int capped = Math.min(Math.max(limit, 1), 200);
        if (failureType == null) {
            return jdbc.queryForList("""
                    select id, failed_at, failure_type, failure_reason,
                           source_topic, source_partition, source_offset,
                           replay_count, left(payload, 300) as payload_preview
                    from dead_letters order by failed_at desc limit ?
                    """, capped);
        }
        return jdbc.queryForList("""
                select id, failed_at, failure_type, failure_reason,
                       source_topic, source_partition, source_offset,
                       replay_count, left(payload, 300) as payload_preview
                from dead_letters where failure_type = ? order by failed_at desc limit ?
                """, failureType, capped);
    }

    /**
     * Republish dead letters to their original topic.
     *
     * <p>Replay is the whole point of keeping them. The usual sequence is: something breaks, the
     * DLQ fills, you fix the consumer, you replay. Because the events carry their original ids and
     * timestamps, replayed events land in their correct partitions and are deduplicated on arrival
     * — a replay is safe to run twice.
     *
     * <p>Replaying a message that is still broken simply produces a new dead letter, which is
     * correct: the backlog should not silently shrink because you retried without fixing anything.
     */
    @PostMapping("/replay")
    public Map<String, Object> replay(@RequestParam(required = false) String failureType,
                                      @RequestParam(defaultValue = "100") int limit,
                                      @RequestParam(defaultValue = "false") boolean includeReplayed) {
        int capped = Math.min(Math.max(limit, 1), 1000);

        StringBuilder sql = new StringBuilder(
                "select id, source_topic, source_key, payload from dead_letters where 1=1");
        List<Object> args = new java.util.ArrayList<>();
        if (failureType != null) {
            sql.append(" and failure_type = ?");
            args.add(failureType);
        }
        if (!includeReplayed) {
            sql.append(" and replayed_at is null");
        }
        sql.append(" order by failed_at asc limit ?");
        args.add(capped);

        List<Map<String, Object>> rows = jdbc.queryForList(sql.toString(), args.toArray());

        int republished = 0;
        for (Map<String, Object> row : rows) {
            try {
                kafka.send((String) row.get("source_topic"),
                        (String) row.get("source_key"),
                        (String) row.get("payload")).get();
                jdbc.update("""
                        update dead_letters
                        set replayed_at = now(), replay_count = replay_count + 1
                        where id = ?
                        """, row.get("id"));
                republished++;
            } catch (Exception e) {
                log.error("Replay failed for dead letter {}", row.get("id"), e);
                Thread.currentThread().interrupt();
                break;
            }
        }

        log.info("Replayed {} of {} candidate dead letters", republished, rows.size());
        return Map.of("candidates", rows.size(), "republished", republished);
    }
}
