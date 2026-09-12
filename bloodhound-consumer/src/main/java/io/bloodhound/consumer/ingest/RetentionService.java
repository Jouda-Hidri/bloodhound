package io.bloodhound.consumer.ingest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Drops event partitions past their retention window.
 *
 * <p>Retention on a security platform is a policy decision disguised as an operational one:
 * whatever you drop, you can no longer investigate. The default here is short because this is a
 * laptop; a real deployment would keep raw events for months and archive rather than delete.
 *
 * <p>Runs daily rather than hourly. Retention that runs often is retention that deletes something
 * unexpected quickly, and there is no undo.
 */
@Service
public class RetentionService {

    private static final Logger log = LoggerFactory.getLogger(RetentionService.class);

    private final JdbcTemplate jdbc;
    private final IngestProperties props;

    public RetentionService(JdbcTemplate jdbc, IngestProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    @Scheduled(cron = "${bloodhound.ingest.retention-cron:0 30 3 * * *}")
    public void enforceRetention() {
        if (!props.isRetentionEnabled()) {
            return;
        }
        List<Map<String, Object>> dropped = run(props.getRetainDays(), false);
        if (!dropped.isEmpty()) {
            log.warn("Retention dropped {} partitions older than {} days: {}",
                    dropped.size(), props.getRetainDays(),
                    dropped.stream().map(row -> row.get("partition_name")).toList());
        }
    }

    /** @param dryRun when true, lists what would be dropped without dropping anything. */
    public List<Map<String, Object>> run(int retainDays, boolean dryRun) {
        return jdbc.queryForList(
                "select * from drop_old_event_partitions(?, ?)", retainDays, dryRun);
    }
}
