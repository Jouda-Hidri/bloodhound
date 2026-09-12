package io.bloodhound.consumer.ingest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

/**
 * Keeps daily partitions created ahead of the data.
 *
 * <p>Partition maintenance is the boring operational chore that sinks a lot of first-time
 * partitioned tables: an insert for a day with no partition simply fails. Running it hourly and
 * at startup is enough at this size; in Month 4 this moves into the orchestrator alongside
 * retention (drop partitions older than N days).
 */
@Component
public class PartitionMaintenance {

    private static final Logger log = LoggerFactory.getLogger(PartitionMaintenance.class);

    private final JdbcTemplate jdbc;
    private final IngestProperties props;

    public PartitionMaintenance(JdbcTemplate jdbc, IngestProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Scheduled(cron = "0 5 * * * *")
    public void ensurePartitions() {
        LocalDate today = LocalDate.now();
        Integer created = jdbc.queryForObject(
                "select ensure_event_partitions(?::date, ?::date)",
                Integer.class,
                today.minusDays(1).toString(),
                today.plusDays(props.getPartitionDaysAhead()).toString());

        Long stranded = jdbc.queryForObject("select count(*) from raw_events_default", Long.class);
        if (stranded != null && stranded > 0) {
            log.warn("{} events landed in the default partition — their days can no longer be "
                    + "partitioned until they are moved out", stranded);
        }
        log.info("Partition maintenance: {} created, window +{}d", created, props.getPartitionDaysAhead());
    }
}
