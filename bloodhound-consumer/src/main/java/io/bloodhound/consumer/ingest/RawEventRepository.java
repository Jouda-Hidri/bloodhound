package io.bloodhound.consumer.ingest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.event.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.List;

/** Writes raw events into the partitioned {@code raw_events} table. */
@Repository
public class RawEventRepository {

    private static final Logger log = LoggerFactory.getLogger(RawEventRepository.class);

    private static final String INSERT = """
            insert into raw_events (
                event_id, ts, event_category, event_action, event_outcome, event_reason,
                user_id, user_name, user_domain,
                source_ip, source_port, source_country, source_city,
                service_name, service_environment, user_agent, labels, raw
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::inet, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb)
            on conflict (event_id, ts) do nothing
            """;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public RawEventRepository(JdbcTemplate jdbc, ObjectMapper eventObjectMapper) {
        this.jdbc = jdbc;
        this.mapper = eventObjectMapper;
    }

    /**
     * @return how many rows were genuinely new; the difference from {@code events.size()} is
     *         the duplicate count, which is a metric worth watching once replays start happening.
     */
    public int insertBatch(List<SecurityEvent> events) {
        int[] results = jdbc.batchUpdate(INSERT, new org.springframework.jdbc.core.BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                bind(ps, events.get(i));
            }

            @Override
            public int getBatchSize() {
                return events.size();
            }
        });

        int inserted = 0;
        for (int result : results) {
            if (result > 0) {
                inserted += result;
            }
        }
        return inserted;
    }

    private void bind(PreparedStatement ps, SecurityEvent e) throws SQLException {
        SecurityEvent.EventInfo event = e.event();
        SecurityEvent.UserInfo user = e.user();
        SecurityEvent.SourceInfo source = e.source();
        SecurityEvent.GeoInfo geo = source != null ? source.geo() : null;
        SecurityEvent.ServiceInfo service = e.service();
        SecurityEvent.UserAgentInfo agent = e.userAgent();

        int i = 1;
        ps.setString(i++, event.id());
        ps.setTimestamp(i++, Timestamp.from(e.timestamp()));
        ps.setString(i++, event.category() != null ? event.category().value() : null);
        ps.setString(i++, event.action() != null ? event.action().value() : null);
        ps.setString(i++, event.outcome() != null ? event.outcome().value() : null);
        ps.setString(i++, event.reason());
        ps.setString(i++, user != null ? user.id() : null);
        ps.setString(i++, user != null ? user.name() : null);
        ps.setString(i++, user != null ? user.domain() : null);
        ps.setString(i++, source != null ? source.ip() : null);
        setNullableInt(ps, i++, source != null ? source.port() : null);
        ps.setString(i++, geo != null ? geo.countryIsoCode() : null);
        ps.setString(i++, geo != null ? geo.cityName() : null);
        ps.setString(i++, service != null ? service.name() : null);
        ps.setString(i++, service != null ? service.environment() : null);
        ps.setString(i++, agent != null ? agent.original() : null);
        ps.setString(i++, toJson(e.labels()));
        // The full original document is kept alongside the extracted columns: columns are what
        // detections query, raw is what an investigator reads when a column turns out to be wrong.
        ps.setString(i, toJson(e));
    }

    private static void setNullableInt(PreparedStatement ps, int index, Integer value) throws SQLException {
        if (value == null) {
            ps.setNull(index, Types.INTEGER);
        } else {
            ps.setInt(index, value);
        }
    }

    private String toJson(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            log.warn("Could not serialise {} to JSON", value.getClass().getSimpleName(), ex);
            return null;
        }
    }
}
