package io.bloodhound.responder.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Append-only record of everything the platform and its operators do.
 *
 * <p>There is no update or delete path, by design. An audit log that can be edited answers no
 * question worth asking.
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private static final String INSERT = """
            insert into audit_log (actor, action, subject_type, subject_id, outcome, detail)
            values (?, ?, ?, ?, ?, ?::jsonb)
            """;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public AuditLog(JdbcTemplate jdbc, ObjectMapper eventObjectMapper) {
        this.jdbc = jdbc;
        this.mapper = eventObjectMapper;
    }

    public void record(String actor, String action, String subjectType, String subjectId,
                       String outcome, Map<String, ?> detail) {
        String json = null;
        try {
            json = detail == null ? null : mapper.writeValueAsString(detail);
        } catch (Exception e) {
            log.warn("Could not serialise audit detail for {}", action, e);
        }
        try {
            jdbc.update(INSERT, actor, action, subjectType, subjectId, outcome, json);
        } catch (RuntimeException e) {
            // Losing an audit entry is serious enough to say so loudly, but not serious enough to
            // fail the action that was already taken — that would leave the world changed and no
            // record either way.
            log.error("AUDIT WRITE FAILED actor={} action={} subject={}/{} outcome={}",
                    actor, action, subjectType, subjectId, outcome, e);
        }
    }

    public List<Map<String, Object>> recent(int limit) {
        return jdbc.queryForList("""
                select at, actor, action, subject_type, subject_id, outcome, detail
                from audit_log order by at desc limit ?
                """, Math.min(Math.max(limit, 1), 500));
    }

    public List<Map<String, Object>> forSubject(String subjectType, String subjectId) {
        return jdbc.queryForList("""
                select at, actor, action, outcome, detail
                from audit_log
                where subject_type = ? and subject_id = ?
                order by at desc limit 200
                """, subjectType, subjectId);
    }
}
