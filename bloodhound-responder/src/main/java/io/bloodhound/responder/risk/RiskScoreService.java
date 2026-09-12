package io.bloodhound.responder.risk;

import io.bloodhound.common.alert.Alert;
import io.bloodhound.common.alert.EntityType;
import io.bloodhound.responder.config.ResponderProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * A decaying risk score per entity.
 *
 * <p>Individual alerts are a bad basis for decisions: most are individually unconvincing, and the
 * interesting entities are the ones setting off several different weak signals at once. A score
 * that accumulates across rules and fades with time turns "seven separate medium alerts" into one
 * ranked question — <em>who is currently the most suspicious thing in the estate?</em>
 *
 * <p>Decay is exponential with a configurable half-life, applied on read rather than by a sweeper.
 * On-read decay means the score is correct whenever anyone looks, including immediately after a
 * restart, and there is no background job to fall behind.
 */
@Service
public class RiskScoreService {

    private final JdbcTemplate jdbc;
    private final ResponderProperties props;

    public RiskScoreService(JdbcTemplate jdbc, ResponderProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    /**
     * Adds an alert's weight to its entity's score and returns the new value.
     *
     * <p>Repeat occurrences of the same alert add a sub-linear amount. The tenth firing of the
     * same rule against the same account is far less informative than the first, and letting
     * repeats add linearly would mean one chatty rule could drive an entity to maximum risk on
     * its own — which is exactly what a multi-signal score is supposed to prevent.
     */
    @Transactional
    public double add(Alert alert, int occurrence) {
        double weight = alert.severity().riskWeight();
        if (occurrence > 1) {
            weight = weight / Math.sqrt(occurrence);
        }
        return adjust(alert.entityType(), alert.entityId(), weight);
    }

    @Transactional
    public double adjust(EntityType entityType, String entityId, double delta) {
        Instant now = Instant.now();
        double current = currentScore(entityType, entityId, now);
        double updated = Math.min(props.getRisk().getMaxScore(), Math.max(0, current + delta));

        jdbc.update("""
                insert into risk_scores (entity_type, entity_id, score, peak_score, updated_at, peaked_at)
                values (?, ?, ?, ?, ?, ?)
                on conflict (entity_type, entity_id) do update
                set score = excluded.score,
                    updated_at = excluded.updated_at,
                    peak_score = greatest(risk_scores.peak_score, excluded.score),
                    peaked_at = case
                        when excluded.score > risk_scores.peak_score then excluded.updated_at
                        else risk_scores.peaked_at end
                """,
                entityType.value(), entityId, updated, updated,
                java.sql.Timestamp.from(now), java.sql.Timestamp.from(now));

        return updated;
    }

    /** The score as of now, with decay applied. */
    public double currentScore(EntityType entityType, String entityId) {
        return currentScore(entityType, entityId, Instant.now());
    }

    private double currentScore(EntityType entityType, String entityId, Instant now) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select score, updated_at from risk_scores where entity_type = ? and entity_id = ?",
                entityType.value(), entityId);
        if (rows.isEmpty()) {
            return 0;
        }
        double stored = ((Number) rows.get(0).get("score")).doubleValue();
        Instant updatedAt = ((java.sql.Timestamp) rows.get(0).get("updated_at")).toInstant();
        return decay(stored, Duration.between(updatedAt, now));
    }

    private double decay(double score, Duration elapsed) {
        if (elapsed.isNegative() || elapsed.isZero() || score <= 0) {
            return Math.max(0, score);
        }
        double halfLives = (double) elapsed.toSeconds() / props.getRisk().getHalfLife().toSeconds();
        double decayed = score * Math.pow(0.5, halfLives);
        // Below a point the residue is noise; zeroing it keeps "has no current risk" meaningful.
        return decayed < 0.5 ? 0 : decayed;
    }

    /** Highest current risk, decay applied, most suspicious first. */
    public List<Map<String, Object>> topRisk(int limit) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                select entity_type, entity_id, score, peak_score, updated_at, peaked_at
                from risk_scores
                where score > 0
                order by score desc
                limit ?
                """, Math.min(Math.max(limit, 1), 200));

        Instant now = Instant.now();
        return rows.stream().map(row -> {
            double stored = ((Number) row.get("score")).doubleValue();
            Instant updatedAt = ((java.sql.Timestamp) row.get("updated_at")).toInstant();
            double live = decay(stored, Duration.between(updatedAt, now));
            return Map.<String, Object>of(
                    "entityType", row.get("entity_type"),
                    "entityId", row.get("entity_id"),
                    "currentScore", Math.round(live * 10) / 10.0,
                    "storedScore", Math.round(stored * 10) / 10.0,
                    "peakScore", Math.round(((Number) row.get("peak_score")).doubleValue() * 10) / 10.0,
                    "lastAlertAt", row.get("updated_at"),
                    "peakedAt", String.valueOf(row.get("peaked_at")));
        })
        // Re-sort: decay can reorder entities relative to their stored scores.
        .sorted((a, b) -> Double.compare((Double) b.get("currentScore"), (Double) a.get("currentScore")))
        .filter(row -> (Double) row.get("currentScore") > 0)
        .toList();
    }
}
