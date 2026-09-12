package io.bloodhound.responder.alerts;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.Topics;
import io.bloodhound.common.alert.Alert;
import io.bloodhound.responder.config.ResponderProperties;
import io.bloodhound.responder.incidents.IncidentService;
import io.bloodhound.responder.response.ResponseEngine;
import io.bloodhound.responder.risk.RiskScoreService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * The pipeline from alert to action.
 *
 * <pre>
 *   alert → deduplicate → score risk → open/attach incident → run playbook → audit
 * </pre>
 *
 * <p>Each step is deliberately separate and individually inspectable. The temptation in a system
 * like this is to collapse it into one "handle alert" method; keeping the seams means you can ask
 * "why did this account get locked" and get an answer at every stage rather than a shrug.
 */
@Component
public class AlertListener {

    private static final Logger log = LoggerFactory.getLogger(AlertListener.class);

    private final ObjectMapper mapper;
    private final AlertService alerts;
    private final RiskScoreService risk;
    private final IncidentService incidents;
    private final ResponseEngine response;
    private final ResponderProperties props;
    private final KafkaTemplate<String, String> kafka;
    private final Timer processingTimer;

    public AlertListener(ObjectMapper eventObjectMapper, AlertService alerts,
                         RiskScoreService risk, IncidentService incidents,
                         ResponseEngine response, ResponderProperties props,
                         KafkaTemplate<String, String> kafka, MeterRegistry meters) {
        this.mapper = eventObjectMapper;
        this.alerts = alerts;
        this.risk = risk;
        this.incidents = incidents;
        this.response = response;
        this.props = props;
        this.kafka = kafka;
        this.processingTimer = Timer.builder("bloodhound.alerts.processing")
                .description("Time to take one alert from Kafka through to response")
                .register(meters);
    }

    @KafkaListener(
            topics = Topics.ALERTS,
            groupId = "${bloodhound.responder.group-id:bloodhound-responder}",
            containerFactory = "alertListenerFactory")
    public void onBatch(List<ConsumerRecord<String, String>> records, Acknowledgment ack) {
        for (ConsumerRecord<String, String> record : records) {
            Timer.Sample sample = Timer.start();
            try {
                handle(mapper.readValue(record.value(), Alert.class));
            } catch (Exception e) {
                // One unprocessable alert must not stall triage for every other alert behind it.
                // It goes to the DLQ and the pipeline keeps moving.
                log.error("Could not process alert at {}-{}@{}",
                        record.topic(), record.partition(), record.offset(), e);
                deadLetter(record, e);
            } finally {
                sample.stop(processingTimer);
            }
        }
        ack.acknowledge();
    }

    private void handle(Alert alert) {
        AlertService.StoredAlert stored = alerts.record(alert);

        double score = risk.add(alert, stored.occurrences());

        // Incidents open on accumulated risk rather than on any single alert. A high-severity
        // alert is enough on its own; several mediums against the same entity also get there,
        // which is the entire point of scoring across rules.
        boolean warrantsIncident = score >= props.getRisk().getIncidentThreshold()
                || alert.severity().atLeast(io.bloodhound.common.alert.Severity.HIGH);

        Long incidentId = stored.incidentId();
        if (incidentId == null && warrantsIncident) {
            incidentId = incidents.openOrAttach(alert, stored.id(), score);
        } else if (incidentId != null) {
            incidents.openOrAttach(alert, stored.id(), score);
        }

        if (incidentId != null) {
            response.evaluate(alert, stored.id(), incidentId, score);
        }

        if (stored.isNew()) {
            log.info("Alert {} [{}] {} {}:{} observed={} threshold={} risk={}",
                    stored.id(), alert.severity().value(), alert.ruleId(),
                    alert.entityType().value(), alert.entityId(),
                    alert.observed(), alert.threshold(), Math.round(score));
        }
    }

    private void deadLetter(ConsumerRecord<String, String> record, Exception cause) {
        try {
            io.bloodhound.common.DeadLetter letter = new io.bloodhound.common.DeadLetter(
                    Instant.now(), record.topic(), record.partition(), record.offset(),
                    record.key(), io.bloodhound.common.DeadLetter.PARSE_ERROR,
                    String.valueOf(cause.getMessage()), "bloodhound-responder", record.value());
            kafka.send(Topics.ALERTS_DLQ, record.key(), mapper.writeValueAsString(letter));
        } catch (Exception e) {
            log.error("Could not dead-letter the alert either; it is lost", e);
        }
    }
}
