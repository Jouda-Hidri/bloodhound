package io.bloodhound.consumer.search;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bloodhound.common.event.SecurityEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Dual-writes events into OpenSearch for investigation queries.
 *
 * <p>Postgres is the system of record; OpenSearch is a derived index. That split is deliberate:
 * Postgres answers "count failures per user per window" far better, and OpenSearch answers "show
 * me everything mentioning this IP" far better. Trying to make one store do both jobs is how you
 * end up with a slow version of each.
 *
 * <p><b>Indexing is best-effort and off the ingest path.</b> If OpenSearch is down, slow, or
 * rejecting, events still land in Postgres and the pipeline keeps its lag. Blocking ingestion on
 * a derived index would mean an outage in the search tier becomes an outage in the pipeline of
 * record — the wrong failure to couple.
 *
 * <p>Written against the REST bulk API with the JDK HTTP client rather than the OpenSearch Java
 * client. One less dependency, and the wire format stays visible.
 */
@Component
public class EventIndexer {

    private static final Logger log = LoggerFactory.getLogger(EventIndexer.class);

    private static final DateTimeFormatter INDEX_DATE =
            DateTimeFormatter.ofPattern("yyyy.MM.dd").withZone(ZoneOffset.UTC);

    private final SearchProperties props;
    private final ObjectMapper mapper;
    private final HttpClient http;
    private final ExecutorService workers;
    private final Counter indexed;
    private final Counter failed;
    private final Counter dropped;

    private static final int TEMPLATE_RETRY_SECONDS = 30;

    private volatile boolean available;
    private volatile long lastTemplateAttemptNanos;

    public EventIndexer(SearchProperties props, ObjectMapper eventObjectMapper, MeterRegistry meters) {
        this.props = props;
        this.mapper = eventObjectMapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(props.getTimeoutSeconds()))
                .build();
        // Bounded queue with CallerRuns deliberately *not* used: if indexing falls behind we drop
        // batches rather than slow the consumer down. Losing search coverage is recoverable by
        // reindexing from Postgres; falling behind on ingest is not.
        this.workers = new ThreadPoolExecutor(1, 2, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(50),
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy());
        this.indexed = Counter.builder("bloodhound.search.indexed").register(meters);
        this.failed = Counter.builder("bloodhound.search.failed").register(meters);
        this.dropped = Counter.builder("bloodhound.search.dropped")
                .description("Batches dropped because the indexer was saturated").register(meters);
        this.available = props.isEnabled();
    }

    @PostConstruct
    void createIndexTemplate() {
        if (!props.isEnabled()) {
            log.info("OpenSearch indexing disabled");
            return;
        }
        try {
            // Explicit mappings, not dynamic. Left to guess, OpenSearch would type source.ip as a
            // string and make CIDR queries impossible, and would create a field for every new key
            // that ever appears — a mapping explosion is a real way to take a cluster down.
            String template = """
                    {
                      "index_patterns": ["%s-*"],
                      "template": {
                        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                        "mappings": {
                          "properties": {
                            "@timestamp":  {"type": "date"},
                            "ingested_at": {"type": "date"},
                            "event": {"properties": {
                              "id":       {"type": "keyword"},
                              "category": {"type": "keyword"},
                              "action":   {"type": "keyword"},
                              "outcome":  {"type": "keyword"},
                              "reason":   {"type": "text"}}},
                            "user": {"properties": {
                              "id":     {"type": "keyword"},
                              "name":   {"type": "keyword"},
                              "domain": {"type": "keyword"}}},
                            "source": {"properties": {
                              "ip":   {"type": "ip"},
                              "port": {"type": "integer"},
                              "geo":  {"properties": {
                                "country_iso_code": {"type": "keyword"},
                                "city_name":        {"type": "keyword"}}}}},
                            "service": {"properties": {
                              "name":        {"type": "keyword"},
                              "environment": {"type": "keyword"}}},
                            "user_agent": {"properties": {
                              "original": {"type": "keyword"}}},
                            "labels": {"type": "object", "enabled": true}
                          }
                        }
                      }
                    }
                    """.formatted(props.getIndexPrefix());

            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(props.getUrl() + "/_index_template/bloodhound-events"))
                            .timeout(Duration.ofSeconds(props.getTimeoutSeconds()))
                            .header("Content-Type", "application/json")
                            .PUT(HttpRequest.BodyPublishers.ofString(template))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 == 2) {
                log.info("OpenSearch index template installed at {}", props.getUrl());
                available = true;
            } else {
                log.warn("OpenSearch rejected the index template ({}): {}",
                        response.statusCode(), response.body());
                available = false;
            }
        } catch (Exception e) {
            // Not fatal. The consumer starts anyway and retries the template when the first
            // batch is indexed — OpenSearch is usually just slower to start than we are.
            log.warn("OpenSearch not reachable at {} ({}). Indexing will be retried.",
                    props.getUrl(), e.toString());
            available = false;
        }
    }

    public void index(List<SecurityEvent> events) {
        if (!props.isEnabled() || events.isEmpty()) {
            return;
        }
        try {
            workers.execute(() -> bulkIndex(events));
        } catch (RejectedExecutionException e) {
            dropped.increment();
        }
    }

    private void bulkIndex(List<SecurityEvent> events) {
        // An index template is applied ONLY at index creation. Indexing before the template
        // exists creates the index with dynamic mappings — source.ip becomes `text` instead of
        // `ip`, and CIDR queries silently return zero hits forever. Dynamic mapping is sticky:
        // the only fix afterwards is to delete and reindex.
        //
        // So the template has to be in place before the first document, not after. When
        // OpenSearch was unavailable at startup, this retries it (with backoff) and drops the
        // batch rather than creating a badly-mapped index.
        if (!available && !ensureTemplate()) {
            dropped.increment();
            return;
        }

        StringBuilder body = new StringBuilder(events.size() * 512);
        try {
            for (SecurityEvent event : events) {
                String index = props.getIndexPrefix() + "-" + INDEX_DATE.format(event.timestamp());
                // The document id is the event id, so a replayed event overwrites rather than
                // duplicating — the same idempotency the Postgres primary key provides.
                body.append("{\"index\":{\"_index\":\"").append(index)
                        .append("\",\"_id\":\"").append(event.event().id()).append("\"}}\n")
                        .append(mapper.writeValueAsString(event)).append('\n');
            }
        } catch (Exception e) {
            failed.increment(events.size());
            log.warn("Could not build bulk request", e);
            return;
        }

        try {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(props.getUrl() + "/_bulk"))
                            .timeout(Duration.ofSeconds(props.getTimeoutSeconds()))
                            .header("Content-Type", "application/x-ndjson")
                            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 == 2) {
                indexed.increment(events.size());
            } else {
                failed.increment(events.size());
                warnOnce(response.statusCode() + " " + response.body());
            }
        } catch (Exception e) {
            failed.increment(events.size());
            warnOnce(e.toString());
        }
    }

    /**
     * Retries the template install, at most once every {@link #TEMPLATE_RETRY_SECONDS}.
     *
     * <p>Without the backoff, a permanently unreachable OpenSearch would mean a 5-second HTTP
     * timeout on every single batch — turning a degraded optional feature into a throughput
     * problem for the indexer thread.
     *
     * @return true if the template is in place and indexing may proceed
     */
    private synchronized boolean ensureTemplate() {
        long now = System.nanoTime();
        if (now - lastTemplateAttemptNanos < TEMPLATE_RETRY_SECONDS * 1_000_000_000L) {
            return false;
        }
        lastTemplateAttemptNanos = now;
        createIndexTemplate();
        if (available) {
            log.info("OpenSearch indexing recovered; template reinstalled");
        }
        return available;
    }

    /** Avoids a log line per batch when OpenSearch is simply down for a while. */
    private void warnOnce(String detail) {
        if (available) {
            log.warn("OpenSearch indexing failing, continuing without it: {}", detail);
            available = false;
        }
    }

    public boolean isAvailable() {
        return available;
    }
}
