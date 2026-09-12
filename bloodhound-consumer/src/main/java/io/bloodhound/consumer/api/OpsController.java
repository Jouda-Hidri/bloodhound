package io.bloodhound.consumer.api;

import io.bloodhound.consumer.ingest.DataQualityService;
import io.bloodhound.consumer.ingest.RetentionService;
import io.bloodhound.consumer.search.EventIndexer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Operational controls: data quality, retention, search-tier status. */
@RestController
@RequestMapping("/ops")
public class OpsController {

    private final DataQualityService quality;
    private final RetentionService retention;
    private final EventIndexer indexer;

    public OpsController(DataQualityService quality, RetentionService retention, EventIndexer indexer) {
        this.quality = quality;
        this.retention = retention;
        this.indexer = indexer;
    }

    @GetMapping("/quality")
    public List<Map<String, Object>> quality() {
        return quality.latest();
    }

    @PostMapping("/quality/run")
    public List<Map<String, Object>> runQuality() {
        quality.runChecks();
        return quality.latest();
    }

    @GetMapping("/search")
    public Map<String, Object> search() {
        return Map.of("openSearchAvailable", indexer.isAvailable());
    }

    /**
     * Defaults to a dry run. Retention has no undo, so the safe behaviour has to be the default
     * one — an operator who forgets the flag should get a preview, not a deletion.
     */
    @PostMapping("/retention")
    public Map<String, Object> retention(@RequestParam(defaultValue = "30") int retainDays,
                                         @RequestParam(defaultValue = "true") boolean dryRun) {
        List<Map<String, Object>> partitions = retention.run(retainDays, dryRun);
        return Map.of("dryRun", dryRun, "retainDays", retainDays,
                "partitions", partitions, "count", partitions.size());
    }
}
