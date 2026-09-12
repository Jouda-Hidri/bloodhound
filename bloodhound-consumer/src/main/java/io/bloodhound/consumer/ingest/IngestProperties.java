package io.bloodhound.consumer.ingest;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "bloodhound.ingest")
public class IngestProperties {

    /**
     * How far ahead of today partitions are pre-created.
     * An insert with no matching partition fails, so this has to stay ahead of the data.
     */
    private int partitionDaysAhead = 7;

    /** Retention runs only when this is on. Off by default — deleting data needs an explicit yes. */
    private boolean retentionEnabled = false;

    /** Days of raw events to keep. Short here because this runs on a laptop. */
    private int retainDays = 30;

    public int getPartitionDaysAhead() {
        return partitionDaysAhead;
    }

    public void setPartitionDaysAhead(int partitionDaysAhead) {
        this.partitionDaysAhead = partitionDaysAhead;
    }

    public boolean isRetentionEnabled() {
        return retentionEnabled;
    }

    public void setRetentionEnabled(boolean retentionEnabled) {
        this.retentionEnabled = retentionEnabled;
    }

    public int getRetainDays() {
        return retainDays;
    }

    public void setRetainDays(int retainDays) {
        this.retainDays = retainDays;
    }
}
