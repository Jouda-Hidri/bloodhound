package io.bloodhound.consumer.search;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "bloodhound.search")
public class SearchProperties {

    /** Dual-write to OpenSearch. Off means the platform still works, just without free-text search. */
    private boolean enabled = true;

    private String url = "http://localhost:9200";

    /** Index name prefix; the daily suffix is appended, e.g. security-events-2026.09.11. */
    private String indexPrefix = "security-events";

    /** Requests are dropped rather than blocking ingestion if OpenSearch is slow. */
    private int timeoutSeconds = 5;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getIndexPrefix() {
        return indexPrefix;
    }

    public void setIndexPrefix(String indexPrefix) {
        this.indexPrefix = indexPrefix;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }
}
