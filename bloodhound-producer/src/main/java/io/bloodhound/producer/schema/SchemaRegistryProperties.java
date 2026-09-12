package io.bloodhound.producer.schema;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "bloodhound.schema-registry")
public class SchemaRegistryProperties {

    private boolean enabled = true;

    /** Redpanda's built-in registry, Confluent-API compatible. */
    private String url = "http://localhost:18081";

    /**
     * BACKWARD: a consumer on the old schema can read data written under the new one.
     * The right default when producers deploy before consumers, which is the usual order.
     */
    private String compatibility = "BACKWARD";

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

    public String getCompatibility() {
        return compatibility;
    }

    public void setCompatibility(String compatibility) {
        this.compatibility = compatibility;
    }
}
