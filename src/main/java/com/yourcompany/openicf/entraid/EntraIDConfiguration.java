package com.yourcompany.openicf.entraid;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * Configuration class for the Microsoft Entra ID Connector.
 * <p>
 * This class holds the necessary parameters to authenticate and interact
 * with the Microsoft Graph API, such as tenant ID, client ID, and client
 * secret.
 * </p>
 */
public class EntraIDConfiguration extends AbstractConfiguration {

    private String tenantId;
    private String clientId;
    private GuardedString clientSecret;
    private boolean enableGuestUserCreation = false;
    private int groupCacheSize = 500;
    private String graphEndpoint = "https://graph.microsoft.com";

    /**
     * Helper method to validate that a property is not missing.
     *
     * @param value The value to check.
     * @param key   The name of the property.
     */
    private void valid(Object value, String key) {
        if (value instanceof String) {
            String str = (String) value;
            if (StringUtil.isBlank(str)) {
                throw new IllegalArgumentException("Property " + key + " cannot be null or empty");
            }
        } else if (value == null) {
            throw new IllegalArgumentException("Property " + key + " cannot be null");
        }
    }

    /**
     * Validates the configuration.
     * <p>
     * Ensures that {@code tenantId}, {@code clientId}, and {@code clientSecret} are
     * provided.
     * </p>
     *
     * @throws IllegalArgumentException if any required property is missing.
     */
    @Override
    public void validate() {
        valid(tenantId, "tenantId");
        valid(clientId, "clientId");
        valid(clientSecret, "clientSecret");
    }

    /**
     * Gets the Tenant ID.
     *
     * @return The Directory (Tenant) ID.
     */
    @ConfigurationProperty(order = 1, displayMessageKey = "tenantId.display", helpMessageKey = "tenantId.help", required = true)
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Sets the Tenant ID.
     *
     * @param tenantId The Directory (Tenant) ID.
     */
    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Gets the Client ID.
     *
     * @return The Application (Client) ID.
     */
    @ConfigurationProperty(order = 2, displayMessageKey = "clientId.display", helpMessageKey = "clientId.help", required = true)
    public String getClientId() {
        return clientId;
    }

    /**
     * Sets the Client ID.
     *
     * @param clientId The Application (Client) ID.
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Gets the Client Secret.
     *
     * @return The Client Secret.
     */
    @ConfigurationProperty(order = 3, displayMessageKey = "clientSecret.display", helpMessageKey = "clientSecret.help", required = true, confidential = true)
    public GuardedString getClientSecret() {
        return clientSecret;
    }

    /**
     * Sets the Client Secret.
     *
     * @param clientSecret The Client Secret.
     */
    public void setClientSecret(GuardedString clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     * Checks if guest user creation is enabled.
     *
     * @return True if guest user creation is enabled, false otherwise.
     */
    @ConfigurationProperty(order = 4, displayMessageKey = "enableGuestUserCreation.display", helpMessageKey = "enableGuestUserCreation.help")
    public boolean isEnableGuestUserCreation() {
        return enableGuestUserCreation;
    }

    /**
     * Sets whether guest user creation is enabled.
     *
     * @param enableGuestUserCreation True to enable, false to disable.
     */
    public void setEnableGuestUserCreation(boolean enableGuestUserCreation) {
        this.enableGuestUserCreation = enableGuestUserCreation;
    }

    /**
     * Gets the group cache size.
     *
     * @return The group cache size.
     */
    @ConfigurationProperty(order = 5, displayMessageKey = "GROUP_CACHE_SIZE", helpMessageKey = "groupCacheSize.help")
    public int getGroupCacheSize() {
        return groupCacheSize;
    }

    /**
     * Sets the group cache size.
     *
     * @param groupCacheSize The group cache size.
     */
    public void setGroupCacheSize(int groupCacheSize) {
        this.groupCacheSize = groupCacheSize;
    }

    /**
     * Gets the Graph Endpoint.
     *
     * @return The Graph Endpoint.
     */
    @ConfigurationProperty(displayMessageKey = "GRAPH_ENDPOINT", helpMessageKey = "Base URL for Microsoft Graph (e.g. https://graph.microsoft.com for Commercial, https://graph.microsoft.us for US Gov)")
    public String getGraphEndpoint() {
        return graphEndpoint;
    }

    /**
     * Sets the Graph Endpoint.
     *
     * @param graphEndpoint The Graph Endpoint.
     */
    public void setGraphEndpoint(String graphEndpoint) {
        this.graphEndpoint = graphEndpoint;
    }
}
