package com.yourcompany.openicf.entraid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet; // NEW
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfo; // NEW
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder; // NEW
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject; // NEW
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name; // NEW
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.GroupCollectionResponse;
import com.microsoft.graph.models.PasswordProfile;
import com.microsoft.graph.models.ReferenceCreate;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserCollectionResponse;
import com.microsoft.graph.models.odataerrors.ODataError;
import com.microsoft.graph.serviceclient.GraphServiceClient;
import com.microsoft.graph.users.UsersRequestBuilder;

/**
 * EntraID Connector class.
 * <p>
 * This connector supports creating users, searching for users, and verifying
 * connectivity
 * to Microsoft Entra ID (formerly Azure AD) via the Microsoft Graph API.
 * </p>
 */
@ConnectorClass(configurationClass = EntraIDConfiguration.class, displayNameKey = "entraid.connector.display")
public class EntraIDConnector
        implements Connector, SchemaOp, CreateOp, SearchOp<String>, UpdateAttributeValuesOp, DeleteOp, UpdateOp,
        TestOp {

    private static final Log LOG = Log.getLog(EntraIDConnector.class);

    private static final String CONSISTENCY_LEVEL_HEADER = "ConsistencyLevel";
    private static final String CONSISTENCY_LEVEL_EVENTUAL = "eventual";
    private static final String GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default";
    private static final String ATTR_GROUPS = "__GROUPS__";
    private static final String API_VERSION = "v1.0";

    private EntraIDConfiguration configuration;
    private GraphServiceClient graphClient;

    public EntraIDConnector() {
        // Default constructor for OpenICF
    }

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    /**
     * Initializes the connector with the given configuration.
     * 
     * @param configuration The configuration to use.
     */
    @Override
    public void init(Configuration configuration) {
        this.configuration = (EntraIDConfiguration) configuration;

        String tenantId = this.configuration.getTenantId();
        String clientId = this.configuration.getClientId();

        final String[] secretValue = new String[1];
        if (this.configuration.getClientSecret() != null) {
            this.configuration.getClientSecret().access(chars -> {
                secretValue[0] = new String(chars);
            });
        }
        String clientSecret = secretValue[0];

        // Using ClientSecretCredential for daemon authentication (App-only access).
        // This is suitable for background services where no user is interactively
        // logged in.
        var credential = new ClientSecretCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();

        // Used https://graph.microsoft.com/.default to request all configured
        // permissions in the App Registration.
        this.graphClient = new GraphServiceClient(credential, GRAPH_DEFAULT_SCOPE);

        // Initialize Cache
        int cacheSize = this.configuration.getGroupCacheSize();
        this.groupNameCache = Collections.synchronizedMap(
                new LinkedHashMap<String, String>(cacheSize, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                        return size() > cacheSize;
                    }
                });

        testConnection();
    }

    /**
     * Disposes of the connector resources.
     */
    @Override
    public void dispose() {
        this.graphClient = null;
        this.configuration = null;
    }

    /**
     * Tests the configuration with the connector.
     */
    @Override
    public void test() {
        if (this.graphClient == null) {
            throw new ConnectorException("Graph Client was not initialized");
        }

        try {
            // Perform a lightweight read to verify connectivity
            this.graphClient.organization().get();
        } catch (Exception e) {
            // Propagate the error so the UI shows "Test Failed"
            throw new ConnectorException("Connection check failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies connectivity to Microsoft Entra ID.
     * 
     * @throws RuntimeException if the connection test fails.
     */
    private void testConnection() {
        try {
            // Simple call to verify connectivity and credentials
            graphClient.organization().get();
        } catch (Exception e) {
            throw new RuntimeException("Failed to connect to Microsoft Entra ID: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the schema supported by this connector.
     * 
     * @return The schema.
     */
    @Override
    public Schema schema() {
        SchemaBuilder builder = new SchemaBuilder(EntraIDConnector.class);

        ObjectClassInfoBuilder accountInfoBuilder = new ObjectClassInfoBuilder();
        accountInfoBuilder.setType(ObjectClass.ACCOUNT_NAME);
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build("userPrincipalName"));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build("displayName"));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build("givenName"));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build("surname"));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build("mobilePhone"));
        accountInfoBuilder
                .addAttributeInfo(AttributeInfoBuilder.build("mail"));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build("onPremisesSamAccountName"));
        accountInfoBuilder.addAttributeInfo(AttributeInfoBuilder
                .build("accountEnabled", Boolean.class));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build(
                        OperationalAttributes.PASSWORD_NAME,
                        GuardedString.class));
        accountInfoBuilder.addAttributeInfo(
                AttributeInfoBuilder.build(
                        ATTR_GROUPS,
                        String.class,
                        EnumSet
                                .of(AttributeInfo.Flags.MULTIVALUED)));

        builder.defineObjectClass(accountInfoBuilder.build());
        return builder.build();
    }

    /**
     * Creates a user in Microsoft Entra ID.
     * 
     * @param objectClass The object class to create (must be __ACCOUNT__).
     * @param attributes  The attributes of the new user.
     * @param options     Operation options.
     * @return The Uid of the created user.
     * @throws IllegalArgumentException If the object class is not supported.
     */
    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> attributes, OperationOptions options) {
        if (!ObjectClass.ACCOUNT.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class: " + objectClass);
        }

        User user = new User();
        user.setAccountEnabled(true); // Default to enabled

        for (Attribute attribute : attributes) {
            if (attribute.is(Name.NAME)) {
                user.setUserPrincipalName(AttributeUtil.getStringValue(attribute));
            } else if (attribute.getName().equals("userPrincipalName")) {
                user.setUserPrincipalName(AttributeUtil.getStringValue(attribute));
            } else if (attribute.getName().equals("displayName")) {
                user.setDisplayName(AttributeUtil.getStringValue(attribute));
            } else if (attribute.getName().equals("mail")) {
                user.setMail(AttributeUtil.getStringValue(attribute));
            } else if (attribute.getName().equals("onPremisesSamAccountName")) {
                user.setOnPremisesSamAccountName(AttributeUtil.getStringValue(attribute));
            } else if (attribute.getName().equals("accountEnabled")) {
                user.setAccountEnabled(AttributeUtil.getBooleanValue(attribute));
            } else if (attribute
                    .is(OperationalAttributes.PASSWORD_NAME)) {
                GuardedString password = AttributeUtil.getGuardedStringValue(attribute);
                if (password != null) {
                    PasswordProfile passwordProfile = new PasswordProfile();
                    passwordProfile.setForceChangePasswordNextSignIn(false);
                    password.access(chars -> passwordProfile.setPassword(new String(chars)));
                    user.setPasswordProfile(passwordProfile);
                }
            }
        }

        // Ensure Mail Nickname is set if not present (required by Graph API)
        if (user.getMailNickname() == null && user.getUserPrincipalName() != null) {
            String upn = user.getUserPrincipalName();
            int atIndex = upn.indexOf('@');
            if (atIndex > 0) {
                user.setMailNickname(upn.substring(0, atIndex));
            } else {
                user.setMailNickname(upn);
            }
        }

        User createdUser = graphClient.users().post(user);
        return new Uid(createdUser.getId());
    }

    /**
     * Creates a filter translator for use in search operations.
     * 
     * @param objectClass The object class to search for.
     * @param options     Operation options.
     * @return A filter translator that converts OpenICF filters to OData query
     *         strings.
     */
    @Override
    public FilterTranslator<String> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new EntraIDFilterTranslator();
    }

    /**
     * Executes a user search query against Microsoft Graph API.
     * 
     * @param objectClass The object class to search (must be __ACCOUNT__).
     * @param query       The OData filter string (can be null).
     * @param handler     The handler to process the results.
     * @param options     Operation options.
     */
    @Override
    public void executeQuery(ObjectClass objectClass, String query, ResultsHandler handler, OperationOptions options) {
        if (!ObjectClass.ACCOUNT.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class: " + objectClass);
        }

        // 1. Check for existing Cookie (Pagination)
        String cookieUrl = (options != null) ? options.getPagedResultsCookie() : null;
        UserCollectionResponse response;

        try {
            if (StringUtil.isNotBlank(cookieUrl)) {
                // CASE A: RESUMING SEARCH (Pagination)
                // We bypass the fluent API and use the raw URL from the cookie
                UsersRequestBuilder builder = new UsersRequestBuilder(cookieUrl, graphClient.getRequestAdapter());
                response = builder.get();
            } else {
                // CASE B: NEW SEARCH
                // We build the request from scratch with filters and page size
                response = graphClient.users().get(requestConfiguration -> {
                    // Apply Filter if present
                    if (StringUtil.isNotBlank(query)) {
                        requestConfiguration.queryParameters.filter = query;
                    }

                    // Apply Page Size (Limit)
                    if (options != null && options.getPageSize() != null && options.getPageSize() > 0) {
                        requestConfiguration.queryParameters.top = options.getPageSize();
                    }

                    // Critical: Select fields you need to avoid heavy payloads
                    requestConfiguration.queryParameters.select = new String[] {
                            "id", "userPrincipalName", "displayName", "accountEnabled", "mail",
                            "onPremisesSamAccountName"
                    };

                    // Critical: Headers for advanced queries (consistency)
                    requestConfiguration.headers.add(CONSISTENCY_LEVEL_HEADER, CONSISTENCY_LEVEL_EVENTUAL);
                    if (StringUtil.isNotBlank(query)) {
                        requestConfiguration.queryParameters.count = true;
                    }
                });
            }

            // 2. Process Results
            if (response != null && response.getValue() != null) {
                for (User graphUser : response.getValue()) {
                    // Convert Graph User to ConnectorObject
                    ConnectorObject connectorObj = convertToConnectorObject(
                            graphUser);

                    // Send to Handler (Stop if handler says "Enough!")
                    if (!handler.handle(connectorObj)) {
                        return;
                    }
                }
            }

            // 3. Handle Next Page Cookie
            String nextLink = response.getOdataNextLink();
            SearchResult searchResult;

            if (nextLink != null && !nextLink.isEmpty()) {
                // We have more pages -> Return the URL as the cookie
                searchResult = new SearchResult(nextLink, -1);
            } else {
                // No more pages -> Cookie is null
                searchResult = new SearchResult(null, -1);
            }

            // 4. Notify OpenICF we are done with this batch
            if (handler instanceof SearchResultsHandler) {
                ((SearchResultsHandler) handler).handleResult(searchResult);
            }

        } catch (Exception e) {
            // Always wrap exceptions
            throw new ConnectorException(
                    "Error executing search: " + e.getMessage(), e);
        }
    }

    private ConnectorObject convertToConnectorObject(User user) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setUid(user.getId());
        builder.setName(user.getUserPrincipalName());
        builder.setObjectClass(ObjectClass.ACCOUNT);

        if (user.getUserPrincipalName() != null) {
            builder.addAttribute("userPrincipalName", user.getUserPrincipalName());
        }
        if (user.getDisplayName() != null) {
            builder.addAttribute("displayName", user.getDisplayName());
        }
        if (user.getMail() != null) {
            builder.addAttribute("mail", user.getMail());
        }
        if (user.getOnPremisesSamAccountName() != null) {
            builder.addAttribute("onPremisesSamAccountName", user.getOnPremisesSamAccountName());
        }
        if (user.getAccountEnabled() != null) {
            builder.addAttribute("accountEnabled", user.getAccountEnabled());
        }
        return builder.build();
    }

    /**
     * Helper to process a list of users and push them to the results handler.
     * 
     * @param users   The list of users from the Graph API.
     * @param handler The result handler.
     */
    /**
     * Updates attribute values for a user.
     * <p>
     * This method adds (or sets) the provided attribute values.
     * </p>
     * 
     * @param objectClass The object class (must be __ACCOUNT__).
     * @param uid         The UID of the user to update.
     * @param values      The set of attributes to update.
     * @param options     Operation options.
     * @return The UID of the updated user.
     */
    @Override
    public Uid addAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> values, OperationOptions options) {
        return update(objectClass, uid, values, options);
    }

    /**
     * Removes attribute values for a user.
     * <p>
     * This method removes the provided attribute values.
     * Note: For single-valued attributes, this may not be supported or may act as
     * specific clear/nullify.
     * </p>
     * 
     * @param objectClass The object class (must be __ACCOUNT__).
     * @param uid         The UID of the user to update.
     * @param values      The set of attributes to remove.
     * @param options     Operation options.
     * @return The UID of the updated user.
     */
    @Override
    public Uid removeAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> values,
            OperationOptions options) {
        // For simple fields, removal often means setting to null or specific handling.
        // However, the Graph API PATCH semantics are typically "replace/set".
        // To strictly "remove" a value from a single-valued field, one might patch
        // simple values to null?
        // But for "removeAttributeValues", we usually expect multi-value handling.
        // Given the requirement focused on setting fields, this might not be fully
        // exercised.
        // We will delegate to update logic for now or throw if logic dictates.
        throw new UnsupportedOperationException(
                "removeAttributeValues is not fully implemented for this connector version.");
    }

    /**
     * Shared logic to update user attributes via Graph API PATCH.
     */
    /**
     * Updates an object.
     * <p>
     * OpenICF UpdateOp.update is typically for replacing attributes.
     * Since Graph API uses PATCH (merge) for updates, we will delegate to
     * updateAttributeValues
     * which performs the PATCH. This effectively supports the update operation.
     * </p>
     */
    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions options) {
        if (attributes == null || attributes.isEmpty()) {
            LOG.warn("Update called with empty attributes for Uid: {0}", uid.getUidValue());
            return uid;
        }

        User patchUser = new User();
        boolean hasChanges = false;

        for (Attribute attr : attributes) {
            String name = attr.getName();

            // 1. Handle Account Status (__ENABLE__)
            if (OperationalAttributes.ENABLE_NAME.equals(name)) {
                boolean enabled = AttributeUtil.getBooleanValue(attr);
                patchUser.setAccountEnabled(enabled);
                hasChanges = true;
            }

            // 2. Handle Password (__PASSWORD__)
            else if (OperationalAttributes.PASSWORD_NAME.equals(name)) {
                String newPass = getGuardedStringValue(attr); // Helper needed to unwrap GuardedString
                if (newPass != null) {
                    PasswordProfile profile = new PasswordProfile();
                    profile.setForceChangePasswordNextSignIn(true); // Best practice for admin resets
                    profile.setPassword(newPass);
                    patchUser.setPasswordProfile(profile);
                    hasChanges = true;
                }
            }

            // 3. Handle Standard Attributes (Manual Mapping)
            // Note: For a generic connector, you might use reflection here.
            // For this specific implementation, explicit mapping is safer.
            else if ("displayName".equalsIgnoreCase(name)) {
                patchUser.setDisplayName(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("givenName".equalsIgnoreCase(name)) {
                patchUser.setGivenName(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("surname".equalsIgnoreCase(name)) {
                patchUser.setSurname(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("mobilePhone".equalsIgnoreCase(name)) {
                patchUser.setMobilePhone(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("mail".equalsIgnoreCase(name)) {
                patchUser.setMail(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("onPremisesSamAccountName".equalsIgnoreCase(name)) {
                patchUser.setOnPremisesSamAccountName(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("userPrincipalName".equalsIgnoreCase(name)) {
                patchUser.setUserPrincipalName(AttributeUtil.getStringValue(attr));
                hasChanges = true;
            } else if ("accountEnabled".equalsIgnoreCase(name)) {
                patchUser.setAccountEnabled(AttributeUtil.getBooleanValue(attr));
                hasChanges = true;
            } else if (ATTR_GROUPS.equalsIgnoreCase(name)) {
                // Intercept __GROUPS__ for group membership updates
                List<Object> val = attr.getValue();
                List<String> newGroupIds = new ArrayList<>();
                if (val != null) {
                    for (Object o : val) {
                        if (o != null)
                            newGroupIds.add(o.toString());
                    }
                }
                updateGroupMemberships(uid, newGroupIds);
            }
            // Add other attributes (JobTitle, Department) as defined in your Schema
        }

        // 4. Execute Patch
        if (hasChanges) {
            try {
                graphClient.users().byUserId(uid.getUidValue()).patch(patchUser);
                LOG.info("Successfully updated user: {0}", uid.getUidValue());
            } catch (Exception e) {
                throw new ConnectorException("Failed to update user " + uid.getUidValue(), e);
            }
        }

        return uid;
    }

    private void updateGroupMemberships(Uid uid, List<String> newGroupNames) {
        if (newGroupNames == null) {
            newGroupNames = new ArrayList<>();
        }

        try {
            // 0. Resolve Names to IDs
            List<String> newGroupIds = new ArrayList<>();
            for (String groupName : newGroupNames) {
                String grid = resolveGroupIdByName(groupName);
                if (grid != null) {
                    newGroupIds.add(grid);
                } else {
                    LOG.warn("Group not found with name: {0}, skipping...", groupName);
                }
            }

            // 1. Fetch current groups
            var memberOfCollection = graphClient.users().byUserId(uid.getUidValue()).memberOf().get();
            List<String> currentGroupIds = new ArrayList<>();

            if (memberOfCollection != null && memberOfCollection.getValue() != null) {
                for (DirectoryObject obj : memberOfCollection.getValue()) {
                    if (obj instanceof Group) {
                        currentGroupIds.add(obj.getId());
                    }
                }
            }

            // 2. Identify differences
            List<String> toAdd = new ArrayList<>(newGroupIds);
            toAdd.removeAll(currentGroupIds);

            List<String> toRemove = new ArrayList<>(currentGroupIds);
            toRemove.removeAll(newGroupIds);

            // 3. Add to groups
            for (String groupId : toAdd) {
                try {
                    ReferenceCreate ref = new ReferenceCreate();
                    String odataId = String.format("%s/%s/directoryObjects/%s", configuration.getGraphEndpoint(),
                            API_VERSION, uid.getUidValue());
                    ref.setOdataId(odataId);
                    graphClient.groups().byGroupId(groupId).members().ref().post(ref);
                    LOG.info("Added user {0} to group {1}", uid.getUidValue(), groupId);
                } catch (Exception e) {
                    LOG.error("Failed to add user {0} to group {1}: {2}", uid.getUidValue(), groupId, e.getMessage());
                }
            }

            // 4. Remove from groups
            for (String groupId : toRemove) {
                try {
                    graphClient.groups().byGroupId(groupId).members().byDirectoryObjectId(uid.getUidValue()).ref()
                            .delete();
                    LOG.info("Removed user {0} from group {1}", uid.getUidValue(), groupId);
                } catch (Exception e) {
                    LOG.error("Failed to remove user {0} from group {1}: {2}", uid.getUidValue(), groupId,
                            e.getMessage());
                }
            }

        } catch (Exception e) {
            throw new ConnectorException("Failed to update group memberships for user " + uid.getUidValue(), e);
        }
    }

    private Map<String, String> groupNameCache;

    private String resolveGroupIdByName(String groupName) {
        if (groupNameCache != null && groupNameCache.containsKey(groupName)) {
            return groupNameCache.get(groupName);
        }

        try {
            GroupCollectionResponse response = graphClient.groups().get(requestConfiguration -> {
                requestConfiguration.queryParameters.filter = "displayName eq '" + groupName.replace("'", "''") + "'";
                requestConfiguration.queryParameters.select = new String[] { "id" };
                requestConfiguration.queryParameters.top = 2; // Optimization: fetch at most 2 to detect duplicates
            });

            if (response != null && response.getValue() != null) {
                List<Group> groups = response.getValue();
                if (groups.isEmpty()) {
                    LOG.warn("No group found with name: {0}", groupName);
                    return null;
                } else if (groups.size() > 1) {
                    LOG.warn("Multiple groups found with name: {0}. Using the first one.", groupName);
                }
                String id = groups.get(0).getId();
                groupNameCache.put(groupName, id);
                return id;
            }
        } catch (Exception e) {
            LOG.warn("Error resolving group id for name {0}: {1}", groupName, e.getMessage());
        }
        return null;
    }

    // Private helper to remove or replace logic if needed
    // The previous updateAttributeValues is replaced by 'update' above.
    // We will make addAttributeValues delegate to 'update'

    private String getGuardedStringValue(Attribute attr) {
        final StringBuilder buf = new StringBuilder();
        GuardedString gs = AttributeUtil.getGuardedStringValue(attr);
        if (gs != null) {
            gs.access(new GuardedString.Accessor() {
                @Override
                public void access(char[] clearChars) {
                    buf.append(clearChars);
                }
            });
        }
        return buf.toString();
    }

    /**
     * Deletes a user from Microsoft Entra ID.
     * 
     * @param objectClass The object class to delete.
     * @param uid         The UID of the user to delete.
     * @param options     Operation options.
     */
    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        if (!ObjectClass.ACCOUNT.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class: " + objectClass);
        }

        try {
            graphClient.users().byUserId(uid.getUidValue()).delete();
        } catch (Exception e) {
            // Check for 404 Not Found to throw UnknownUidException
            if (e instanceof ODataError) {
                ODataError oDataError = (ODataError) e;
                if (oDataError.getError() != null
                        && "Request_ResourceNotFound".equals(oDataError.getError().getCode())) {
                    throw new UnknownUidException(uid.getUidValue());
                }
            } else if (e.getMessage() != null && e.getMessage().contains("Request_ResourceNotFound")) {
                // Fallback check if exception mapping is different
                throw new UnknownUidException(uid.getUidValue());
            }
            throw new RuntimeException("Failed to delete user: " + e.getMessage(), e);
        }
    }

}
