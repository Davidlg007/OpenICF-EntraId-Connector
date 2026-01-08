package com.yourcompany.openicf.entraid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class EntraIDConnectorIntegrationTest {

    private EntraIDConnector connector;
    private EntraIDConfiguration configuration;
    private Uid generatedUid;
    private String generatedUserPrincipalName;

    // Env vars
    private String tenantId;
    private String clientId;
    private String clientSecret;
    private String tenantDomain;

    private static final io.github.cdimascio.dotenv.Dotenv dotenv = io.github.cdimascio.dotenv.Dotenv.configure()
            .ignoreIfMissing().load();

    @Test
    @Order(1)
    public void init() {
        tenantId = getEnv("ENTRA_TENANT_ID");
        clientId = getEnv("ENTRA_CLIENT_ID");
        clientSecret = getEnv("ENTRA_CLIENT_SECRET");
        tenantDomain = getEnv("ENTRA_TENANT_DOMAIN");

        configuration = new EntraIDConfiguration();
        configuration.setTenantId(tenantId);
        configuration.setClientId(clientId);
        configuration.setClientSecret(new GuardedString(clientSecret.toCharArray()));
        configuration.setGraphEndpoint("https://graph.microsoft.com"); // explicitly set to commercial for test
        configuration.validate();

        connector = new EntraIDConnector();
        connector.init(configuration);

        // Internal testConnection is called inside init, so if we are here, it passed.
        // We can double check if needed, but init() success implies connectivity.
    }

    private String getEnv(String key) {
        // Load dotenv (lazy load or every time is fine for tests, but efficient is
        // better)
        // For simplicity and avoiding static issues, we can load here or use a
        // singleton.
        // User instruction: "Initialize Dotenv ... (static or in @BeforeAll)."
        // We'll use a local instance here or a static field initialized in static block
        // or init logic.
        // Let's use a static field for Dotenv.

        String val = null;
        if (dotenv != null) {
            val = dotenv.get(key);
        }

        if (val == null) {
            val = System.getenv(key);
        }

        // If val is null, this will throw AssumptionViolatedException and skip the test
        assumeTrue(val != null, "Missing env var: " + key);
        return val;
    }

    @Test
    @Order(2)
    public void create() {
        assumeTrue(connector != null, "Connector not initialized");
        assertThat(connector).isNotNull();

        String uniqueId = UUID.randomUUID().toString().substring(0, 8);
        generatedUserPrincipalName = "test.user." + uniqueId + "@" + tenantDomain;
        String displayName = "Test User " + uniqueId;
        String nickname = "testuser" + uniqueId;

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(AttributeBuilder.build("userPrincipalName", generatedUserPrincipalName));
        attributes.add(AttributeBuilder.build(Name.NAME, generatedUserPrincipalName)); // Name is usually UPN
        attributes.add(AttributeBuilder.build("displayName", displayName));
        attributes.add(AttributeBuilder.build("mailNickname", nickname));
        attributes.add(AttributeBuilder.build("accountEnabled", true));
        attributes.add(AttributeBuilder.build(OperationalAttributes.PASSWORD_NAME,
                new GuardedString("P@ssw0rd123!".toCharArray())));

        generatedUid = connector.create(ObjectClass.ACCOUNT, attributes, null);

        assertThat(generatedUid).isNotNull();
        assertThat(generatedUid.getUidValue()).isNotBlank();
        System.out.println("Created User UPN: " + generatedUserPrincipalName + ", UID: " + generatedUid.getUidValue());
    }

    @Test
    @Order(3)
    public void search() {
        assumeTrue(connector != null, "Connector not initialized");
        assertThat(generatedUid).isNotNull();

        // Search by UID
        // We use a filter or just get?
        // The SearchOp in connector uses OData filter.
        // Let's try searching by UPN (Name) using Equals filter logic if implemented,
        // or just a raw search.
        // The instructions said "Search for the Uid created in step 2".
        // Often connectors support `Uid` filter. Our filter translator converts
        // filters.
        // But for integration test against a generic connector logic, we might use a
        // filter.
        // However, our connector translates `EqualTo` filter.
        // Let's assume we can search by UPN or just verify it exists.

        // Simpler: iterate and find? No, efficient search.
        // Let's search by UserPrincipalName which is mapped to Name

        final ConnectorObject[] result = new ConnectorObject[1];
        connector.executeQuery(ObjectClass.ACCOUNT, "userPrincipalName eq '" + generatedUserPrincipalName + "'",
                new SearchResultsHandler() {
                    @Override
                    public boolean handle(ConnectorObject obj) {
                        result[0] = obj;
                        return true;
                    }

                    @Override
                    public void handleResult(SearchResult searchResult) {
                    }
                }, null);

        assertThat(result[0]).isNotNull();
        assertThat(result[0].getUid()).isEqualTo(generatedUid);
        assertThat(result[0].getName().getNameValue()).isEqualTo(generatedUserPrincipalName);
    }

    @Test
    @Order(4)
    public void update() {
        assumeTrue(connector != null, "Connector not initialized");
        assertThat(generatedUid).isNotNull();

        String newJobTitle = "Senior Tester";
        // Wait, EntraIDConnector schema might not have mapped JobTitle yet?
        // Checking schema()...
        // In previous view_file steps, I saw mapped attributes: userPrincipalName,
        // displayName, givenName, surname, mobilePhone, mail, onPremisesSamAccountName,
        // accountEnabled, password, __GROUPS__.
        // I did NOT see "jobTitle" explicitly mapped in `convertToConnectorObject` or
        // `update`.
        // I should choose an attribute that IS mapped.
        // "surname" or "givenName" or "mobilePhone".
        // I'll update "givenName".

        String newGivenName = "UpdatedGivenName";
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(AttributeBuilder.build("givenName", newGivenName));

        Uid updatedUid = connector.update(ObjectClass.ACCOUNT, generatedUid, attributes, null);
        assertThat(updatedUid).isEqualTo(generatedUid);

        // Verify update
        final ConnectorObject[] result = new ConnectorObject[1];
        connector.executeQuery(ObjectClass.ACCOUNT, "userPrincipalName eq '" + generatedUserPrincipalName + "'",
                obj -> {
                    result[0] = obj;
                    return true;
                }, null);

        // Wait, did I map "givenName" in returned attributes?
        // Checking convertToConnectorObject in my memory...
        // YES: if (user.getDisplayName() != null) ...
        // Wait, create: user.setGivenName is invalid?
        // Let me check EntraIDConnector.java code again to be sure what attributes are
        // supported.
        // In `create`: displayName, mail, onPremisesSamAccountName, accountEnabled,
        // password.
        // In `update`: displayName, givenName, surname, mobilePhone, mail...
        // Ah, `update` handles givenName.
        // But `convertToConnectorObject`?
        // Let me check the file content if needed.
        // I'll update "displayName" instead, safer as I know it's in
        // `convertToConnectorObject`.

        String newDisplayName = "Updated DisplayName";
        Set<Attribute> updateAttrs = new HashSet<>();
        updateAttrs.add(AttributeBuilder.build("displayName", newDisplayName));

        connector.update(ObjectClass.ACCOUNT, generatedUid, updateAttrs, null);

        // Verify
        final ConnectorObject[] verifyResult = new ConnectorObject[1];
        connector.executeQuery(ObjectClass.ACCOUNT, "userPrincipalName eq '" + generatedUserPrincipalName + "'",
                obj -> {
                    verifyResult[0] = obj;
                    return true;
                }, null);

        assertThat(verifyResult[0]).isNotNull();
        Attribute displayNameAttr = verifyResult[0].getAttributeByName("displayName");
        assertThat(displayNameAttr).isNotNull();
        assertThat(displayNameAttr.getValue().get(0)).isEqualTo(newDisplayName);
    }

    @Test
    @Order(5)
    public void delete() {
        assumeTrue(connector != null, "Connector not initialized");
        assertThat(generatedUid).isNotNull();
        connector.delete(ObjectClass.ACCOUNT, generatedUid, null);

        // Verify deletion
        final ConnectorObject[] result = new ConnectorObject[1];
        connector.executeQuery(ObjectClass.ACCOUNT, "userPrincipalName eq '" + generatedUserPrincipalName + "'",
                obj -> {
                    result[0] = obj;
                    return true;
                }, null);

        assertThat(result[0]).isNull();
    }

    @AfterAll
    public void cleanup() {
        if (generatedUid != null && connector != null) {
            try {
                connector.delete(ObjectClass.ACCOUNT, generatedUid, null);
                System.out.println("Cleanup: Deleted user " + generatedUid.getUidValue());
            } catch (Exception e) {
                System.out.println("Cleanup: Failed to delete user (might be already deleted): " + e.getMessage());
            }
        }
        if (connector != null) {
            connector.dispose();
            System.out.println("Cleanup: Connector disposed.");
        }
    }
}
