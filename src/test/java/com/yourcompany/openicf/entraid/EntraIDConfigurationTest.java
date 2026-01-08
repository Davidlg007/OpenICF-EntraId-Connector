package com.yourcompany.openicf.entraid;

import org.identityconnectors.common.security.GuardedString;
import org.testng.annotations.Test;

public class EntraIDConfigurationTest {

    @Test
    public void testValidateSuccess() {
        EntraIDConfiguration config = new EntraIDConfiguration();
        config.setTenantId("tenant");
        config.setClientId("client");
        config.setClientSecret(new GuardedString("secret".toCharArray()));
        config.validate();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testValidateMissingTenant() {
        EntraIDConfiguration config = new EntraIDConfiguration();
        config.setClientId("client");
        config.setClientSecret(new GuardedString("secret".toCharArray()));
        config.validate();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testValidateMissingClient() {
        EntraIDConfiguration config = new EntraIDConfiguration();
        config.setTenantId("tenant");
        config.setClientSecret(new GuardedString("secret".toCharArray()));
        config.validate();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testValidateMissingSecret() {
        EntraIDConfiguration config = new EntraIDConfiguration();
        config.setTenantId("tenant");
        config.setClientId("client");
        config.validate();
    }
}
