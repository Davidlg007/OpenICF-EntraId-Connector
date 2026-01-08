
import com.yourcompany.openicf.entraid.EntraIDConfiguration;
import com.yourcompany.openicf.entraid.EntraIDConnector;
import org.identityconnectors.common.security.GuardedString;

public class LocalDebug {
    public static void main(String[] args) {
        String tenantId = System.getenv("TENANT_ID");
        String clientId = System.getenv("CLIENT_ID");
        String clientSecret = System.getenv("CLIENT_SECRET");

        if (tenantId == null || clientId == null || clientSecret == null) {
            System.err.println(
                    "Error: Missing environment variables. Please set TENANT_ID, CLIENT_ID, and CLIENT_SECRET.");
            System.exit(1);
        }

        System.out.println("Starting LocalDebug...");

        EntraIDConfiguration config = new EntraIDConfiguration();
        config.setTenantId(tenantId);
        config.setClientId(clientId);
        config.setClientSecret(new GuardedString(clientSecret.toCharArray()));

        try {
            config.validate();
            System.out.println("Configuration valid.");

            EntraIDConnector connector = new EntraIDConnector();
            connector.init(config);
            System.out.println("Success: Connector initialized and connected to Microsoft Entra ID.");

            connector.dispose();
            System.out.println("Connector disposed.");
        } catch (Exception e) {
            System.err.println("Failure during connection test:");
            e.printStackTrace();
        }
    }
}
