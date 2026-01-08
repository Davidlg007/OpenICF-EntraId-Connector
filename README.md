# EntraID Connector

This is an OpenICF Connector for Microsoft Entra ID (formerly Azure Active Directory). It allows for the provisioning, de-provisioning, and management of users in Entra ID via the Microsoft Graph API.

## Prerequisites

*   **Java 17** or higher (Note: Project compiles with source/target 11 compatibility)
*   **Maven** 3.8+

## Azure Setup

To use this connector, you must register an application in the Azure Portal and grant it the necessary API permissions.

### Application Registration
1.  Navigate to **App registrations** in the Azure Portal.
2.  Create a new registration.
3.  Note the **Application (client) ID** and **Directory (tenant) ID**.
4.  Generate a **Client Secret** in the "Certificates & secrets" blade. Note this value immediately.

### API Permissions
The connector requires the following **Microsoft Graph** permissions (Type: **Application**):

*   `User.ReadWrite.All` (Required for creating and managing users)
*   `User.Read.All` (Required for reading/searching users)
*   `Directory.Read.All` (Optional, depending on scope)

**Important**: After adding permissions, you must click **"Grant admin consent for [Your Organization]"**.

## Build Instructions

This project uses Maven to build an OSGi bundle suitable for deployment in MidPoint or ForgeRock IDM.

1.  Navigate to the project root:
    ```bash
    cd entraid-connector
    ```
2.  Run the Maven build:
    ```bash
    mvn clean install
    ```
3.  The generated connector bundle will be located at:
    ```
    target/entraid-connector-1.0.0-SNAPSHOT.jar
    ```

## Deployment

To deploy the connector:

1.  Locate the generated JAR file: `target/entraid-connector-1.0.0-SNAPSHOT.jar`.
2.  Copy this file to the `bundles` or `connectors` directory of your Identity Management solution (e.g., MidPoint, ForgeRock IDM).
    *   **MidPoint**: usually `/opt/midpoint/var/icf-connectors/`.
    *   **ForgeRock IDM**: usually `connectors/` directory.
3.  Restart your IDM service if required.

## Configuration Properties

When configuring the connector resource, provide the following details:

*   **Tenant ID**: The Directory (Tenant) ID from Azure Portal.
*   **Client ID**: The Application (Client) ID.
*   **Client Secret**: The generated Client Secret.
*   **Enable Guest User Creation**: Set to `true` if you wish to invite guest users (requires specific implementation support).
