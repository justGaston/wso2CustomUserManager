package org.wso2.carbon.user.core.ldap.org.wso2.carbon.user.core;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.ldap.ReadOnlyLDAPUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class TcCustomUserStoreManager extends ReadOnlyLDAPUserStoreManager {

    private static final Log log = LogFactory.getLog(TcCustomUserStoreManager.class);
    private String apiUrl;

    public TcCustomUserStoreManager() {
        System.out.println("Initialized custom manager TCCustomUserStoreManager ---------------------------------------------------------------------");
    }

    public TcCustomUserStoreManager(RealmConfiguration realmConfig,
                                    Map properties, ClaimManager claimManager,
                                    ProfileConfigurationManager profileManager,
                                    UserRealm realm, Integer tenantId)
            throws UserStoreException {
        this(realmConfig, properties, claimManager, profileManager, realm, tenantId, false);
        this.apiUrl = realmConfig.getUserStoreProperty("RestApiUrl");
        System.out.println("Initialized custom manager TCCustomUserStoreManager ---------------------------------------------------------------------");
        if (this.apiUrl == null || this.apiUrl.isEmpty()) {
            throw new UserStoreException("RestApiUrl property is not configured.");
        }
    }

    private String callHttpLoginEndpoint(String userName, String credential) {
        System.out.println("llamando al login v2 *****************************************************************");
        HttpURLConnection connection = null;
        try {

            URL url = new URL("http://192.168.0.177:8000/test");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Content-Type", "application/json");
            int responseCode = connection.getResponseCode();
            System.out.println("Código de respuesta: " + responseCode);

            // Leer la respuesta del servidor
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }

            // Cerrar los streams
            in.close();

            // Imprimir la respuesta
            System.out.println("Respuesta del servidor: " + content.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return "true";
    }

    /**
     * Constructor with Hybrid Role Manager
     *
     * @param realmConfig
     * @param properties
     * @param claimManager
     * @param profileManager
     * @param realm
     * @param tenantId
     * @throws UserStoreException
     */
    public TcCustomUserStoreManager(RealmConfiguration realmConfig,
                                    Map properties, ClaimManager claimManager,
                                    ProfileConfigurationManager profileManager,
                                    UserRealm realm, Integer tenantId, boolean skipInitData)
            throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Initialization Started " + System.currentTimeMillis());
        }

        this.realmConfig = realmConfig;
        this.claimManager = claimManager;
        this.userRealm = realm;
        this.tenantId = tenantId;

//		if (isReadOnly() && realmConfig.isPrimary()) {
//			String adminRoleName =
//			                       UserCoreUtil.removeDomainFromName(realmConfig.getAdminRoleName());
//			realmConfig.setAdminRoleName(UserCoreUtil.addInternalDomainName(adminRoleName));
//		}

        // check if required configurations are in the user-mgt.xml
        checkRequiredUserStoreConfigurations();

        dataSource = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            // avoid returning null
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("Data Source is null");
        }
        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);

        /*
         * obtain the ldap connection source that was created in
         * DefaultRealmService.
         */


        this.userRealm = realm;
        this.persistDomain();
        doInitialSetup();
        if (realmConfig.isPrimary() && StringUtils.isBlank(realmConfig.getAssociatedOrganizationUUID())) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }
        /*
         * Initialize user roles cache as implemented in
         * AbstractUserStoreManager
         */
        initUserRolesCache();

        if (log.isDebugEnabled()) {
            log.debug("Initialization Ended " + System.currentTimeMillis());
        }
    }

    /**
     * @throws UserStoreException
     */
    protected void checkRequiredUserStoreConfigurations() throws UserStoreException {
        System.out.println("checkRequiredUserStoreConfigurations  ---------------------------------------------------------------------");
        log.debug("Checking Rest configurations ");
    }

    private String makeGetRequest(String endpoint) throws UserStoreException {
        try {
            URL url = new URL(apiUrl + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();
                return content.toString();
            } else {
                throw new UserStoreException("GET request failed with HTTP code: " + responseCode);
            }
        } catch (Exception e) {
            log.error("Error during REST GET request", e);
            throw new UserStoreException("Failed to retrieve data from REST endpoint.", e);
        }
    }

    // Protected abstract methods required by AbstractUserStoreManager

    @Override
    public Map getUserPropertyValues(String userName, String[] propertyNames, String profileName) throws UserStoreException {
        throw new UserStoreException("Operation not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public boolean doCheckExistingRole(String roleName) throws UserStoreException {
        throw new UserStoreException("Check existing role operation is not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public boolean doCheckExistingUser(String userName) throws UserStoreException {
        try {
            // Assuming the REST API expects a GET request to check for the existence of a user
            URL url = new URL(apiUrl + "/users/exists?username=" + userName);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Assuming the API returns a JSON response with a boolean indicating existence
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();

                // Parse the JSON response (assuming it returns a field "exists": true/false)
                String jsonResponse = content.toString();
                // For simplicity, checking for "true" in the response. Adjust based on actual response structure.
                return jsonResponse.contains("\"exists\": true");
            } else {
                throw new UserStoreException("Check user existence request failed with HTTP code: " + responseCode);
            }
        } catch (Exception e) {
            log.error("Error during REST request to check user existence", e);
            throw new UserStoreException("Failed to check if user exists through REST endpoint.", e);
        }
    }


    @Override
    public String[] getUserListFromProperties(String property, String value, String profileName) throws UserStoreException {
        throw new UserStoreException("Operation not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        try {
            // Assuming the REST API expects the username and credential in a POST request
            URL url = new URL(apiUrl + "/authenticate");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            // Create JSON payload for the request
            String jsonInputString = "{\"username\": \"" + userName + "\", \"credential\": \"" + credential.toString() + "\"}";

            // Send the request
            try (java.io.OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonInputString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                os.write(input);
            }

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Assuming the API returns a JSON response with a boolean indicating success
                try (java.io.BufferedReader in = new java.io.BufferedReader(new java.io.InputStreamReader(conn.getInputStream()))) {
                    String inputLine;
                    StringBuilder content = new StringBuilder();
                    while ((inputLine = in.readLine()) != null) {
                        content.append(inputLine);
                    }

                    // Parse the JSON response (assuming it returns a field "authenticated": true/false)
                    String jsonResponse = content.toString();
                    // For simplicity, checking for "true" in the response. Adjust based on actual response structure.
                    return jsonResponse.contains("\"authenticated\": true");
                }
            } else {
                throw new UserStoreException("Authentication request failed with HTTP code: " + responseCode);
            }
        } catch (Exception e) {
            log.error("Error during REST authentication request", e);
            throw new UserStoreException("Failed to authenticate user through REST endpoint.", e);
        }
    }


    @Override
    public void doAddUser(String userName, Object credential, String[] roleList,
                             Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {
        throw new UserStoreException("Add user operation is not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {
        throw new UserStoreException("Update credential operation is not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        throw new UserStoreException("Admin update credential operation is not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public void doDeleteUser(String userName) throws UserStoreException {
        throw new UserStoreException("Delete user operation is not supported in ReadOnlyRestUserStoreManager");
    }

    @Override
    public void doDeleteUserClaimValue(String s, String s1, String s2) throws UserStoreException {
        throw new UserStoreException("Delete user operation is not supported in Rea...");
    }
}