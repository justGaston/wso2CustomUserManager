package org.wso2.custom.userstore.manager;


import org.jasypt.util.password.StrongPasswordEncryptor;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.common.FailureReason;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;
import org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.utils.Secret;

import java.io.OutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class CustomUserStoreManager extends UniqueIDJDBCUserStoreManager {
    private static final StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();


    public CustomUserStoreManager() {
        super();
        System.out.println("Initialized custom manager ++++++++++++*****************************************************************");

    }



    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        System.out.println("Constructor de user storage -----------------*****************************************************************");

    }



    private String callHttpLoginEndpoint(String userName, String credential) {
        System.out.println("Llamando al login v3 *****************************************************************");
        HttpURLConnection connection = null;
        try {
            URL url = new URL("https://api.teamcore.net/tr/auth/1/public/login");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");

            // Habilita la salida para permitir el uso de OutputStream
            connection.setDoOutput(true);

            String jsonInputString = "{"
                    + "\"username\": \"snaveas@testing\","
                    + "\"password\": \"arbelovers\","
                    + "\"platform\": \"ios\","
                    + "\"version\": \"\""
                    + "}";

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonInputString.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            System.out.println("Código de respuesta: " + responseCode);

            // Leer la respuesta del servidor
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
            StringBuilder content = new StringBuilder();
            String inputLine;

            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();

            System.out.println("Respuesta del servidor: " + content.toString());
            return content.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    @Override
    public boolean isLocalUserStore() {
        System.out.println("is local user *****************************************************************");

        String jsonResponse = callHttpLoginEndpoint("patitoperez", "Simbalion");
        if (jsonResponse == null) {
            String reason = "Failed to call HTTP endpoint.";
        }
        else{
            System.out.println(jsonResponse);
        }

        System.out.println("is local user out *****************************************************************");


        return super.isLocalUserStore();
    }

    @Override
    public boolean doCheckExistingUser(String userName) throws UserStoreException {
        return true;
    }

    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        System.out.println("Authentication *****************************************************************");
        System.out.println("***************************************************************** "+ userName);
        return super.doAuthenticate(userName, credential);
    }

    @Override
    public AuthenticationResult doAuthenticateWithUserName(String userName, Object credential)
            throws UserStoreException {
        System.out.println("do authentication custom manager *****************************************************************");

        super.doAuthenticateWithUserName(userName, credential);

        boolean isAuthenticated = false;
        String userID = null;
        User user;

        if (!isValidUserName(userName)) {
            String reason = "Username validation failed.";
            return getAuthenticationResult(reason);
        }

        if (!isValidCredentials(credential)) {
            String reason = "Password validation failed.";
            return getAuthenticationResult(reason);
        }

        try {
            String candidatePassword = String.copyValueOf(((Secret) credential).getChars());

            Connection dbConnection = null;
            ResultSet rs = null;
            PreparedStatement prepStmt = null;
            String sql = null;
            dbConnection = this.getDBConnection();
            dbConnection.setAutoCommit(false);
            // get the SQL statement used to select user details
            sql = this.realmConfig.getUserStoreProperty(JDBCRealmConstants.SELECT_USER_NAME);

            prepStmt = dbConnection.prepareStatement(sql);
            prepStmt.setString(1, userName);
            // check whether tenant id is used
            if (sql.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(2, this.tenantId);
            }

            rs = prepStmt.executeQuery();
            if (rs.next()) {
                userID = rs.getString(1);
                String storedPassword = rs.getString(3);

                // check whether password is expired or not
                boolean requireChange = rs.getBoolean(5);
                Timestamp changedTime = rs.getTimestamp(6);
                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();
                if (!(requireChange && changedTime.before(date))) {
                    // compare the given password with stored password using jasypt
                    isAuthenticated = passwordEncryptor.checkPassword(candidatePassword, storedPassword);
                }
            }
            dbConnection.commit();
        } catch (SQLException exp) {
            try {
                this.getDBConnection().rollback();
            } catch (SQLException e1) {
                throw new UserStoreException("Transaction rollback connection error occurred while" +
                        " retrieving user authentication info. Authentication Failure.", e1);
            }
            throw new UserStoreException("Authentication Failure");
        }
        if (isAuthenticated) {
            user = getUser(userID, userName);
            AuthenticationResult authenticationResult = new AuthenticationResult(
                    AuthenticationResult.AuthenticationStatus.SUCCESS);
            authenticationResult.setAuthenticatedUser(user);
            return authenticationResult;
        } else {
            AuthenticationResult authenticationResult = new AuthenticationResult(
                    AuthenticationResult.AuthenticationStatus.FAIL);
            authenticationResult.setFailureReason(new FailureReason("Invalid credentials."));
            return authenticationResult;
        }
    }

    @Override
    protected String preparePassword(Object password, String saltValue) throws UserStoreException {
        System.out.println("prepare password *****************************************************************");
        if (password != null) {
            String candidatePassword = String.copyValueOf(((Secret) password).getChars());
            return passwordEncryptor.encryptPassword(candidatePassword);
        } else {
            throw new UserStoreException("Authentication Failure");
        }
    }

    private AuthenticationResult getAuthenticationResult(String reason) {
        System.out.println("get authentication result custom manager *****************************************************************");
        AuthenticationResult authenticationResult = new AuthenticationResult(
                AuthenticationResult.AuthenticationStatus.FAIL);
        authenticationResult.setFailureReason(new FailureReason(reason));
        return authenticationResult;
    }

}
