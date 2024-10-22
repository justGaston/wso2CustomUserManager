package org.wso2.custom.userstore.manager;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class CustomUserStoreManager extends UniqueIDJDBCUserStoreManager {
    private static final StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();


    public CustomUserStoreManager() {

    }

    @Override
    public boolean isLocalUserStore() {
        return super.isLocalUserStore();
    }

    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
    }

    private String callHttpLoginEndpoint(String userName, Object credential) {
        HttpURLConnection connection = null;
        try {

            URL url = new URL("http://127.0.0.1:8000/login");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);


            String candidatePassword = String.copyValueOf(((Secret) credential).getChars());
            String jsonInputString = String.format("{\"user\": \"%s\", \"password\": \"%s\"}", userName, candidatePassword);


            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonInputString.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                return response.toString();
            }
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
    public AuthenticationResult doAuthenticateWithUserName(String userName, Object credential)
            throws UserStoreException {

        String jsonResponse = callHttpLoginEndpoint(userName, credential);
        if (jsonResponse == null) {
            String reason = "Failed to call HTTP endpoint.";
        }

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
        if (password != null) {
            String candidatePassword = String.copyValueOf(((Secret) password).getChars());
            return passwordEncryptor.encryptPassword(candidatePassword);
        } else {
            throw new UserStoreException("Authentication Failure");
        }
    }

    private AuthenticationResult getAuthenticationResult(String reason) {

        AuthenticationResult authenticationResult = new AuthenticationResult(
                AuthenticationResult.AuthenticationStatus.FAIL);
        authenticationResult.setFailureReason(new FailureReason(reason));
        return authenticationResult;
    }

}
