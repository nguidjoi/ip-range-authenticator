package org.devware.ipauthenticator;

import java.util.Collections;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;

public class IPAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(IPAuthenticator.class);
    private static final String IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "ip_based_otp_conditional";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        IPAddressSeqRange userAllowedIpRange = getUserIpAddressRangeAllowed(user);
        IPAddress remoteUserIpAddress = getRemoteUserIPAddress(context.getConnection());
        isRemoteUserIpAddressInUserAllowedIpAddressRange(remoteUserIpAddress, userAllowedIpRange);

        if (isRemoteUserIpAddressInUserAllowedIpAddressRange(remoteUserIpAddress, userAllowedIpRange)) {
            logger.infof("IPs do not match. Realm %s expected %s but user %s logged from %s", realm.getName(),  user.getUsername(), remoteUserIpAddress);
            UserCredentialManager credentialManager = session.userCredentialManager();

            if (!credentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)) {
                user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            }

            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
        } else {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("skip"));
        }

        context.success();
    }

    private boolean isRemoteUserIpAddressInUserAllowedIpAddressRange(IPAddress remoteUserIpAddress, IPAddressSeqRange userAllowedIpRange) {
        return userAllowedIpRange.contains(remoteUserIpAddress);
    }

    private IPAddressSeqRange getUserIpAddressRangeAllowed(UserModel user) {
        IPAddress allowedUserStartIPInRangeAddress = new IPAddressString(user.getAttributeStream("StartIPInRangeIpAddress").toString()).getAddress();
        IPAddress allowedUserEndIPInRangeAddress = new IPAddressString(user.getAttributeStream("EndIPInRangeIpAddress").toString()).getAddress();
        return allowedUserStartIPInRangeAddress.toSequentialRange(allowedUserEndIPInRangeAddress);
    }

    private static IPAddress getRemoteUserIPAddress(ClientConnection clientConnection) {
        IPAddress remoteUserIPAddress = new IPAddressString(clientConnection.getRemoteAddr()).getAddress();
        return remoteUserIPAddress;
    }


    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
