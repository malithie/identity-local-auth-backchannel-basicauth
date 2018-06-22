/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.backchannel.basicauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.backchannel.basicauth.cache.AuthJwtCache;
import org.wso2.carbon.identity.application.authenticator.backchannel.basicauth.internal
        .BasicAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.common.model.User;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * Signed JWT token based Authenticator
 */
public class BackchannelBasicAuthenticator extends BasicAuthenticator {

    private static final long serialVersionUID = 1819665634416029785L;
    private static final Log log = LogFactory.getLog(BackchannelBasicAuthenticator.class);
    public static final String FULLSTOP_DELIMITER = ".";
    public static final String DASH_DELIMITER = "-";
    public static final String KEYSTORE_FILE_EXTENSION = ".jks";
    public static final String AUTHENTICATOR_NAME = "BackchannelBasicAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "backchannel-basic";
    public static final String PARAM_TOKEN = "token";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String token = request.getParameter(PARAM_TOKEN);
        if (token != null) {
            return true;
        }
        return false;
    }


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String authToken = request.getParameter(PARAM_TOKEN);
        if (log.isDebugEnabled()) {
            log.debug("User authentication token : " + authToken);
        }
        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<String, Object>();
            context.setProperties(authProperties);
        }

        SignedJWT signedJWT = getSignedJWT(authToken);
        JWTClaimsSet claimsSet = getClaimSet(signedJWT);

        if (isValidClaimSet(claimsSet)) {
            String username = claimsSet.getSubject();
            User user = User.getUserFromUserName(username);
            if (isValidSignature(signedJWT, user.getTenantDomain())) {
                AuthJwtCache.getInstance().addToCache(claimsSet.getJWTID(), claimsSet.getJWTID());
                //TODO: user tenant domain has to be an attribute in the AuthenticationContext
                authProperties.put("user-tenant-domain", user.getTenantDomain());
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                String rememberMe = request.getParameter("chkRemember");

                if (rememberMe != null && "on".equals(rememberMe)) {
                    context.setRememberMe(true);
                }
            } else {
                throw new AuthenticationFailedException("User authentication failed : Invalid signature.");
            }

        } else {
            throw new AuthenticationFailedException("Invalid token");
        }

    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    private SignedJWT getSignedJWT(String assertion)
            throws AuthenticationFailedException {

        String errorMessage = "No Valid Assertion was found.";
        SignedJWT signedJWT;
        if (isEmpty(assertion)) {
            throw new AuthenticationFailedException(errorMessage);
        }
        try {
            signedJWT = SignedJWT.parse(assertion);
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
            throw new AuthenticationFailedException("Error while parsing the JWT.");
        }
        if (signedJWT == null) {
            throw new AuthenticationFailedException(errorMessage);
        }
        return signedJWT;
    }

    private JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws AuthenticationFailedException {

        JWTClaimsSet claimsSet;
        String errorMessage;
        if (signedJWT == null) {
            errorMessage = "No Valid Assertion was found";
            throw new AuthenticationFailedException(errorMessage);
        }
        try {
            claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet == null) {
                errorMessage = "Claim values are empty in the given JSON Web Token.";
                throw new AuthenticationFailedException(errorMessage);
            }
        } catch (ParseException e) {
            String errorMsg = "Error when trying to retrieve claimsSet from the JWT.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new AuthenticationFailedException(errorMsg);
        }
        return claimsSet;
    }

    boolean isValidClaimSet(JWTClaimsSet claimsSet) throws AuthenticationFailedException {

        if (StringUtils.isEmpty(claimsSet.getSubject()) || StringUtils.isEmpty(claimsSet.getIssuer())
                || StringUtils.isEmpty(claimsSet.getJWTID()) || claimsSet.getExpirationTime() == null) {
            throw new AuthenticationFailedException("Invalid token : Required fields are not present in the token.");
        }

        if (AuthJwtCache.getInstance().getValueFromCache(claimsSet.getJWTID()) != null) {
            throw new AuthenticationFailedException("Invalid token : Possible replay attack");
        }

        Date currentDate = new Date();
        if (currentDate.compareTo(claimsSet.getExpirationTime()) > 0) {
            throw new AuthenticationFailedException("Invalid token : Token expired");
        }
        return true;

    }

    private boolean isValidSignature(SignedJWT signedJWT, String tenantDomain) throws AuthenticationFailedException {

        X509Certificate cert = getCertificate(tenantDomain);

        try {
            return validateSignature(signedJWT, cert);
        } catch (JOSEException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }
    }

    private boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate)
            throws JOSEException, AuthenticationFailedException {

        JWSVerifier verifier;
        JWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            throw new AuthenticationFailedException("Unable to locate certificate for JWT " + header.toString());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (isEmpty(alg)) {
            throw new AuthenticationFailedException("Signature validation failed. No algorithm is found in the JWT header.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.indexOf("RS") == 0) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new AuthenticationFailedException("Signature validation failed. Public key is not an RSA public key.");
                }
            } else {
                throw new AuthenticationFailedException("Signature Algorithm not supported : " + alg);
            }
        }
        // At this point 'verifier' will never be null.
        return signedJWT.verify(verifier);
    }

    private static X509Certificate getCertificate(String tenantDomain) throws AuthenticationFailedException {

        int tenantId;
        try {
            tenantId = BasicAuthenticatorServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error getting the tenant ID for the tenant domain : " + tenantDomain;
            throw new AuthenticationFailedException(errorMsg);
        }

        KeyStoreManager keyStoreManager;
        // get an instance of the corresponding Key Store Manager instance
        keyStoreManager = KeyStoreManager.getInstance(tenantId);
        KeyStore keyStore;
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                // for tenants, load key from their generated key store and get the primary certificate.
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                return (X509Certificate) keyStore.getCertificate(tenantDomain);

            } else {
                // for super tenant, load the default pub. cert using the config. in carbon.xml
                return keyStoreManager.getDefaultPrimaryCertificate();
            }

        } catch (KeyStoreException e) {
            String errorMsg = "Error instantiating an X509Certificate object for the primary certificate  in tenant: "
                    + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new AuthenticationFailedException(errorMsg);
        } catch (Exception e) {
            String message = "Unable to load key store manager for the tenant domain: " + tenantDomain;
            //keyStoreManager throws Exception
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new AuthenticationFailedException(message);
        }
    }

    private static String generateKSNameFromDomainName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(FULLSTOP_DELIMITER, DASH_DELIMITER);
        return ksName + KEYSTORE_FILE_EXTENSION;
    }

}
