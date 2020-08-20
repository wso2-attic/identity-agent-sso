/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.agent.oidc.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.identity.sso.agent.oidc.bean.TokenData;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentClientException;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentServerException;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * This class is used to define the utilities required in sso-agent-oidc module.
 */
public class CommonUtils {

    public static final Map<String, TokenData> TOKEN_STORE = new HashMap<>();

    private CommonUtils() {

    }

//    public static JSONObject requestToJson(final OAuthClientRequest accessRequest) {
//
//        JSONObject obj = new JSONObject();
//        obj.append("tokenEndPoint", accessRequest.getLocationUri());
//        obj.append("request body", accessRequest.getBody());
//
//        return obj;
//    }

//    public static JSONObject responseToJson(final OAuthClientResponse oAuthResponse) {
//
//        JSONObject obj = new JSONObject();
//        obj.append("status-code", "200");
//        obj.append("id_token", oAuthResponse.getParam("id_token"));
//        obj.append("access_token", oAuthResponse.getParam("access_token"));
//        return obj;
//
//    }

    public static boolean logout(final HttpServletRequest request, final HttpServletResponse response) {
        // Invalidate session
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        final Optional<Cookie> appIdCookie = getAppIdCookie(request);

        if (appIdCookie.isPresent()) {
            TOKEN_STORE.remove(appIdCookie.get().getValue());
            appIdCookie.get().setMaxAge(0);
            response.addCookie(appIdCookie.get());
            return true;
        }
        return false;
    }

//    public static void getToken(final HttpServletRequest request, final HttpServletResponse response)
//            throws OAuthProblemException, OAuthSystemException, SSOAgentServerException {
//
//        HttpSession session = request.getSession(false);
//        if (!checkOAuth(request)) {
//            session.invalidate();
//            session = request.getSession();
//        }
//        final Optional<Cookie> appIdCookie = getAppIdCookie(request);
//        final Properties properties = SSOAgentContextEventListener.getProperties();
//        final TokenData storedTokenData;
//
//        if (appIdCookie.isPresent()) {
//            storedTokenData = TOKEN_STORE.get(appIdCookie.get().getValue());
//            if (storedTokenData != null) {
//                setTokenDataToSession(session, storedTokenData);
//                return;
//            }
//        }
//
//        final String authzCode = request.getParameter("code");
//
//        if (authzCode == null) {
//            throw new SSOAgentServerException("Authorization code not present in callback");
//        }
//
//        final OAuthClientRequest.TokenRequestBuilder oAuthTokenRequestBuilder =
//                new OAuthClientRequest.TokenRequestBuilder(
//                        properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT));
//
//        final OAuthClientRequest accessRequest = oAuthTokenRequestBuilder.setGrantType(GrantType.AUTHORIZATION_CODE)
//                .setClientId(properties.getProperty(SSOAgentConstants.CONSUMER_KEY))
//                .setClientSecret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET))
//                .setRedirectURI(properties.getProperty(SSOAgentConstants.CALL_BACK_URL))
//                .setCode(authzCode)
//                .buildBodyMessage();
//
//        //create OAuth client that uses custom http client under the hood
//        final OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
//        final JSONObject requestObject = requestToJson(accessRequest);
//        final OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
//        final JSONObject responseObject = responseToJson(oAuthResponse);
//        final String accessToken = oAuthResponse.getParam("access_token");
//
//        session.setAttribute("requestObject", requestObject);
//        session.setAttribute("responseObject", responseObject);
//        if (accessToken != null) {
//            session.setAttribute("accessToken", accessToken);
//            String idToken = oAuthResponse.getParam("id_token");
//            if (idToken != null) {
//                session.setAttribute("idToken", idToken);
//            }
//            session.setAttribute("authenticated", true);
//            session.setAttribute("user", getUserAttributes(idToken));
//
//            TokenData tokenData = new TokenData();
//            tokenData.setAccessToken(accessToken);
//            tokenData.setIdToken(idToken);
//
//            final String sessionId = UUID.randomUUID().toString();
//            TOKEN_STORE.put(sessionId, tokenData);
//            final Cookie cookie = new Cookie("AppID", sessionId);
//            cookie.setMaxAge(-1);
//            cookie.setPath("/");
//            response.addCookie(cookie);
//        } else {
//            session.invalidate();
//        }
//    }

    public static Optional<Cookie> getAppIdCookie(final HttpServletRequest request) {

        final Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("AppID".equals(cookie.getName())) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    public static Optional<TokenData> getTokenDataByCookieID(final String cookieID) {

        if (TOKEN_STORE.containsKey(cookieID)) {
            return Optional.of(TOKEN_STORE.get(cookieID));
        }

        return Optional.empty();
    }

    private static void setTokenDataToSession(final HttpSession session, final TokenData storedTokenData) {

        session.setAttribute("authenticated", true);
        session.setAttribute("accessToken", storedTokenData.getAccessToken());
        session.setAttribute("idToken", storedTokenData.getIdToken());
    }

    private static HttpsURLConnection getHttpsURLConnection(final String url) throws SSOAgentClientException {

        try {
            final URL requestUrl = new URL(url);
            return (HttpsURLConnection) requestUrl.openConnection();
        } catch (IOException e) {
            throw new SSOAgentClientException("Error while creating connection to: " + url, e);
        }
    }

    private static boolean checkOAuth(final HttpServletRequest request) {

        final HttpSession currentSession = request.getSession(false);

        return currentSession != null
                && currentSession.getAttribute("authenticated") != null
                && (boolean) currentSession.getAttribute("authenticated");
    }

    private static Map<String, Object> getUserAttributes(String idToken) throws SSOAgentServerException {

        Map<String, Object> userClaimValueMap = new HashMap<>();
        try {
            JWTClaimsSet claimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();
            Map<String, Object> customClaimValueMap = claimsSet.getClaims();

            for (String claim : customClaimValueMap.keySet()) {
                if (!SSOAgentConstants.OIDC_METADATA_CLAIMS.contains(claim)) {
                    userClaimValueMap.put(claim, customClaimValueMap.get(claim));
                }
            }
        } catch (ParseException e) {
            throw new SSOAgentServerException("Error while parsing JWT.");
        }
        return userClaimValueMap;
    }
}
