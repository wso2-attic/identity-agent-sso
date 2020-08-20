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

package org.wso2.carbon.identity.sso.agent.oidc;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentClientException;
import org.wso2.carbon.identity.sso.agent.oidc.util.SSOAgentConstants;

import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * A Filter class used to check sessions and secure pages.
 */
public class OIDCAuthorizationFilter implements Filter {

    protected FilterConfig filterConfig = null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        this.filterConfig = filterConfig;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession();

        Properties properties = SSOAgentContextEventListener.getProperties();

        if (isURLtoSkip(request, properties)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (session == null || session.getAttribute("authenticated") == null) {

            String consumerKey = properties.getProperty(SSOAgentConstants.CONSUMER_KEY);
            String authzEndpoint = properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT);
            String authzGrantType = properties.getProperty(SSOAgentConstants.OAUTH2_GRANT_TYPE);
            String scope = properties.getProperty(SSOAgentConstants.SCOPE);
            String callBackUrl = properties.getProperty(SSOAgentConstants.CALL_BACK_URL);
            String logoutEndpoint = properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT);
            String sessionIFrameEndpoint = properties.getProperty(SSOAgentConstants.OIDC_SESSION_IFRAME_ENDPOINT);

            session.setAttribute(SSOAgentConstants.OAUTH2_GRANT_TYPE, authzGrantType);
            session.setAttribute(SSOAgentConstants.CONSUMER_KEY, consumerKey);
            session.setAttribute(SSOAgentConstants.SCOPE, scope);
            session.setAttribute(SSOAgentConstants.CALL_BACK_URL, callBackUrl);
            session.setAttribute(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT, authzEndpoint);
            session.setAttribute(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT, logoutEndpoint);
            session.setAttribute(SSOAgentConstants.OIDC_SESSION_IFRAME_ENDPOINT, sessionIFrameEndpoint);

            OAuthClientRequest.AuthenticationRequestBuilder oAuthAuthenticationRequestBuilder =
                    new OAuthClientRequest.AuthenticationRequestBuilder(authzEndpoint);
            oAuthAuthenticationRequestBuilder
                    .setClientId(consumerKey)
                    .setRedirectURI((String) session.getAttribute(SSOAgentConstants.CALL_BACK_URL))
                    .setResponseType(authzGrantType)
                    .setScope(scope);

            // Build the new response mode with form post.
            OAuthClientRequest authzRequest;
            try {
                authzRequest = oAuthAuthenticationRequestBuilder.buildQueryMessage();
                response.sendRedirect(authzRequest.getLocationUri());
                return;
            } catch (OAuthSystemException e) {
                String indexPage = getIndexPage(properties);
                if (StringUtils.isNotBlank(indexPage)) {
                    response.sendRedirect(indexPage);
                } else {
                    throw new SSOAgentClientException("indexPage property is not configured.");
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {

    }

    private boolean isURLtoSkip(HttpServletRequest request, Properties properties) {

        Set<String> skipURIs = getSkipURIs(properties);
        return skipURIs.contains(request.getRequestURI());
    }

    private Set<String> getSkipURIs(Properties properties) {

        Set<String> skipURIs = new HashSet<String>();
        String skipURIsString = properties.getProperty(SSOAgentConstants.SKIP_URIS);
        if (StringUtils.isNotBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }
        }
        if (StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.INDEX_PAGE))) {
            skipURIs.add(properties.getProperty(SSOAgentConstants.INDEX_PAGE));
        }
        return skipURIs;
    }

    private String getIndexPage(Properties properties) {

        String indexPage = null;
        if (StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.INDEX_PAGE))) {
            indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);
        }
        return indexPage;
    }
}
