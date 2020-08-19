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
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentClientException;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentServerException;
import org.wso2.carbon.identity.sso.agent.oidc.util.CommonUtils;
import org.wso2.carbon.identity.sso.agent.oidc.util.SSOAgentConstants;

import java.io.IOException;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DispatchClientServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        responseHandler(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        responseHandler(req, resp);
    }

    private void responseHandler(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, SSOAgentClientException {

        Properties properties = SSOAgentContextEventListener.getProperties();
        String indexPage = getIndexPage(properties);
        // Create the initial session
        if (request.getSession(false) == null) {
            request.getSession(true);
        }

        // Validate callback properties
        if (request.getParameterMap().isEmpty() || (request.getParameterMap().containsKey("sp") &&
                request.getParameterMap().containsKey("tenantDomain"))) {
            CommonUtils.logout(request, response);
            if (!StringUtils.isBlank(indexPage)) {
                response.sendRedirect(indexPage);
            } else {
                throw new SSOAgentClientException("indexPage property is not configured.");
            }
            return;
        }

        final String error = request.getParameter(SSOAgentConstants.ERROR);

        if (StringUtils.isNotBlank(error)) {
            // Error response from IDP
            CommonUtils.logout(request, response);
            if (!StringUtils.isBlank(indexPage)) {
                response.sendRedirect(indexPage);
            } else {
                throw new SSOAgentClientException("indexPage property is not configured.");
            }
            return;
        }

        // Obtain and store session_state against this session
        request.getSession(false)
                .setAttribute(SSOAgentConstants.SESSION_STATE, request.getParameter(SSOAgentConstants.SESSION_STATE));

        try {
            // Obtain token response
            CommonUtils.getToken(request, response);
            response.sendRedirect("home.jsp");
        } catch (SSOAgentServerException | OAuthSystemException | OAuthProblemException e) {
            if (!StringUtils.isBlank(indexPage)) {
                response.sendRedirect(indexPage);
            } else {
                throw new SSOAgentClientException("indexPage property is not configured.");
            }
        }
    }

    private String getIndexPage(Properties properties) {

        String indexPage = null;
        if (!StringUtils.isBlank(properties.getProperty(SSOAgentConstants.INDEX_PAGE))) {
            indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);
        }
        return indexPage;
    }
}
