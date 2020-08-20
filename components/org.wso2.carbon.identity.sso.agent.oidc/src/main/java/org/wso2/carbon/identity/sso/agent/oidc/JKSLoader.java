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
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentClientException;
import org.wso2.carbon.identity.sso.agent.oidc.util.SSOAgentConstants;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Used to find and set JKS required for IS server communication.
 */
public class JKSLoader implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {

        // First find jks properties
        try {
            ServletContext servletContext = servletContextEvent.getServletContext();
            String propertyFileName = servletContext.getInitParameter(
                    SSOAgentConstants.JKS_PROPERTY_FILE_PARAMETER_NAME);
            InputStream jksInputStream;
            if (StringUtils.isNotBlank(propertyFileName)) {
                jksInputStream = this.getClass().getClassLoader().getResourceAsStream(propertyFileName);
            } else {
                throw new SSOAgentClientException(SSOAgentConstants.JKS_PROPERTY_FILE_PARAMETER_NAME
                        + " context-param is not specified in the web.xml");
            }

            if (jksInputStream == null) {
                return;
            }

            // Load properties
            final Properties jksProperties = new Properties();
            jksProperties.load(jksInputStream);

            // Find and set JKS required for IS server communication
            final URL resource =
                    this.getClass().getClassLoader().getResource(jksProperties.getProperty("keystorename"));

            if (resource != null) {
                System.setProperty("javax.net.ssl.trustStore", resource.getPath());
                System.setProperty("javax.net.ssl.trustStorePassword", jksProperties.getProperty("keystorepassword"));
            }

        } catch (IOException | SSOAgentClientException e) {
            e.printStackTrace();
            return;
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        // Ignored
    }

}