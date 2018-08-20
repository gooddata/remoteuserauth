/**
 * Copyright 2016 Angus Warren
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package anguswarren.jira;

import org.apache.log4j.Category;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.atlassian.core.util.ClassLoaderUtils;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;

public class RemoteUserJiraAuth extends JiraSeraphAuthenticator {
    private static final Category log = Category.getInstance(RemoteUserJiraAuth.class);

    private Properties getProperties() {
        Properties p = new Properties();

        try {
            InputStream iStream = ClassLoaderUtils.getResourceAsStream("RemoteUserJiraAuth.properties", this.getClass());
            p.load(iStream);
        } catch (Exception e) {
            log.debug("Exception loading propertie. The properties file is optional anyway, so this may not be an issues: " + e, e);
        }

        return p;
    }

    private boolean isTrustedHost(Properties p, HttpServletRequest request) {
        final String trustedHosts = p.getProperty("trustedhosts");
        if (trustedHosts != null) {
            final String ipAddress = request.getRemoteAddr();
            if (Arrays.asList(trustedHosts.split(",")).contains(ipAddress)) {
                log.debug("IP found in trustedhosts.");
                return true;
            } else {
                log.debug("IP not found in trustedhosts: " + ipAddress);
                return false;
            }
        } else {
            log.debug("trustedhosts not configured. If you're using http headers, this may be a security issue.");
            return true;
        }
    }

    private String getRemoteUser(Properties p, HttpServletRequest request) {
        String header = p.getProperty("header");
        if (header == null) {
            log.debug("Trying REMOTE_USER for SSO");
            return request.getRemoteUser();
        } else {
            log.debug("Trying HTTP header '" + header + "' for SSO");
            return request.getHeader(header);
        }
    }

    private String removeRealm(Properties p, String remoteUser) {
        String removeRealm = p.getProperty("removeRealm");
        if (removeRealm == null || Boolean.parseBoolean(removeRealm)) {
            return remoteUser.split("@")[0];
        } else {
            return remoteUser;
        }
    }

    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        try {
            Principal user = super.getUser(request, response);
            if (user != null) {
                log.debug("JiraSeraphAuthenticator.getUser succeeded");
                return user;
            }

            final Properties p = getProperties();

            if (!isTrustedHost(p, request)) {
                return null;
            }

            String remoteUser = getRemoteUser(p, request);
            if (remoteUser == null) {
                log.debug("remoteUser is null");
                return null;
            }

            remoteUser = removeRealm(p, remoteUser);

            log.debug("Trying to resolve remote user: " + remoteUser);
            user = getUser(remoteUser);
            if (user != null) {
                log.debug("Logging in with username: " + user);
                if (authoriseUserAndEstablishSession(request, response, user)) {
                    return user;
                }
            }
        } catch (Exception e) {
            log.error("Exception: " + e, e);
        }

        return null;
    }
}
