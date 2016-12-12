/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.auth;

import java.io.IOException;
import java.net.InetAddress;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.callback.*;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslServer;


import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;

public class JAASAuthenticator implements IAuthenticator
{
    private static final Logger logger = LoggerFactory.getLogger(JAASAuthenticator.class);
    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";
    private static final String CONFIG_NAME = "Cassandra";
//    private static final String CONFIG_NAME = System.getProperty("cassandra.auth.remote.login.config");



    private AuthenticatedUser authenticate(String username, String password) throws AuthenticationException
    {

        LoginContext lc;
        try
        {
            lc = new LoginContext(CONFIG_NAME, new AuthRequestCallbackHandler(username, password));
            lc.login();
        }
        catch (LoginException e)
        {
            logger.info("", e);
            throw new AuthenticationException(e.getMessage());
        }
        return new AuthenticatedUser(username);
    }


    final static class AuthRequestCallbackHandler implements CallbackHandler
    {
        private final String username;
        private final String password;


        AuthRequestCallbackHandler(String username, String password)
        {
            this.username = username;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws UnsupportedCallbackException
        {
            for (Callback callback : callbacks)
            {
                if (callback instanceof NameCallback)
                {
                    ((NameCallback) callback).setName(username);
                }
                else if (callback instanceof PasswordCallback)
                {
                    ((PasswordCallback) callback).setPassword(password.toCharArray());
                }
                else
                {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }
    }

    public boolean requireAuthentication()
    {
        return true;
    }

    public Set<? extends IResource> protectedResources()
    {
        // Also protected by CassandraRoleManager, but the duplication doesn't hurt and is more explicit
        return ImmutableSet.of(DataResource.table(SchemaConstants.AUTH_KEYSPACE_NAME, AuthKeyspace.ROLES));

    }

    public void validateConfiguration() throws ConfigurationException
    {

    }

    public void setup()
    {

    }

    // TODO: Currently Cassandra clients only do no auth or username / password auth. May wish to explore x509
    private class JaasPlainTextSaslAuthenticator extends PlainTextCqlSaslNegotiator
    {
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            if (!complete)
                throw new AuthenticationException("SASL negotiation not complete");
            return authenticate(username, password);
        }
    }

    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {

        return new JaasPlainTextSaslAuthenticator();
    }

    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        String username = credentials.get(USERNAME_KEY);
        if (username == null)
            throw new AuthenticationException(String.format("Required key '%s' is missing", USERNAME_KEY));

        String password = credentials.get(PASSWORD_KEY);
        if (password == null)
            throw new AuthenticationException(String.format("Required key '%s' is missing for provided username %s", PASSWORD_KEY, username));

        return authenticate(username, password);
    }
}
