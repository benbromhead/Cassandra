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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import com.google.common.collect.ImmutableSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.config.Config;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.ftpserver.command.impl.SYST;

public class LDAPAuthenticator implements IAuthenticator
{
    private static final Logger logger = LoggerFactory.getLogger(LDAPAuthenticator.class);
    private Hashtable<String, String> ldapEnv = new Hashtable<>();
    Properties ldapProp = new Properties();
    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";


    public boolean requireAuthentication()
    {
        return true;
    }

    public Set<? extends IResource> protectedResources()
    {
        return Collections.emptySet();
    }

    public void validateConfiguration() throws ConfigurationException
    {

        //We need to ensure the following environment variables are set
        try (FileInputStream input = new FileInputStream(System.getProperty("cassandraLdapConfigurationLocation", "conf/ldap.properties")))
        {
            ldapProp.load(input);
        }
        catch (IOException e)
        {
            throw new ConfigurationException("Could not open ldap configuration file", e);
        }

        ldapProp.stringPropertyNames()
                .forEach(s -> ldapEnv.put(s, ldapProp.getProperty(s)));
    }

    public void setup()
    {
    }

    /*
    * Currently we just try passing the supplied user name and password & log in
    * to the directory server using supplied credentials. According to the interwebs
    * binding to a user with the provided credentials is the best way to do so.
    *
    * Currently we just try straight up authenticating to the server using passed through
    * creds. This is slower than we can do.
    *
    * TODO: Authenticate to LDAP using a dedicated Cassandra user, pool connection then rebind to check auth per auth request
    *
    * This will probably be faster.
    */

    private AuthenticatedUser authenticate(String username, String password) throws AuthenticationException
    {
        try
        {
            ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
            ldapEnv.put("com.sun.jndi.ldap.read.timeout", "1000");
            ldapEnv.put("com.sun.jndi.ldap.connect.timeout", "2000");
            if (username != null)
            {
                ldapEnv.put(Context.SECURITY_PRINCIPAL, "cn=" + username + ",dc=example,dc=org");
            }
            if (password != null)
            {
                ldapEnv.put(Context.SECURITY_CREDENTIALS, password);
            }

//            Context

            DirContext dir = new InitialDirContext(ldapEnv);
            dir.close();

            return new AuthenticatedUser(username);
//
//            LdapName ln = new LdapName(username);
//
//            for (Rdn rdn : ln.getRdns())
//            {
//                if (rdn.getType().equalsIgnoreCase("CN"))
//                {
//                    return new AuthenticatedUser((String) rdn.getValue());
//                }
//            }
//            throw new AuthenticationException("Could not determine CN from: " + username);
        }
        catch (NamingException e)
        {
            if(e.getCause() instanceof javax.naming.AuthenticationException)
                throw new AuthenticationException(e.getExplanation() );
            throw new SecurityException("Could not authenticate to directory server using provided credentials", e);
        }
        finally
        {
            ldapEnv.remove(Context.SECURITY_PRINCIPAL);
            ldapEnv.remove(Context.SECURITY_CREDENTIALS);
        }
    }


    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {
        return new AbstractPlainTextSaslNegotiator()
        {
            public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
            {
                return authenticate(username, password);
            }
        };
    }

    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        //TODO extract from PasswordAuth into common class
        String username = credentials.get(USERNAME_KEY);
        if (username == null)
            throw new AuthenticationException(String.format("Required key '%s' is missing", USERNAME_KEY));

        String password = credentials.get(PASSWORD_KEY);
        if (password == null)
            throw new AuthenticationException(String.format("Required key '%s' is missing for provided username %s", PASSWORD_KEY, username));

        return authenticate(username, password);
    }
}
