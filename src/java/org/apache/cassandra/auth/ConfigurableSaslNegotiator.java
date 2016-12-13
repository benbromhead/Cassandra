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

import javax.security.auth.login.LoginContext;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.apache.cassandra.exceptions.AuthenticationException;

public class ConfigurableSaslNegotiator implements IAuthenticator.SaslNegotiator
{
    private final SaslServer server;
    private LoginContext lc;


    public ConfigurableSaslNegotiator(SaslServer server)
    {
        this.server = server;
        this.lc = new LoginContext("Cassandra", )
    }

    public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
    {
        try
        {
            return server.evaluateResponse(clientResponse);
        }
        catch (SaslException e)
        {
            throw new AuthenticationException(e.getLocalizedMessage());
        }
    }

    public boolean isComplete()
    {
        return server.isComplete();
    }

    public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
    {
        return new AuthenticatedUser(server.getAuthorizationID());
    }
}
