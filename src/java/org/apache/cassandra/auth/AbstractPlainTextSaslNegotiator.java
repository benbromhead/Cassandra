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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.exceptions.AuthenticationException;

public abstract class AbstractPlainTextSaslNegotiator implements IAuthenticator.SaslNegotiator
{
    private static final Logger logger = LoggerFactory.getLogger(AbstractPlainTextSaslNegotiator.class);
    private static final byte NUL = 0;

    public boolean complete = false;
    public String username;
    public String password;

    public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
    {
        decodeCredentials(clientResponse);
        complete = true;
        return null;
    }

    public boolean isComplete()
    {
        return complete;
    }

    /**
     * SASL PLAIN mechanism specifies that credentials are encoded in a
     * sequence of UTF-8 bytes, delimited by 0 (US-ASCII NUL).
     * The form is : {code}authzId<NUL>authnId<NUL>password<NUL>{code}
     * authzId is optional, and in fact we don't care about it here as we'll
     * set the authzId to match the authnId (that is, there is no concept of
     * a user being authorized to act on behalf of another with this IAuthenticator).
     *
     * @param bytes encoded credentials string sent by the client
     * @throws org.apache.cassandra.exceptions.AuthenticationException if either the
     *                                                                 authnId or password is null
     */
    private void decodeCredentials(byte[] bytes) throws AuthenticationException
    {
        logger.trace("Decoding credentials from client token");
        byte[] user = null;
        byte[] pass = null;
        int end = bytes.length;
        for (int i = bytes.length - 1; i >= 0; i--)
        {
            if (bytes[i] == NUL)
            {
                if (pass == null)
                    pass = Arrays.copyOfRange(bytes, i + 1, end);
                else if (user == null)
                    user = Arrays.copyOfRange(bytes, i + 1, end);
                end = i;
            }
        }

        if (pass == null)
            throw new AuthenticationException("Password must not be null");
        if (user == null)
            throw new AuthenticationException("Authentication ID must not be null");

        username = new String(user, StandardCharsets.UTF_8);
        password = new String(pass, StandardCharsets.UTF_8);
    }
}
