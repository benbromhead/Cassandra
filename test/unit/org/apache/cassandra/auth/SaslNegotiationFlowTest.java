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

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.Assert;
import org.junit.Test;

import org.apache.cassandra.exceptions.AuthenticationException;

public class SaslNegotiationFlowTest
{

    @Test
    public void checkSASLmechanism()
    {
        IAuthenticator authenticator = new PasswordAuthenticator();

        Assert.assertTrue(authenticator.getSupportedSaslMechanisms().contains("PLAIN"));
        Assert.assertTrue(authenticator.getSupportedSaslMechanisms().size() == 1);
    }

    /**
     * Taken from the java driver
     */
    protected byte[] getUserPasswordBytes(byte[] username, byte[] password) {
        byte[] initialToken = new byte[username.length + password.length + 2];
        initialToken[0] = 0;
        System.arraycopy(username, 0, initialToken, 1, username.length);
        initialToken[username.length + 1] = 0;
        System.arraycopy(password, 0, initialToken, username.length + 2, password.length);
        return initialToken;
    }

    @Test
    public void testSASLNegotiatorFlow() throws UnknownHostException
    {
        IAuthenticator authenticator = new PasswordAuthenticator();
        PlainTextCqlSaslNegotiator negotiator = (PlainTextCqlSaslNegotiator) authenticator.newV5SaslNegotiator(InetAddress.getLocalHost(), null);

        String username = "cassandra";
        String password = "password";

        /*
          First call to evaluateResponse should return empty string
         */
        Assert.assertArrayEquals(negotiator.evaluateResponse("PLAIN".getBytes()), "".getBytes());
        /*
          Second call to evaluateResponse returns null (the response does not matter as
          isComplete will return true, in which case AuthSuccess gets returned ignoring
          anything returned from evaluate response.
         */
        Assert.assertNull(negotiator.evaluateResponse(getUserPasswordBytes(username.getBytes(), password.getBytes())));

        Assert.assertEquals(negotiator.username, username);
        Assert.assertEquals(negotiator.password, password);
        Assert.assertTrue(negotiator.isComplete());
    }


    @Test(expected = AuthenticationException.class)
    public void testSASLNegotiatorFailureFlow() throws UnknownHostException
    {
        IAuthenticator authenticator = new PasswordAuthenticator();
        PlainTextCqlSaslNegotiator negotiator = (PlainTextCqlSaslNegotiator) authenticator.newV5SaslNegotiator(InetAddress.getLocalHost(), null);

        negotiator.evaluateResponse("INVALID_SASL_MECH".getBytes());

    }
}
