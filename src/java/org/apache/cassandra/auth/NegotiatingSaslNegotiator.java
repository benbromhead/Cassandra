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
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.exceptions.AuthenticationException;

public abstract class NegotiatingSaslNegotiator implements IAuthenticator.SaslNegotiator
{
    private boolean negotiationComplete = false;
    private static final Logger logger = LoggerFactory.getLogger(NegotiatingSaslNegotiator.class);
    public String mechanism;


    public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
    {
        if(!negotiationComplete) {

            logger.trace("Negotiating SASL mechanism");
            String candidateMechanism = new String(clientResponse, StandardCharsets.UTF_8);
            if(!getListOfAcceptableMechanisms().contains(candidateMechanism))
                throw new AuthenticationException("Chosen SASL mechanism is not supported");
            mechanism = candidateMechanism;
            logger.trace("Negotiated SASL mechanism: ", mechanism );
            negotiationComplete = true;
            setupOnCompletedNegotiation();

            /*
                Just accept the mechanism chosen by the client, the negotiator could be extended to
                support choosing the most secure of a set of mechanisms, returning the mechanism name
                ensures that the choice is explicit.
             */

            return clientResponse;
        } else {
            return evaluateResponseAfterNegotiation(clientResponse);
        }
    }

    public boolean isNegotiationComplete() {
        return negotiationComplete;
    }

    public abstract byte[] evaluateResponseAfterNegotiation(byte[] clientResponse);

    public abstract List<String> getListOfAcceptableMechanisms();

    public void setupOnCompletedNegotiation() {}
}
