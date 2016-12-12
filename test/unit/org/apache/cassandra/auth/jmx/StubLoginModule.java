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

package org.apache.cassandra.auth.jmx;

import java.io.IOException;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.cassandra.auth.CassandraPrincipal;

public class StubLoginModule implements LoginModule
{
    private CassandraPrincipal principal;
    private Subject subject;
    private CallbackHandler callbackHandler;

    public StubLoginModule(){}

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
    {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        principal = new CassandraPrincipal((String)options.get("role_name"));
    }

    public boolean login() throws LoginException
    {
        NameCallback nc = new NameCallback("username: ");
        PasswordCallback pc = new PasswordCallback("password: ", false);
        try {
            callbackHandler.handle(new Callback[]{ nc, pc});
            return nc.getName().equals("testuser") && new String(pc.getPassword()).equals("testpassword");
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException("Auth failed");
        }
    }

    public boolean commit() throws LoginException
    {
        if (!subject.getPrincipals().contains(principal))
            subject.getPrincipals().add(principal);
        return true;
    }

    public boolean abort() throws LoginException
    {
        return true;
    }

    public boolean logout() throws LoginException
    {
        return true;
    }
}
