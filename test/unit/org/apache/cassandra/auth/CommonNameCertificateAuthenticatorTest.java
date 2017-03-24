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

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
import org.junit.Before;
import org.junit.BeforeClass;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;

import static org.apache.cassandra.auth.AuthTestUtils.setupAuthorizer;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class CommonNameCertificateAuthenticatorTest
{
    private CommonNameCertificateAuthenticator authenticator;
    private static KeyStore testCertificates;


    @BeforeClass
    public static void setUpClass() throws Exception {
        DatabaseDescriptor.daemonInitialization();
        setupAuthorizer();
        testCertificates = KeyStore.getInstance("JKS");
        ClassLoader resourceLoader = CommonNameCertificateAuthenticatorTest.class.getClassLoader();
        try (InputStream resource = resourceLoader.getResourceAsStream("auth/CommonNameTestCertificates.jks"))
        {
            testCertificates.load(resource, "actest".toCharArray());
        }
    }


    @Test
    public void checkSASLmechanism()
    {
        IAuthenticator authenticator = new CommonNameCertificateAuthenticator();

        Assert.assertTrue(authenticator.getSupportedSaslMechanisms().contains("EXTERNAL"));
        Assert.assertTrue(authenticator.getSupportedSaslMechanisms().size() == 1);
    }


    @Before
    public void setUp()
    {
        authenticator = new CommonNameCertificateAuthenticator();
    }

    @Test
    public void testShouldRequireAuthentication()
    {
        assertTrue(authenticator.requireAuthentication());
    }

    @Test
    public void testSupportMethodsShouldDoNothing() throws Exception
    {
        assertTrue(authenticator.protectedResources().isEmpty());
        authenticator.validateConfiguration();
        authenticator.setup();
    }

    @Test
    public void testShouldNotSupportOtherAuthenticationMechanisms() throws Exception
    {
        try
        {
            authenticator.legacyAuthenticate(null);
            fail("expected exception");
        }
        catch (UnsupportedOperationException e) {}
        try
        {
            authenticator.newSaslNegotiator(null);
            fail("expected exception");
        }
        catch (UnsupportedOperationException e) {}
    }

    @Test
    public void testShouldUseCommonNameAsAuthenticatedUser() throws Exception
    {
        Certificate[] chain = testCertificates.getCertificateChain("actest");
        assertEquals("CN=cassandra,OU=Engineering,O=Instaclustr,L=Canberra,ST=ACT,C=AU",
                     subject(chain));
        assertAuthenticatesAs("cassandra", chain);
    }

    @Test
    public void testShouldIgnoreOtherCertificatesInChain() throws Exception
    {
        Certificate[] storedChain = testCertificates.getCertificateChain("acother");
        Certificate[] testChain = {storedChain[0], null, null, null, null};
        assertAuthenticatesAs("other", testChain);
    }

    @Test
    public void testShouldRejectEmptyChainsOrNonX509Certificates() throws Exception
    {
        assertAuthenticationFailure(new Certificate[0]);
        Certificate[] notX509 = {new DummyCertificate()};
        assertAuthenticationFailure(notX509);
    }

    @Test
    public void testShouldRejectCertificatesWithoutCommonNameField() throws Exception
    {
        Certificate[] chain = testCertificates.getCertificateChain("acnoname");
        assertEquals("O=NoName", subject(chain));
        assertAuthenticationFailure(chain);
    }

    private String subject(Certificate[] chain)
    {
        return ((X509Certificate)chain[0]).getSubjectX500Principal().getName();
    }

    private void assertAuthenticatesAs(String username, Certificate[] chain) throws Exception
    {
        AuthenticatedUser user = authenticator.authenticate(chain);
        assertEquals(username, user.getName());
    }

    private void assertAuthenticationFailure(Certificate[] chain)
    {
        try
        {
            authenticator.authenticate(chain);
            fail("Expected authentication failure.");
        }
        catch (AuthenticationException e) {}
    }

    private static final class DummyCertificate extends Certificate
    {

        public DummyCertificate()
        {
            super(null);
        }

        @Override
        public byte[] getEncoded()
        {
            return null;
        }

        @Override
        public PublicKey getPublicKey()
        {
            return null;
        }

        @Override
        public String toString()
        {
            return null;
        }

        @Override
        public void verify(PublicKey key)
        {

        }

        @Override
        public void verify(PublicKey key, String sigProvider)
        {

        }

        @Override
        public Object writeReplace()
        {
            return null;
        }
    }


}
