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

package org.apache.cassandra.io.util;

/*
 * Quasar: lightweight threads and actors for the JVM.
 * Copyright (c) 2013-2014, Parallel Universe Software Co. All rights reserved.
 *
 * This program and the accompanying materials are dual-licensed under
 * either the terms of the Eclipse Public License v1.0 as published by
 * the Eclipse Foundation
 *
 *   or (per the licensee's choosing)
 *
 * under the terms of the GNU Lesser General Public License version 3.0
 * as published by the Free Software Foundation.
 */

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import co.paralleluniverse.common.util.CheckedCallable;
import co.paralleluniverse.fibers.Fiber;
import co.paralleluniverse.fibers.FiberAsync;
import co.paralleluniverse.fibers.SuspendExecution;
import co.paralleluniverse.fibers.Suspendable;
import org.apache.activemq.artemis.jlibaio.SubmitInfo;

/**
 *
 * @author pron
 */
abstract class CassandraFiberAsyncIO<V> extends FiberAsync<V, IOException>
{
    protected SubmitInfo makeCallback() {
        return new SubmitInfo() {
            public void onError(int errno, String message)
            {
                CassandraFiberAsyncIO.this.asyncFailed(new IOException(message));
            }

            public void done()
            {
                CassandraFiberAsyncIO.this.asyncCompleted(null);
            }
        };
    }

    @Override
    public V run() throws IOException, SuspendExecution
    {
        try {
            return super.run();
        } catch (InterruptedException e) {
            throw new InterruptedIOException();
        }
    }

    @Override
    public V run(long timeout, TimeUnit unit) throws IOException, SuspendExecution, TimeoutException
    {
        try {
            return super.run(timeout, unit);
        } catch (InterruptedException e) {
            throw new InterruptedIOException();
        }
    }

    @Suspendable
    public V runSneaky() throws IOException {
        try {
            return super.run();
        } catch (InterruptedException e) {
            throw new IOException(e);
        } catch (SuspendExecution e) {
            throw new AssertionError();
        }
    }

    @Suspendable
    public static <V> V runBlockingIO(final ExecutorService exec, final CheckedCallable<V, IOException> callable) throws IOException {
        try {
            return FiberAsync.runBlocking(exec, callable);
        } catch (InterruptedException e) {
            throw new IOException(e);
        } catch (SuspendExecution e) {
            throw new AssertionError();
        }
    }
}

