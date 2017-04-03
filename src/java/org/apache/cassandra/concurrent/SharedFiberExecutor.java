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

package org.apache.cassandra.concurrent;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import co.paralleluniverse.fibers.Fiber;
import co.paralleluniverse.fibers.FiberExecutorScheduler;
import co.paralleluniverse.fibers.FiberForkJoinScheduler;
import co.paralleluniverse.fibers.FiberScheduler;
import co.paralleluniverse.fibers.SuspendExecution;
import co.paralleluniverse.strands.SuspendableCallable;
import co.paralleluniverse.strands.SuspendableRunnable;

public class SharedFiberExecutor extends AbstractLocalAwareExecutorService
{
    public static final SharedFiberExecutor SHARED = new SharedFiberExecutor("SharedPool");


    final String poolName;
    final AtomicLong workerId = new AtomicLong();
    private boolean shutdown = false;

    public SharedFiberExecutor(String poolName) {
        this.poolName = poolName;
    }

    public SharedFiberExecutor newScheduler() {
        return SHARED;
    }

    protected void addTask(FutureTask<?> futureTask)
    {
        new Fiber<>((SuspendableCallable<Void>) () ->
        {
            futureTask.run();
            return null;
        }).start();
    }

    protected void onCompletion()
    {

    }

    public void execute(Runnable command) {
        new Fiber<>((SuspendableCallable<Void>) () ->
        {
            command.run();
            return null;
        }).start();
    }

    public void execute(Runnable command, ExecutorLocals locals) {
        execute(command);
    }

    // permits executing in the context of the submitting thread
    public void maybeExecuteImmediately(Runnable command) {
        command.run();
    }

    public void shutdown()
    {

    }

    public List<Runnable> shutdownNow()
    {
        return null;
    }

    public boolean isShutdown()
    {
        return false;
    }

    public boolean isTerminated()
    {
        return false;
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException
    {
        return false;
    }
}
