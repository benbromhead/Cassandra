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

package org.apache.cassandra.utils;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A typed cache that prevents "thundering herd" behavior by only allowing a single thread to fill the cache at
 * a given time. It is implemented on top of ReentrantReadWriteLock, so multiple readers are allowed.
 *
 * @param <T> the type of the value to be cached
 */
public abstract class CachedValue<T>
{
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile T current = null;

    /**
     * Fetches the cached value. If there is a cache miss, it's filled by calling the the {@link #load} method.
     *
     * @return the cached value
     */
    public T get()
    {
        lock.readLock().lock();

        try
        {
            if (current == null)
            {
                // release read lock to prevent a deadlock (write lock waits for existing readers to finish)
                lock.readLock().unlock();
                lock.writeLock().lock();

                try
                {
                    if (current == null)
                        current = load();
                }
                finally
                {
                    // "demote" back to a read lock, done before releasing write lock to follow lock ordering rules
                    lock.readLock().lock();
                    lock.writeLock().unlock();
                }
            }

            return current;
        }
        finally
        {
            lock.readLock().unlock();
        }
    }

    /**
     * Invalidates the cached value. The next time @{@link #get} is called, it will miss. This takes the write lock,
     * so it will wait for any previous writers & readers to finish, and block readers until it's finished.
     */
    public void invalidate()
    {
        lock.writeLock().lock();
        try
        {
            current = null;
        }
        finally
        {
            lock.writeLock().unlock();
        }
    }

    /**
     * Called during cache fill operations.
     *
     * @return The value that should be cached. A null will result in a subsequent cache miss as it  indicates that the
     *  cache could not be properly filled.
     */
    protected abstract T load();
}
