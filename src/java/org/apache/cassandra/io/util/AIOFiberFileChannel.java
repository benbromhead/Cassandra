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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.ScatteringByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import co.paralleluniverse.fibers.Suspendable;
import org.apache.activemq.artemis.jlibaio.LibaioContext;
import org.apache.activemq.artemis.jlibaio.LibaioFile;
import org.apache.activemq.artemis.jlibaio.SubmitInfo;

public class AIOFiberFileChannel implements SeekableByteChannel, GatheringByteChannel, ScatteringByteChannel, AutoCloseable
{
    private static final FileAttribute<?>[] NO_ATTRIBUTES = new FileAttribute[0];
    private static final int LIBAIO_QUEUE_SIZE = 50;
    private static LibaioContext<? extends SubmitInfo> aioContext = new AIOHolder().ctx;
    private long position = 0;

    private LibaioFile file;

    AIOFiberFileChannel(LibaioFile file) {
        this.file = file;
    }

    private static class AIOHolder {
        public final LibaioContext<? extends SubmitInfo> ctx;


        public AIOHolder() {
            ctx = new LibaioContext<>(LIBAIO_QUEUE_SIZE, true, true);
        }

        public void finalize() {
            ctx.close();
        }
    }

    @Suspendable
    public static AIOFiberFileChannel open(Path path, boolean direct) throws IOException {
        return new AIOFiberFileChannel(aioContext.openFile(path.toString(), direct));
    }

    @Override
    public final boolean isOpen() {
        return file == null;
    }

    @Override
    @Suspendable
    public void close() throws IOException {
        file.close();
    }

    @Override
    public long position() throws IOException {
        return position;
    }

    @Override
    public AIOFiberFileChannel position(long newPosition) throws IOException {
        this.position = newPosition;
        return this;
    }


    @Suspendable
    public int read(final ByteBuffer dst, final long position) throws IOException {
        return new CassandraFiberAsyncIO<Integer>() {
            @Override
            protected void requestAsync() {
                try
                {
                    file.read(position, dst.capacity(), dst, makeCallback());
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                }
            }
        }.runSneaky();
    }

    @Override
    @Suspendable
    public int read(ByteBuffer dst) throws IOException {
        final int bytes = read(dst, position);
        position(position + bytes);
        return bytes;
    }


    @Override
    @Suspendable
    public final long read(ByteBuffer[] dsts) throws IOException {
        return read(dsts, 0, dsts.length);
    }

    @Override
    @Suspendable
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        long r = 0;
        for (int i = 0; i < length; i++)
            r += read(dsts[offset + i]);
        return r;
    }


    @Suspendable
    public int write(final ByteBuffer src, final long position) throws IOException {
        return new CassandraFiberAsyncIO<Integer>() {
            @Override
            protected void requestAsync() {
                ac.write(src, position, null, makeCallback());
            }
        }.runSneaky();
    }

    @Override
    @Suspendable
    public int write(ByteBuffer src) throws IOException {
        final int bytes = write(src, position);
        position(position + bytes);
        return bytes;
    }

    @Override
    @Suspendable
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        long r = 0;
        for (int i = 0; i < length; i++)
            r += write(srcs[offset + i]);
        return r;
    }

    @Override
    @Suspendable
    public final long write(ByteBuffer[] srcs) throws IOException {
        return write(srcs, 0, srcs.length);
    }

    @Override
    public long size() throws IOException {
        return ac.size();
    }

    @Suspendable
    public FileLock lock(final long position, final long size, final boolean shared) throws IOException {
        return new CassandraFiberAsyncIO<FileLock>() {
            @Override
            protected void requestAsync() {
                ac.lock(position, size, shared, null, makeCallback());
            }
        }.runSneaky();
    }

    public void force(boolean metaData) throws IOException {
        ac.force(metaData);
    }

    @Override
    public AIOFiberFileChannel truncate(long size) throws IOException {
        ac.truncate(size);
        return this;
    }

    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        return ac.tryLock(position, size, shared);
    }

    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        throw new UnsupportedOperationException();
    }

    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        throw new UnsupportedOperationException();
    }

    public MappedByteBuffer map(FileChannel.MapMode mode, long position, long size) throws IOException {
        throw new UnsupportedOperationException();
    }
}
