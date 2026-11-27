package com.localwebfilter.proxy;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Shared worker pool for proxy connections. */
public final class Workers {
    private static final ExecutorService POOL = new ThreadPoolExecutor(
            4, 256, 30L, TimeUnit.SECONDS,
            new SynchronousQueue<>(),
            r -> {
                Thread t = new Thread(r, "lwf-worker");
                t.setDaemon(true);
                return t;
            },
            new ThreadPoolExecutor.DiscardPolicy());

    private Workers() {}

    public static void execute(Runnable r) { POOL.execute(r); }
}
