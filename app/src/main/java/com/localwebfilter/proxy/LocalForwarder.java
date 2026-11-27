package com.localwebfilter.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Local TCP forwarder. The VPN writes every intercepted stream into a
 * {@link TunSink}; the sink connects here and speaks the normal HTTP proxy
 * protocol to 127.0.0.1:18765 ({@link FilterProxy}). Keeping this as a plain
 * loopback socket means the proxy code is identical whether traffic arrives via
 * the VPN or via a manually configured Wi-Fi proxy (parity with the Windows app,
 * where the system proxy points at 127.0.0.1:18765).
 */
public final class LocalForwarder implements Runnable {

    public static volatile boolean running;
    private ServerSocket server;
    private Thread thread;

    public synchronized void start() {
        if (running) return;
        running = true;
        thread = new Thread(this, "lwf-forward");
        thread.setDaemon(true);
        thread.start();
    }

    public synchronized void stop() {
        running = false;
        try { if (server != null) server.close(); } catch (IOException ignored) {}
    }

    @Override
    public void run() {
        try {
            server = new ServerSocket(Config.UI_PORT + 1000, 64, InetAddress.getByName("127.0.0.1"));
        } catch (IOException e) {
            Log.write("forwarder bind failed: " + e);
            return;
        }
        while (running) {
            try {
                Socket s = server.accept();
                Workers.execute(() -> splice(s));
            } catch (IOException e) {
                if (running) Log.write("forward accept: " + e);
            }
        }
    }

    /** Copy bytes both directions between the tun-side socket and the proxy. */
    private static void splice(Socket tunSide) {
        Socket up = null;
        try {
            up = new Socket(InetAddress.getByName("127.0.0.1"), Config.PROXY_PORT);
            final Socket u = up;
            Thread t = new Thread(() -> copy(tunSide, u), "splice-up");
            t.setDaemon(true);
            t.start();
            copy(u, tunSide);
        } catch (IOException ignored) {
        } finally {
            try { tunSide.close(); } catch (IOException ignored) {}
            try { if (up != null) up.close(); } catch (IOException ignored) {}
        }
    }

    private static void copy(Socket a, Socket b) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = a.getInputStream();
            OutputStream out = b.getOutputStream();
            int n;
            while ((n = in.read(buf)) > 0) { out.write(buf, 0, n); out.flush(); }
        } catch (IOException ignored) {
        } finally {
            try { b.shutdownOutput(); } catch (IOException ignored) {}
        }
    }
}
