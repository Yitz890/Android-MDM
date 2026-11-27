package com.localwebfilter.proxy;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;

/** Small helpers for socket read timeouts (mirrors the Windows proxy's idle cutoffs). */
public final class Timeout {

    private Timeout() {}

    public static void in(Socket s, int millis) {
        try { s.setSoTimeout(millis); } catch (IOException ignored) {}
    }

    /** Clears the timeout once a tunnel is established so long downloads survive. */
    public static void off(Socket s) {
        try { s.setSoTimeout(0); } catch (IOException ignored) {}
    }

    public static boolean isTimeout(Throwable t) {
        return t instanceof SocketTimeoutException;
    }
}
