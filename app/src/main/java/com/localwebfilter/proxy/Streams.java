package com.localwebfilter.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TCP stream splicer for the always-on VPN.
 *
 * The kernel hands us raw packets addressed to real servers. For every new
 * connection we answer the SYN with a SYN-ACK locally, then pipe the client's
 * bytes into 127.0.0.1:{@link Config#PROXY_PORT} (the {@link FilterProxy}) and
 * pipe the proxy's replies back out as properly sequenced tun packets.
 *
 * This is the Android equivalent of Windows' "redirect everything to the local
 * proxy" firewall rule: apps never learn they are being filtered because the
 * hostname travels inside their own TLS SNI / HTTP Host header, which the proxy
 * reads before deciding allow/block.
 */
public final class Streams {

    private static final Map<String, Stream> OPEN = new ConcurrentHashMap<>();
    private static OutputStream tunOut;

    /** Called once by the VPN service when the tunnel comes up. */
    public static void attach(OutputStream tun) { tunOut = tun; }

    public static void detach() {
        for (Stream s : OPEN.values()) s.close();
        OPEN.clear();
        tunOut = null;
    }

    static final class Stream {
        byte[] cliIp;      // phone-side address (dst of inbound pkts)
        int cliPort;
        byte[] srvIp;      // original destination address
        int srvPort;
        int nextSeq = 1;   // sequence we will send next
        long lastSeen = System.currentTimeMillis();
        Socket proxy;      // connected to 127.0.0.1:18765
        Thread reader;

        void close() {
            lastSeen = 0;
            Socket s = proxy;
            proxy = null;
            if (s != null) { try { s.close(); } catch (IOException ignored) {} }
        }

        String key() {
            return cliPort + ":" + (srvIp[0] & 255) + "." + (srvIp[1] & 255) + "."
                    + (srvIp[2] & 255) + "." + (srvIp[3] & 255) + ":" + srvPort;
        }
    }

    /** Handle one inbound TCP packet; creates/updates the matching stream. */
    public static void accept(Packet p, byte[] raw, OutputStream tun) {
        try {
            if (!p.isV4()) return; // v6 passthrough not spliced (proxy resolves v4)
            String key = key(p);
            Stream s = OPEN.get(key);

            boolean syn = (p.tcpFlags & 0x02) != 0 && (p.tcpFlags & 0x10) == 0;
            boolean fin = (p.tcpFlags & 0x01) != 0;
            boolean rst = (p.tcpFlags & 0x04) != 0;

            if (s == null) {
                if (!syn) {
                    // unknown flow: RST it so the app fails fast instead of hanging
                    send(tun, Packet.tcpPacket(p.srcIp, p.srcPort, p.dstIp, p.dstPort,
                            p.ack, safeAdd(p.seq), 0x04 /*RST*/ | 0x10 /*ACK*/));
                    return;
                }
                s = new Stream();
                s.cliIp = p.srcIp;
                s.cliPort = p.srcPort;
                s.srvIp = p.dstIp;
                s.srvPort = p.dstPort;
                s.nextSeq = (int) (System.nanoTime() & 0x7FFFFFFF);
                OPEN.put(key, s);
                // SYN-ACK: our ISN, ack = client seq + 1
                send(tun, Packet.tcpPacket(s.cliIp, s.cliPort, s.srvIp, s.srvPort,
                        s.nextSeq, safeAdd(p.seq, 1), 0x12 /*SYN|ACK*/));
                s.nextSeq++;
                openProxy(s);
                return;
            }

            s.lastSeen = System.currentTimeMillis();

            if (rst) { s.close(); OPEN.remove(key); return; }

            if (fin) {
                // ACK the FIN and tear the stream down
                send(tun, Packet.tcpPacket(s.cliIp, s.cliPort, s.srvIp, s.srvPort,
                        s.nextSeq, safeAdd(p.seq, Math.max(1, p.payloadLen)), 0x10));
                s.close();
                OPEN.remove(key);
                return;
            }

            if (p.payloadLen > 0) {
                // acknowledge the client's bytes
                send(tun, Packet.tcpPacket(s.cliIp, s.cliPort, s.srvIp, s.srvPort,
                        s.nextSeq, safeAdd(p.seq, p.payloadLen), 0x10 /*ACK*/));
                if (s.proxy != null) {
                    s.proxy.getOutputStream().write(raw, p.payloadOff, p.payloadLen);
                    s.proxy.getOutputStream().flush();
                } else {
                    // proxy socket still opening or already gone: drop, idle reaper cleans up
                }
            } else if ((p.tcpFlags & 0x10) != 0) {
                // pure ACK from client: nothing to do
            }
        } catch (Throwable t) {
            Log.write("streams: " + t);
        }
    }

    private static String key(Packet p) {
        return p.srcPort + ":" + (p.dstIp[0] & 255) + "." + (p.dstIp[1] & 255) + "."
                + (p.dstIp[2] & 255) + "." + (p.dstIp[3] & 255) + ":" + p.dstPort;
    }

    private static void openProxy(Stream s) {
        final OutputStream tun = tunOut;
        s.reader = new Thread(() -> {
            try {
                Socket up = new Socket();
                up.connect(new InetSocketAddress("127.0.0.1", Config.PROXY_PORT), 5000);
                s.proxy = up;
                InputStream in = up.getInputStream();
                byte[] buf = new byte[1400];
                int n;
                while ((n = in.read(buf)) > 0) {
                    byte[] pkt = Packet.withPayload(
                            Packet.tcpPacket(s.cliIp, s.cliPort, s.srvIp, s.srvPort,
                                    s.nextSeq, 0, 0x10 /*ACK*/),
                            buf, 0, n);
                    send(tun, pkt);
                    s.nextSeq += n;
                }
            } catch (IOException ignored) {
            } finally {
                s.proxy = null;
                OPEN.remove(s.key());
            }
        }, "lwf-stream");
        s.reader.setDaemon(true);
        s.reader.start();
    }

    private static void send(OutputStream tun, byte[] pkt) {
        if (tun == null || pkt == null) return;
        try {
            synchronized (tun) {
                tun.write(pkt);
                tun.flush();
            }
        } catch (IOException ignored) {}
    }

    private static int safeAdd(int a, int b) {
        return a + b; // wrap-around is fine: TCP seq arithmetic is modular
    }

    /** Drop streams idle for more than 60s (keeps the map bounded). */
    public static void reapIdle() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Stream> e : OPEN.entrySet()) {
            if (now - e.getValue().lastSeen > 60_000L) {
                e.getValue().close();
                OPEN.remove(e.getKey());
            }
        }
    }

    static final class StreamCloser {
        static void closeAll() { detach(); }
    }
}
