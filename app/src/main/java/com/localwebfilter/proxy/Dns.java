package com.localwebfilter.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Tiny DNS codec used by the VPN: parses a query name, builds answers from the
 * real system resolver (so filtering still happens on hostname), or fabricates
 * an A record pointing at the fake tunnel range when we want to force traffic
 * into {@link Streams}.
 */
public final class Dns {

    private static final byte[] FAKE_BASE = Packet.v4("10.66.0.0"); // 10.66.x.y pool

    private Dns() {}

    /** Write a reply for the parsed query packet onto the tun output. */
    public static void answer(Packet q, byte[] raw, int rawLen, OutputStream tun) {
        try {
            byte[] query = new byte[q.payloadLen];
            System.arraycopy(raw, q.payloadOff, query, 0, q.payloadLen);
            byte[] reply = buildReply(query, resolveFor(q, query));
            if (reply == null) return;
            byte[] pkt = Packet.udpPacket(q.srcIp, q.srcPort, q.dstIp, q.dstPort, reply);
            synchronized (tun) {
                tun.write(pkt);
                tun.flush();
            }
        } catch (IOException ignored) {
        } catch (Throwable t) {
            Log.write("dns: " + t);
        }
    }

    /**
     * Resolve the queried hostname normally. If resolution fails we answer with
     * a synthetic address in the fake pool so the TCP connection still lands in
     * Streams and the proxy can block it by SNI/Host (and log the attempt).
     */
    private static String resolveFor(Packet q, byte[] query) {
        String name = queryName(query);
        if (name != null && !name.isEmpty()) {
            try {
                InetAddress[] all = InetAddress.getAllByName(name);
                for (InetAddress a : all) {
                    if (a instanceof java.net.Inet4Address) return a.getHostAddress();
                }
            } catch (UnknownHostException ignored) {}
        }
        // synthetic fallback derived from the name hash -> 10.66.x.y
        int h = name == null ? 0 : Math.abs(name.hashCode());
        return "10.66." + ((h >>> 8) & 0xFF) + "." + (h & 0xFF);
    }

    /** Extract the QNAME from a raw DNS query payload. */
    public static String queryName(byte[] raw) {
        if (raw == null || raw.length < 13) return null;
        int p = 12; // skip 12-byte DNS header
        StringBuilder sb = new StringBuilder();
        while (p < raw.length) {
            int len = raw[p] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) break; // compression not expected in queries
            if (sb.length() > 0) sb.append('.');
            int avail = Math.min(len, raw.length - p - 1);
            sb.append(new String(raw, p + 1, avail).toLowerCase());
            p += 1 + len;
        }
        return sb.toString();
    }

    /** Build a DNS response (QR=1, RA=1) with one or two A records. */
    private static byte[] buildReply(byte[] query, String ipV4) {
        // header: copy query id+flags->response, counts: 1 question, 1 answer
        ByteBuffer in = ByteBuffer.wrap(query);
        int id = in.getShort() & 0xFFFF;
        in.getShort(); // flags
        int qd = in.getShort();
        in.position(12);
        // read question section bytes (name + type + class)
        int start = 12;
        int p = start;
        while (p < query.length) {
            int l = query[p] & 0xFF;
            if (l == 0) { p++; break; }
            if ((l & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + l;
        }
        p += 4; // qtype + qclass
        if (p > query.length) return null;
        byte[] question = new byte[p - start];
        System.arraycopy(query, start, question, 0, question.length);

        byte[] ip;
        try {
            ip = InetAddress.getByName(ipV4).getAddress();
        } catch (UnknownHostException e) {
            ip = FAKE_BASE;
        }
        boolean isV4 = ip.length == 4;

        // answer: pointer to name (C0 0C), type A(1)/AAAA(28), class IN, ttl 60, rdlength, data
        byte[] ans = new byte[4 + 4 + 2 + ip.length];
        ans[0] = (byte) 0xC0; ans[1] = 0x0C;
        short type = (short) (isV4 ? 1 : 28);
        ans[2] = (byte) (type >> 8); ans[3] = (byte) type;
        ans[4] = 0; ans[5] = 1;              // class IN
        ans[6] = 0; ans[7] = 0; ans[8] = 0; ans[9] = 60; // ttl
        ans[10] = (byte) (ip.length >> 8); ans[11] = (byte) ip.length;
        System.arraycopy(ip, 0, ans, 12, ip.length);

        int total = 12 + question.length + ans.length;
        ByteBuffer out = ByteBuffer.allocate(total);
        out.putShort((short) id);
        out.putShort((short) 0x8180);         // response, recursion available
        out.putShort((short) Math.max(1, qd));
        out.putShort((short) 1);
        out.putShort((short) 0);
        out.putShort((short) 0);
        out.put(question);
        out.put(ans);
        return out.array();
    }
}
