package com.localwebfilter.proxy;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Minimal IPv4 / IPv6 + TCP/UDP packet view over a raw tun buffer, used by the
 * always-on VPN to splice app traffic onto the local filtering proxy.
 */
public final class Packet {

    public static final int TCP = 6;
    public static final int UDP = 17;
    public static final int ICMP = 1;

    public int protocol;
    public byte[] srcIp;   // 4 or 16 bytes
    public byte[] dstIp;
    public int srcPort;
    public int dstPort;
    /** For TCP: header fields below. */
    public int seq, ack;
    public int tcpFlags;
    public int tcpHdrLen;      // bytes
    public int payloadLen;     // bytes after L4 header
    public int payloadOff;     // offset into the original buffer
    public int totalLen;       // bytes parsed from buffer

    private static int u8(byte[] b, int i) { return b[i] & 0xFF; }
    private static int u16(byte[] b, int i) { return (u8(b, i) << 1) | u8(b, i + 1); }

    public static Packet parse(byte[] buf, int len) {
        if (len < 20) return null;
        Packet p = new Packet();
        p.totalLen = len;
        int version = u8(buf, 0) >>> 4;
        if (version == 4) {
            int ihl = (u8(buf, 0) & 0x0F) * 4;
            if (ihl < 20 || len < ihl) return null;
            p.protocol = u8(buf, 9);
            p.srcIp = new byte[]{buf[12], buf[13], buf[14], buf[15]};
            p.dstIp = new byte[]{buf[16], buf[17], buf[18], buf[19]};
            int l4off = ihl;
            int l4len = len - l4off;
            if (!readL4(p, buf, l4off, l4len)) return null;
            return p;
        } else if (version == 6) {
            if (len < 40) return null;
            int next = u8(buf, 6);
            int off = 40;
            // skip simple extension headers (hop-by-hop 0, routing 43, frag 44, dest opts 60)
            while (off + 8 <= len && (next == 0 || next == 43 || next == 44 || next == 60 || next == 51)) {
                int hdrlen = (u8(buf, off + 1) + 1) * 8;
                if (next == 44) hdrlen = 8; // fragment header is fixed 8 bytes
                next = u8(buf, off);
                off += hdrlen;
            }
            p.protocol = next;
            p.srcIp = new byte[16];
            p.dstIp = new byte[16];
            System.arraycopy(buf, 8, p.srcIp, 0, 16);
            System.arraycopy(buf, 24, p.dstIp, 0, 16);
            if (!readL4(p, buf, off, len - off)) return null;
            return p;
        }
        return null;
    }

    private static boolean readL4(Packet p, byte[] buf, int off, int avail) {
        if (p.protocol == TCP) {
            if (avail < 20) return false;
            p.srcPort = u16(buf, off);
            p.dstPort = u16(buf, off + 2);
            p.seq = be32(buf, off + 4);
            p.ack = be32(buf, off + 8);
            p.tcpHdrLen = (u8(buf, off + 12) >>> 4) * 4;
            p.tcpFlags = u8(buf, off + 13);
            int pay = avail - p.tcpHdrLen;
            p.payloadOff = off + p.tcpHdrLen;
            p.payloadLen = Math.max(0, pay);
            return true;
        }
        if (p.protocol == UDP) {
            if (avail < 8) return false;
            p.srcPort = u16(buf, off);
            p.dstPort = u16(buf, off + 2);
            p.payloadOff = off + 8;
            p.payloadLen = Math.max(0, Math.min(u16(buf, off + 4) - 8, avail - 8));
            return true;
        }
        // ICMP etc.: we just RST/close it at the VPN layer
        p.payloadOff = off;
        p.payloadLen = Math.max(0, avail);
        return true;
    }

    public boolean isV4() { return srcIp.length == 4; }

    public String dstHost() {
        try {
            return InetAddress.getByAddress(dstIp).getHostAddress();
        } catch (UnknownHostException e) {
            return "0.0.0.0";
        }
    }

    public String srcHost() {
        try {
            return InetAddress.getByAddress(srcIp).getHostAddress();
        } catch (UnknownHostException e) {
            return "0.0.0.0";
        }
    }

    static int be32(byte[] b, int i) {
        return (u8(b, i) << 24) | (u8(b, i + 1) << 16) | (u8(b, i + 2) << 8) | u8(b, i + 3);
    }

    // ---------------------------------------------------------------- build

    /** Build an IPv4+TCP header-only packet (ACK/RST/syn-ack style replies). */
    public static byte[] tcpPacket(byte[] dstIp, int dstPort, byte[] srcIp, int srcPort,
                                   int seq, int ack, int flags) {
        byte[] o = new byte[40];
        o[0] = 0x45;
        o[1] = 0;
        put16(o, 2, 40);
        put16(o, 4, 0);
        o[6] = 0x40; o[7] = 0;
        o[8] = 64;
        o[9] = (byte) TCP;
        put16(o, 10, 0); // checksum filled below
        System.arraycopy(srcIp, 0, o, 12, 4);
        System.arraycopy(dstIp, 0, o, 16, 4);
        put16(o, 20, srcPort);
        put16(o, 22, dstPort);
        put32(o, 24, seq);
        put32(o, 28, ack);
        o[32] = (byte) 0x50;
        o[33] = (byte) flags;
        put16(o, 34, 65535);
        put16(o, 36, 0);
        put16(o, 20 + 16, tcpChecksum(o, 20, 20));
        put16(o, 10, ipChecksum(o, 0, 20));
        return o;
    }

    /** Build an IPv4 + UDP packet with the given payload (DNS answers). */
    public static byte[] udpPacket(byte[] dstIp, int dstPort, byte[] srcIp, int srcPort, byte[] payload) {
        int total = 20 + 8 + payload.length;
        byte[] o = new byte[total];
        o[0] = 0x45;
        put16(o, 2, total);
        o[6] = 0x40;
        o[8] = 64;
        o[9] = (byte) UDP;
        System.arraycopy(srcIp, 0, o, 12, 4);
        System.arraycopy(dstIp, 0, o, 16, 4);
        put16(o, 20, srcPort);
        put16(o, 22, dstPort);
        put16(o, 24, 8 + payload.length);
        System.arraycopy(payload, 0, o, 28, payload.length);
        int uc = udpChecksum(o, 20, 8 + payload.length, srcIp, dstIp);
        if (uc == 0) uc = 0xFFFF; // UDP: 0 means "no checksum"
        put16(o, 20 + 6, uc);
        put16(o, 10, ipChecksum(o, 0, 20));
        return o;
    }

    public static byte[] v4(String a) {
        String[] sp = a.split("\\.");
        return new byte[]{(byte) Integer.parseInt(sp[0]), (byte) Integer.parseInt(sp[1]),
                (byte) Integer.parseInt(sp[2]), (byte) Integer.parseInt(sp[3])};
    }

    /** Copy payload of an incoming TCP segment into a fresh outbound packet. */
    public static byte[] withPayload(byte[] headerOnly, byte[] payload, int off, int len) {
        int hl = headerOnly.length;
        byte[] o = new byte[hl + len];
        System.arraycopy(headerOnly, 0, o, 0, hl);
        System.arraycopy(payload, off, o, hl, len);
        // fix IP total length + checksums
        put16(o, 2, o.length);
        put16(o, 10, 0);
        int l4 = (o[0] & 0x0F) * 4;
        put16(o, l4 + 16, 0);
        put16(o, l4 + 16, tcpChecksum(o, l4, o.length - l4));
        put16(o, 10, ipChecksum(o, 0, l4));
        return o;
    }

    // ------------------------------------------------------------ checksums

    static int ipChecksum(byte[] b, int off, int len) {
        int sum = 0;
        for (int i = off; i < off + len - 1; i += 2) sum += u16(b, i);
        if ((len & 1) != 0) sum += (b[off + len - 1] & 0xFF) << 8;
        while ((sum >>> 16) != 0) sum = (sum & 0xFFFF) + (sum >>> 16);
        return ~sum & 0xFFFF;
    }

    static int tcpChecksum(byte[] b, int l4off, int l4len) {
        return pseudoChecksum(b, l4off, l4len, b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], TCP);
    }

    static int udpChecksum(byte[] b, int l4off, int l4len,
                           byte[] src, byte[] dst, int proto) {
        return pseudoChecksumFromAddr(b, l4off, l4len, src, dst, proto);
    }

    private static int pseudoChecksum(byte[] b, int l4off, int l4len,
                                      byte s0, byte s1, byte s2, byte s3,
                                      byte d0, byte d1, byte d2, byte d3, int proto) {
        int sum = 0;
        sum += ((s0 & 0xFF) << 8 | (s1 & 0xFF));
        sum += ((s2 & 0xFF) << 8 | (s3 & 0xFF));
        sum += ((d0 & 0xFF) << 8 | (d1 & 0xFF));
        sum += ((d2 & 0xFF) << 8 | (d3 & 0xFF));
        sum += proto;
        sum += l4len;
        for (int i = l4off; i < l4off + l4len - 1; i += 2) sum += u16(b, i);
        if ((l4len & 1) != 0) sum += (b[l4off + l4len - 1] & 0xFF) << 8;
        while ((sum >>> 16) != 0) sum = (sum & 0xFFFF) + (sum >>> 16);
        int c = ~sum & 0xFFFF;
        return c == 0 ? 0xFFFF : c;
    }

    private static int pseudoChecksumFromAddr(byte[] b, int l4off, int l4len,
                                              byte[] src, byte[] dst, int proto) {
        return pseudoChecksum(b, l4off, l4len,
                src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], proto);
    }

    static void put16(byte[] b, int i, int v) {
        b[i] = (byte) (v >>> 8);
        b[i + 1] = (byte) v;
    }

    static void put32(byte[] b, int i, int v) {
        b[i] = (byte) (v >>> 24);
        b[i + 1] = (byte) (v >>> 16);
        b[i + 2] = (byte) (v >>> 8);
        b[i + 3] = (byte) v;
    }
}
