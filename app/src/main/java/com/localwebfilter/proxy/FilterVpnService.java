package com.localwebfilter.proxy;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Always-on VPN that carries all IP traffic into the local filtering proxy.
 *
 * This is the Android equivalent of the Windows app's "forced through the
 * filter" firewall rules: routes 0.0.0.0/0 + ::/0, blocking mode (no network
 * access if the VPN stops), and every TCP stream is re-spliced onto
 * 127.0.0.1:18765 where {@link FilterProxy} decides allow/block. DNS inside the
 * tunnel is answered with a single virtual address so connections land here and
 * the proxy resolves the real hostname from the SNI / Host header.
 */
public class FilterVpnService extends VpnService {

    public static volatile boolean vpnUp;
    private static final Object LOCK = new Object();
    private static ParcelFileDescriptor tun;
    private static Thread tunThread;
    private static LocalForwarder forwarder;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        synchronized (LOCK) {
            if (!vpnUp) establish();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    /** Tear down the tunnel. Only called after a PIN-verified unlock. */
    public static void shutdown() {
        synchronized (LOCK) {
            vpnUp = false;
            try { if (tun != null) tun.close(); } catch (IOException ignored) {}
            tun = null;
            if (forwarder != null) { forwarder.stop(); forwarder = null; }
            if (tunThread != null) { tunThread.interrupt(); tunThread = null; }
        }
    }

    private void establish() {
        try {
            Builder b = new Builder()
                    .setSession("Local Web Filter")
                    .addAddress("10.66.66.1", 32)
                    .addDnsServer("10.66.66.1")
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .setMtu(16384)
                    .setBlocking(true);
            // our own sockets bypass the tunnel (avoids routing loops)
            b.addAllowedApplication(Config.SELF_PACKAGE);
            // Play Store + GMS stay reachable so pinned installs keep working
            for (String p : new String[]{"com.android.vending", "com.google.android.gms"}) {
                try { b.addDisallowedApplication(p); } catch (Exception ignored) {}
            }

            ParcelFileDescriptor fd = b.establish();
            if (fd == null) { Log.write("establish returned null"); return; }
            tun = fd;
            vpnUp = true;

            forwarder = new LocalForwarder();
            forwarder.start();

            tunThread = new Thread(this::pumpPackets, "lwf-tun");
            tunThread.setDaemon(true);
            tunThread.start();
            Log.write("VPN established: all traffic -> 127.0.0.1:" + Config.PROXY_PORT);
            Guard.notifyVpnUp(this);
        } catch (Exception e) {
            Log.write("establish failed: " + e);
        }
    }

    private void pumpPackets() {
        InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(tun) { };
        java.io.OutputStream out = new ParcelFileDescriptor.AutoCloseOutputStream(dup(tun));
        byte[] buf = new byte[16384];
        while (vpnUp) {
            int n;
            try { n = in.read(buf); } catch (IOException e) { break; }
            if (n <= 0) continue;
            Packet p = Packet.parse(buf, n);
            if (p == null) continue;
            if (p.protocol == Packet.UDP && (p.dstPort == 53 || p.srcPort == 53)) {
                Dns.answer(p, out);
                continue;
            }
            if (p.protocol == Packet.TCP) {
                Streams.accept(p, out);
            }
        }
        vpnUp = false;
    }

    private static ParcelFileDescriptor dup(ParcelFileDescriptor fd) {
        try { return ParcelFileDescriptor.dup(fd.getFileDescriptor()); }
        catch (IOException e) { return fd; }
    }

    public static Intent intent(Context c) { return new Intent(c, FilterVpnService.class); }

    @Override
    public android.os.IBinder onBind(Intent intent) { return null; }
}
