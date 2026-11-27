package com.localwebfilter.proxy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * The admin/guard side of the app, mirroring the Windows guard service on
 * 127.0.0.1:18766. Two jobs:
 *
 *  1. Local HTTP API used by the setup/management UI and by external tooling:
 *       GET  /status      -> json state (mode, vpn up, lists, approvals)
 *       POST /approve     -> {site,pin,minutes|permanent}   (access PIN)
 *       POST /revoke      -> {site, admin_pin}              (removal PIN)
 *       POST /config      -> full config update             (removal PIN)
 *       POST /unlock      -> {admin_pin} -> ok (enables uninstall/clear-data)
 *       POST /blockpage   -> custom block page html         (removal PIN)
 *
 *  2. Static helpers for the DeviceAdminReceiver / AccessibilityService guards:
 *     whether a given foreground package/screen must be bounced, and the
 *     "verified" gate that only lets an admin-PIN unlock disarm protections.
 */
public final class Guard implements Runnable {

    public static volatile boolean running;
    private static Context appCtx;
    private static ServerSocket server;
    /** Set true only after a correct admin PIN; auto-expires in 60s. */
    private static volatile long unlockedUntil;

    private Guard() {}

    public static void notifyVpnUp(Context c) {
        appCtx = c.getApplicationContext();
        Log.write("vpn up");
    }

    public static synchronized void start(Context c) {
        if (running) return;
        appCtx = c.getApplicationContext();
        running = true;
        Thread t = new Thread(new Guard(), "lwf-guard");
        t.setDaemon(true);
        t.start();
    }

    public static synchronized void stop() {
        running = false;
        try { if (server != null) server.close(); } catch (IOException ignored) {}
    }

    @Override
    public void run() {
        try {
            server = new ServerSocket(Config.UI_PORT, 16, InetAddress.getByName("127.0.0.1"));
        } catch (IOException e) {
            Log.write("guard bind failed: " + e);
            return;
        }
        Log.write("guard listening on 127.0.0.1:" + Config.UI_PORT);
        while (running) {
            try {
                Socket s = server.accept();
                Workers.execute(() -> serve(s));
            } catch (IOException e) {
                if (running) Log.write("guard accept: " + e);
            }
        }
    }

    // ------------------------------------------------------------- guard rules

    /** True while an admin-PIN unlock is active (uninstall/clear allowed). */
    public static boolean unlocked() { return System.currentTimeMillis() < unlockedUntil; }

    public static void unlock() { unlockedUntil = System.currentTimeMillis() + 60_000L; }

    public static void lock() { unlockedUntil = 0; }

    /** Should this foreground package be bounced away by the accessibility guard? */
    public static boolean shouldBounce(String pkg) {
        Context c = appCtx;
        if (c == null || pkg == null) return false;
        if (pkg.equals(Config.SELF_PACKAGE)) return false;
        if (unlocked()) return false;
        Config cfg = Config.peek();
        if (cfg == null) return false;

        boolean settingsApp = pkg.equals("com.android.settings")
                || pkg.equals("com.samsung.android.settings")
                || pkg.equals("com.google.android.settings.intelligence")
                || pkg.equals("com.android.settings.intelligence");
        if (settingsApp && cfg.getSettingsBlock()) return true;

        // installers & play store
        if ((pkg.equals("com.android.vending") || pkg.contains("packageinstaller")
                || pkg.equals("com.google.android.packageinstaller")) && cfg.getPlayBlock()) {
            return true;
        }
        return false;
    }

    /** Fine-grained screen check using window title text (developer options etc.). */
    public static boolean dangerousScreen(CharSequence title) {
        if (title == null) return false;
        String t = title.toString().toLowerCase(Locale.US);
        Config cfg = Config.peek();
        if (cfg == null || unlocked()) return false;
        if (cfg.getUsbBlock() && (t.contains("developer options") || t.contains("usb debugging")
                || t.contains("wireless debugging") || t.contains("debugging"))) return true;
        if (cfg.getAccessibilityBlock() && t.contains("accessibility")) return true;
        if (cfg.isAlwaysOn() && (t.contains("vpn") || t.contains("private dns")
                || t.contains("always-on vpn"))) return true;
        if (cfg.getUnknownSourcesBlock() && (t.contains("install unknown apps")
                || t.contains("unknown apps") || t.contains("special app access"))) return true;
        if ((cfg.getUninstallBlock() || cfg.getClearDataBlock())
                && (t.contains("app info") || t.contains("app storage")
                    || t.contains("uninstall") || t.contains("clear data")
                    || t.contains("manage apps") || t.contains("device admin"))) return true;
        return false;
    }

    public static void goHome(Context c) {
        try {
            Intent i = new Intent(Intent.ACTION_MAIN);
            i.addCategory(Intent.CATEGORY_HOME);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            c.startActivity(i);
        } catch (Exception ignored) {}
    }

    /** Best-effort: disable unknown-sources for a package if we hold the perm (device owner). */
    public static void revokeInstallSources(Context c, String pkg) {
        try {
            DevicePolicyManager dpm = (DevicePolicyManager)
                    c.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null && dpm.isDeviceOwnerApp(c.getPackageName())) {
                dpm.setSecureSetting(null, Settings.Global.INSTALL_NON_MARKET_APPS, "0");
            }
        } catch (Throwable ignored) {}
        try {
            c.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:" + pkg)).setFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        } catch (Exception ignored) {}
    }

    // -------------------------------------------------------------- local API

    private void serve(Socket client) {
        try {
            Timeout.in(client, 15_000);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));
            OutputStream out = client.getOutputStream();
            String line = in.readLine();
            if (line == null) return;
            String[] sp = line.split(" ");
            if (sp.length < 2) return;
            String method = sp[0], path = sp[1];
            int len = 0;
            String h;
            while ((h = in.readLine()) != null && !h.isEmpty()) {
                if (h.toLowerCase(Locale.US).startsWith("content-length:")) {
                    try { len = Integer.parseInt(h.substring(15).trim()); } catch (Exception ignored) {}
                }
            }
            String body = "";
            if (len > 0) {
                char[] cb = new char[Math.min(len, 1 << 20)];
                int off = 0;
                while (off < cb.length) {
                    int n = in.read(cb, off, cb.length - off);
                    if (n < 0) break;
                    off += n;
                }
                body = new String(cb, 0, off);
            }

            String resp;
            Config cfg = Config.get(appCtx);
            switch (path) {
                case "/status":
                    resp = statusJson(cfg);
                    break;
                case "/approve":
                    resp = approve(cfg, body);
                    break;
                case "/revoke":
                    resp = needAdmin(cfg, body, () -> {
                        String site = FilterProxy.json(body, "site");
                        if (site != null) cfg.revoke(site);
                        return "{\"ok\":true}";
                    });
                    break;
                case "/unlock":
                    resp = needAdmin(cfg, body, () -> {
                        unlock();
                        return "{\"ok\":true,\"seconds\":60}";
                    });
                    break;
                case "/blockpage":
                    resp = needAdmin(cfg, body, () -> {
                        String html = FilterProxy.json(body, "html_b64");
                        if (html != null) {
                            byte[] dec = android.util.Base64.decode(html, android.util.Base64.NO_WRAP);
                            java.io.File f = new java.io.File(cfg.stateDir(), "block_page.html");
                            try (OutputStream fo = new java.io.FileOutputStream(f)) { fo.write(dec); }
                        }
                        return "{\"ok\":true}";
                    });
                    break;
                default:
                    resp = "{\"ok\":false,\"error\":\"not found\"}";
                    break;
            }
            byte[] b = resp.getBytes(StandardCharsets.UTF_8);
            out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + b.length + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.write(b);
            out.flush();
        } catch (Exception ignored) {
        } finally {
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    interface Act { String run(); }

    private static String needAdmin(Config cfg, String body, Act act) {
        String pin = FilterProxy.json(body, "admin_pin");
        if (pin == null || !cfg.checkAdminPin(pin)) return "{\"ok\":false,\"error\":\"bad admin pin\"}";
        return act.run();
    }

    private static String approve(Config cfg, String body) {
        String pin = FilterProxy.json(body, "pin");
        String site = FilterProxy.json(body, "site");
        boolean permanent = "true".equals(FilterProxy.json(body, "permanent"));
        String minStr = FilterProxy.json(body, "minutes");
        if (site == null || site.isEmpty()) return "{\"ok\":false,\"error\":\"no site\"}";
        if (cfg.approvalLocked()) return "{\"ok\":false,\"error\":\"locked\"}";
        if (pin == null || !cfg.checkAccessPin(pin)) { cfg.recordWrongPin(); return "{\"ok\":false,\"error\":\"wrong pin\"}"; }
        cfg.clearWrongPins();
        int minutes = 30;
        try { if (minStr != null) minutes = Integer.parseInt(minStr.trim()); } catch (Exception ignored) {}
        if (permanent) minutes = 0;
        cfg.approve(site, minutes);
        return "{\"ok\":true,\"site\":\"" + Config.mainDomain(site) + "\"}";
    }

    private static String statusJson(Config cfg) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"mode\":\"").append(cfg.getMode())
          .append("\",\"vpn\":").append(FilterVpnService.vpnUp)
          .append(",\"proxy\":").append(FilterProxy.running)
          .append(",\"guard\":").append(running)
          .append(",\"unlocked\":").append(unlocked())
          .append(",\"blocked\":[");
        boolean first = true;
        for (String s : cfg.getSiteList("blocked")) { if (!first) sb.append(','); first = false; sb.append('"').append(s).append('"'); }
        sb.append("],\"allowed\":[");
        first = true;
        for (String s : cfg.getSiteList("allowed")) { if (!first) sb.append(','); first = false; sb.append('"').append(s).append('"'); }
        sb.append("],\"approvals\":{");
        first = true;
        for (java.util.Map.Entry<String, Long> e : cfg.approvalsSnapshot().entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append("\":").append(e.getValue());
        }
        sb.append("},\"pending\":[");
        first = true;
        for (String s : cfg.pendingSnapshot()) { if (!first) sb.append(','); first = false; sb.append('"').append(s).append('"'); }
        sb.append("]}");
        return sb.toString();
    }

    /** Simple GET helper used by the in-app management screen. */
    public static String localGet(int port, String path) {
        try (Socket s = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
            OutputStream o = s.getOutputStream();
            o.write(("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            o.flush();
            ByteArrayOutputStream all = new ByteArrayOutputStream();
            InputStream in = s.getInputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) all.write(buf, 0, n);
            String r = all.toString(StandardCharsets.ISO_8859_1.name());
            int i = r.indexOf("\r\n\r\n");
            return i < 0 ? r : r.substring(i + 4);
        } catch (IOException e) {
            return "{\"ok\":false,\"error\":\"" + e.getMessage() + "\"}";
        }
    }
}
