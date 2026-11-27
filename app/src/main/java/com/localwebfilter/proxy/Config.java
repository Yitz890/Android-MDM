package com.localwebfilter.proxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Central configuration + state, mirroring the file layout of the upstream
 * Windows "Local Web Filter" app (config.json / allowed_sites.txt /
 * blocked_sites.txt / approvals) but stored in the app-private directory so it
 * survives as long as the app data exists.
 *
 * Secrets (website access PIN, admin/removal PIN) are only kept as salted
 * PBKDF2-SHA256 hashes, exactly like install.json / config.json upstream.
 */
public final class Config {

    public static final String PREFS = "lwf_prefs";

    // Same default ports as the Windows filter/guard services.
    public static final int PROXY_PORT = 18765;   // the filtering proxy
    public static final int UI_PORT = 18766;      // guard/admin endpoint (/approve)

    public static final String MODE_ALLOWLIST = "allowlist";
    public static final String MODE_BLOCKLIST = "blocklist";

    private static final int PBKDF2_ITERS = 120_000;
    private static final int PBKDF2_LEN = 32;

    /** The one app that is always reachable so the child can request access. */
    public static final String SELF_PACKAGE = "com.localwebfilter.proxy";

    /** Packages whose screens are guarded (settings / installs / debugging). */
    public static final String[] GUARD_PKGS = {
            "com.android.settings", "com.samsung.android.settings",
            "com.google.android.settings.intelligence", "com.android.systemui",
            "com.android.vending", "com.google.android.packageinstaller",
            "com.android.permissioncontroller", "com.google.android.packageinstaller"
    };

    private static Config sInstance;
    private final File dir;
    private final SharedPreferences prefs;

    // ---- live state (guarded by `this`) -------------------------------------
    private final Map<String, Long> approvals = new HashMap<>();   // site -> expiry millis (0 = forever)
    private final Set<String> pendingRequests = new LinkedHashSet<>(); // sites shown on the block page
    private final List<String> recentHosts = new ArrayList<>();    // last hosts seen (for pinning)
    private long lastWrongPinAt;
    private int wrongPinStreak;
    private long blocklistUntil; // temporary global blocklist pause (pin on block page)

    public static synchronized Config get(Context c) {
        if (sInstance == null) sInstance = new Config(c.getApplicationContext());
        return sInstance;
    }

    /** Same as get() but never creates: returns null before the app context exists. */
    public static synchronized Config peek() {
        return sInstance;
    }

    private Config(Context c) {
        dir = new File(c.getFilesDir(), "state");
        if (!dir.exists()) dir.mkdirs();
        prefs = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        loadApprovals();
        // first run defaults
        if (!prefs.contains("mode")) setMode(MODE_BLOCKLIST);
        if (!prefs.contains("usb_block")) setUsbBlock(true);
        if (!prefs.contains("unknown_sources_block")) setUnknownSourcesBlock(true);
        if (!prefs.contains("accessibility_block")) setAccessibilityBlock(true);
        if (!prefs.contains("uninstall_block")) setUninstallBlock(true);
        if (!prefs.contains("cleardata_block")) setClearDataBlock(true);
        if (!prefs.contains("settings_block")) setSettingsBlock(true);
        if (!prefs.contains("play_block")) setPlayBlock(true);
        if (!prefs.contains("always_on")) setAlwaysOn(true);
    }

    // ---- simple boolean/string settings ------------------------------------

    public String getMode() { return prefs.getString("mode", MODE_BLOCKLIST); }
    public synchronized void setMode(String m) { prefs.edit().putString("mode", m).apply(); }

    public boolean isAllowlist() { return MODE_ALLOWLIST.equals(getMode()); }

    public boolean getUsbBlock() { return prefs.getBoolean("usb_block", true); }
    public synchronized void setUsbBlock(boolean v) { prefs.edit().putBoolean("usb_block", v).apply(); }

    public boolean getUnknownSourcesBlock() { return prefs.getBoolean("unknown_sources_block", true); }
    public synchronized void setUnknownSourcesBlock(boolean v) { prefs.edit().putBoolean("unknown_sources_block", v).apply(); }

    public boolean getAccessibilityBlock() { return prefs.getBoolean("accessibility_block", true); }
    public synchronized void setAccessibilityBlock(boolean v) { prefs.edit().putBoolean("accessibility_block", v).apply(); }

    public boolean getUninstallBlock() { return prefs.getBoolean("uninstall_block", true); }
    public synchronized void setUninstallBlock(boolean v) { prefs.edit().putBoolean("uninstall_block", v).apply(); }

    public boolean getClearDataBlock() { return prefs.getBoolean("cleardata_block", true); }
    public synchronized void setClearDataBlock(boolean v) { prefs.edit().putBoolean("cleardata_block", v).apply(); }

    public boolean getSettingsBlock() { return prefs.getBoolean("settings_block", true); }
    public synchronized void setSettingsBlock(boolean v) { prefs.edit().putBoolean("settings_block", v).apply(); }

    public boolean getPlayBlock() { return prefs.getBoolean("play_block", true); }
    public synchronized void setPlayBlock(boolean v) { prefs.edit().putBoolean("play_block", v).apply(); }

    public boolean isAlwaysOn() { return prefs.getBoolean("always_on", true); }
    public synchronized void setAlwaysOn(boolean v) { prefs.edit().putBoolean("always_on", v).apply(); }

    /** Hosts that must never be filtered (Google Play / update endpoints stay alive). */
    public boolean isExemptHost(String host) {
        String h = host.toLowerCase(Locale.US);
        for (String suf : new String[]{
                ".googleapis.com", ".gvt1.com", ".ggpht.com", ".android.com",
                ".google.com", ".googleusercontent.com", ".playstation.com"}) {
            if (h.endsWith(suf)) return true;
        }
        return h.equals("localhost") || h.startsWith("127.") || h.startsWith("10.0.2.");
    }

    // ---- website lists ------------------------------------------------------

    public List<String> getSiteList(String kind) {
        return readLines(new File(dir, kind + "_sites.txt"));
    }

    public synchronized void setSiteList(String kind, List<String> sites) {
        StringBuilder sb = new StringBuilder();
        Set<String> seen = new LinkedHashSet<>();
        for (String s : sites) {
            String d = mainDomain(s.trim());
            if (!d.isEmpty() && seen.add(d)) sb.append(d).append('\n');
        }
        writeText(new File(dir, kind + "_sites.txt"), sb.toString());
    }

    public boolean isInList(String kind, String host) {
        String m = mainDomain(host);
        for (String s : getSiteList(kind)) {
            if (m.equals(s) || m.endsWith("." + s)) return true;
        }
        return false;
    }

    // ---- approvals ----------------------------------------------------------

    public synchronized boolean isApproved(String host) {
        String m = mainDomain(host);
        Long exp = approvals.get(m);
        if (exp == null) return false;
        if (exp != 0L && exp < System.currentTimeMillis()) {
            approvals.remove(m);
            saveApprovals();
            return false;
        }
        return true;
    }

    public synchronized void approve(String host, int minutes) {
        String m = mainDomain(host);
        long exp = minutes <= 0 ? 0L : System.currentTimeMillis() + minutes * 60_000L;
        approvals.put(m, exp);
        pendingRequests.remove(m);
        saveApprovals();
    }

    public synchronized void revoke(String host) {
        approvals.remove(mainDomain(host));
        saveApprovals();
    }

    public synchronized Map<String, Long> approvalsSnapshot() {
        return new HashMap<>(approvals);
    }

    public synchronized void noteBlocked(String host) {
        String m = mainDomain(host);
        if (pendingRequests.size() > 50) pendingRequests.remove(pendingRequests.iterator().next());
        pendingRequests.add(m);
    }

    public synchronized List<String> pendingSnapshot() {
        return new ArrayList<>(pendingRequests);
    }

    public synchronized void noteHost(String host) {
        String m = mainDomain(host);
        if (m.isEmpty()) return;
        recentHosts.remove(m);
        recentHosts.add(0, m);
        while (recentHosts.size() > 25) recentHosts.remove(recentHosts.size() - 1);
    }

    public synchronized List<String> recentHosts() {
        return new ArrayList<>(recentHosts);
    }

    private void loadApprovals() {
        approvals.clear();
        try {
            File f = new File(dir, "approvals.json");
            if (!f.exists()) return;
            JSONObject o = new JSONObject(readText(f));
            JSONArray names = o.names();
            if (names != null) {
                for (int i = 0; i < names.length(); i++) {
                    String k = names.getString(i);
                    approvals.put(k, o.getLong(k));
                }
            }
        } catch (Exception ignored) {}
    }

    private void saveApprovals() {
        try {
            JSONObject o = new JSONObject();
            for (Map.Entry<String, Long> e : approvals.entrySet()) o.put(e.getKey(), e.getValue());
            writeText(new File(dir, "approvals.json"), o.toString());
        } catch (Exception ignored) {}
    }

    // ---- PINs (PBKDF2-SHA256, salted) --------------------------------------

    public boolean hasAccessPin() { return prefs.getString("pin_access", null) != null; }
    public boolean hasAdminPin() { return prefs.getString("pin_admin", null) != null; }

    public synchronized void setAccessPin(String pin) { prefs.edit().putString("pin_access", hash(pin)).apply(); }
    public synchronized void setAdminPin(String pin) { prefs.edit().putString("pin_admin", hash(pin)).apply(); }

    public synchronized boolean checkAccessPin(String pin) {
        String want = prefs.getString("pin_access", null);
        return want != null && verify(pin, want);
    }

    public synchronized boolean checkAdminPin(String pin) {
        String want = prefs.getString("pin_admin", null);
        return want != null && verify(pin, want);
    }

    /** Block-page lockout: 5 wrong tries pauses approvals, growing each time. */
    public synchronized boolean approvalLocked() {
        if (blocklistUntil > System.currentTimeMillis()) return true;
        long pause = wrongPauseMillis();
        return wrongPinStreak >= 5 && System.currentTimeMillis() - lastWrongPinAt < pause;
    }

    public synchronized long approvalLockRemainingMs() {
        if (blocklistUntil > System.currentTimeMillis()) return blocklistUntil - System.currentTimeMillis();
        long pause = wrongPauseMillis();
        long left = lastWrongPinAt + pause - System.currentTimeMillis();
        return wrongPinStreak >= 5 ? Math.max(0, left) : 0;
    }

    private long wrongPauseMillis() {
        int steps = Math.max(0, wrongPinStreak - 5);
        return Math.min(3_600_000L, 300_000L << Math.min(steps, 4));
    }

    public synchronized void recordWrongPin() {
        if (wrongPinStreak < 5) lastWrongPinAt = System.currentTimeMillis();
        else if (approvalLocked()) { /* keep counting, lengthens pause */ }
        else lastWrongPinAt = System.currentTimeMillis();
        wrongPinStreak++;
    }

    public synchronized void clearWrongPins() { wrongPinStreak = 0; }

    public synchronized void pauseBlocklist(long ms) {
        blocklistUntil = System.currentTimeMillis() + ms;
    }

    public synchronized boolean blocklistPaused() { return blocklistUntil > System.currentTimeMillis(); }

    // ---- helpers ------------------------------------------------------------

    /** open.spotify.com/search -> spotify.com ; keeps ip literals intact. */
    public static String mainDomain(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.US);
        int colon = h.indexOf(':');
        if (colon > 0) h = h.substring(0, colon);
        if (h.isEmpty()) return "";
        // IPv4 literal
        if (h.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return h;
        String[] parts = h.split("\\.");
        if (parts.length <= 2) return h;
        // naive public-suffix handling for common two-level TLDs
        if (parts.length >= 3) {
            String last = parts[parts.length - 1];
            String second = parts[parts.length - 2];
            if (last.length() == 2 && (second.equals("co") || second.equals("com")
                    || second.equals("org") || second.equals("net") || second.equals("gov"))) {
                return second + "." + last + "." + parts[parts.length - 3];
            }
        }
        return parts[parts.length - 2] + "." + last;
    }

    private static String hash(String secret) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] dk = pbkdf2(secret.getBytes(StandardCharsets.UTF_8), salt);
        return Base64.encodeToString(salt, Base64.NO_WRAP) + ":" + Base64.encodeToString(dk, Base64.NO_WRAP);
    }

    private static boolean verify(String secret, String stored) {
        try {
            String[] sp = stored.split(":");
            byte[] salt = Base64.decode(sp[0], Base64.NO_WRAP);
            byte[] want = Base64.decode(sp[1], Base64.NO_WRAP);
            byte[] got = pbkdf2(secret.getBytes(StandardCharsets.UTF_8), salt);
            return MessageDigest.isEqual(want, got);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] pbkdf2(byte[] pw, byte[] salt) {
        try {
            javax.crypto.SecretKeyFactory f = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                    new String(pw, StandardCharsets.UTF_8).toCharArray(), salt, PBKDF2_ITERS, PBKDF2_LEN * 8);
            return f.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private List<String> readLines(File f) {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) out.add(line);
            }
        } catch (Exception ignored) {}
        return out;
    }

    private String readText(File f) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
        } catch (Exception ignored) {}
        return sb.toString();
    }

    private void writeText(File f, String text) {
        try (FileOutputStream o = new FileOutputStream(f)) {
            o.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {}
    }

    public File stateDir() { return dir; }

    /** Sites currently expired-but-present, used by the ProxyService sweeper. */
    public synchronized Set<String> expiredSites() {
        Set<String> gone = new HashSet<>();
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Long> e : approvals.entrySet()) {
            if (e.getValue() != 0L && e.getValue() < now) gone.add(e.getKey());
        }
        if (!gone.isEmpty()) {
            for (String s : gone) approvals.remove(s);
            saveApprovals();
        }
        return gone;
    }

    public static List<String> sorted(Set<String> in) {
        List<String> l = new ArrayList<>(in);
        Collections.sort(l);
        return l;
    }
}
