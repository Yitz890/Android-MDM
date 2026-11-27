package com.localwebfilter.proxy;

import android.content.Context;
import android.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The filtering proxy, mirroring core.go of the Windows app:
 *  - listens on 127.0.0.1:18765 (VPN forwards all traffic here)
 *  - CONNECT tunnels for allowed hosts pass through untouched (never decrypted)
 *  - blocked hosts get a man-in-the-middle TLS session carrying the block page
 *    at the site's own address, so "request access" works even on HTTPS
 *  - plain HTTP requests are answered with the block page or proxied
 *  - a sweeper every 3s closes connections whose approval just expired
 */
public final class FilterProxy implements Runnable {

    public static volatile boolean running;
    private static final List<Socket> live = new CopyOnWriteArrayList<>();
    private static final Map<String, SSLSocketFactory> ctxCache = new ConcurrentHashMap<>();

    private final Context ctx;
    private final Config cfg;
    private ServerSocket server;
    private Thread thread;
    private ScheduledExecutorService sweeper;

    // CA material
    private PrivateKey caKey;
    private X509Certificate caCert;
    private byte[] caDer;

    public FilterProxy(Context c) {
        this.ctx = c.getApplicationContext();
        this.cfg = Config.get(ctx);
    }

    public synchronized void start() {
        if (running) return;
        running = true;
        try {
            loadOrMakeCa();
        } catch (Throwable t) {
            Log.write("CA init failed: " + t);
        }
        thread = new Thread(this, "lwf-proxy");
        thread.setDaemon(true);
        thread.start();
        sweeper = Executors.newSingleThreadScheduledExecutor(namedThreadFactory("lwf-sweep"));
        sweeper.scheduleWithFixedDelay(FilterProxy::closeExpired, 3, 3, TimeUnit.SECONDS);
    }

    public synchronized void stop() {
        running = false;
        try { if (server != null) server.close(); } catch (IOException ignored) {}
        for (Socket s : live) { try { s.close(); } catch (IOException ignored) {} }
        live.clear();
        if (sweeper != null) sweeper.shutdownNow();
        if (thread != null) thread.interrupt();
    }

    @Override
    public void run() {
        try {
            server = new ServerSocket(Config.PROXY_PORT, 128, InetAddress.getByName("127.0.0.1"));
        } catch (IOException e) {
            Log.write("proxy bind failed: " + e);
            return;
        }
        Log.write("filter listening on 127.0.0.1:" + Config.PROXY_PORT);
        while (running) {
            try {
                Socket s = server.accept();
                s.setTcpNoDelay(true);
                live.add(s);
                Workers.execute(() -> handle(s));
            } catch (IOException e) {
                if (running) Log.write("accept: " + e);
            }
        }
    }

    /** Every 3 seconds: drop connections to sites whose approval ended. */
    private static void closeExpired() {
        try {
            Config c = Config.peek();
            if (c == null) return;
            java.util.Set<String> gone = c.expiredSites();
            if (gone.isEmpty()) return;
            for (Socket s : live) {
                Object tag = s.getAttachment();
                if (tag instanceof String && gone.contains(Config.mainDomain((String) tag))) {
                    try { s.close(); } catch (IOException ignored) {}
                }
            }
        } catch (Throwable ignored) {}
    }

    // ------------------------------------------------------------------ core

    private void handle(Socket client) {
        String hostTag = null;
        try {
            Timeout.in(client, 30_000);
            BufferedReader in = reader(client.getInputStream());
            OutputStream out = client.getOutputStream();

            RequestLine rl = readHead(in);
            if (rl == null) { close(client); return; }

            String target = rl.target;
            String hostHdr = header(rl.headers, "host");
            String scheme = "http";
            String host = targetHost(target);
            if (host == null || host.isEmpty()) host = hostHdr;
            int port = targetPort(target, 80);
            if ("connect".equalsIgnoreCase(rl.method)) {
                scheme = "https";
                host = targetHost(target);
                port = targetPort(target, 443);
            }
            if (host == null || host.isEmpty()) { close(client); return; }
            host = host.toLowerCase(Locale.US);
            hostTag = host;
            client.setAttachment(host);
            cfg.noteHost(host);

            boolean allow = decide(host);
            Log.write(rl.method + " " + host + " -> " + (allow ? "ALLOW" : "BLOCK"));

            if ("connect".equalsIgnoreCase(rl.method)) {
                if (allow) tunnel(client, in, out, host, port);
                else mitmBlock(client, out, host, port);
            } else {
                String path = target.startsWith("/") ? target : "/";
                if (allow) forwardHttp(client, in, out, rl, host, port);
                else serveBlock(out, host, "http://" + host + path);
            }
        } catch (Throwable t) {
            // clients vanish constantly; only log interesting failures
            String m = String.valueOf(t.getMessage());
            if (!m.contains("reset") && !m.contains("closed") && !m.contains("timeout")) {
                Log.write("handle " + hostTag + ": " + t);
            }
        } finally {
            live.remove(client);
            close(client);
        }
    }

    /** Filtering decision, same rules as core.go's Decide(). */
    private boolean decide(String host) {
        if (cfg.isExemptHost(host)) return true;
        if (cfg.isApproved(host)) return true;
        if (cfg.blocklistPaused()) return false;      // temporary global pause from the block page
        if (cfg.isAllowlist()) {
            return cfg.isInList("allowed", host);     // allow everything except allowed list
        }
        return !cfg.isInList("blocked", host);        // block everything except blocked list
    }

    // ------------------------------------------------------------- CONNECT

    /** Allowed site: raw bidirectional copy. Never decrypted (upstream parity). */
    private void tunnel(Socket client, BufferedReader in, OutputStream out, String host, int port)
            throws IOException {
        Socket up;
        try {
            up = new Socket(InetAddress.getByName(host), port);
        } catch (IOException e) {
            sendStatus(out, 502, "Bad Gateway");
            return;
        }
        out.write("HTTP/1.1 200 Connection Established\r\nProxy-agent: LocalWebFilter\r\n\r\n"
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        live.add(up);
        up.setAttachment(host);
        final Socket cu = up;
        Thread t2 = new Thread(() -> pump(cu, client), "pump-up");
        t2.setDaemon(true);
        t2.start();
        pump(client, cu);
        try { cu.close(); } catch (IOException ignored) {}
    }

    private static void pump(Socket a, Socket b) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = a.getInputStream();
            OutputStream out = b.getOutputStream();
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignored) {
        } finally {
            try { b.shutdownOutput(); } catch (IOException ignored) {}
        }
    }

    /** Blocked site: terminate TLS ourselves and answer with the block page. */
    private void mitmBlock(Socket client, OutputStream rawOut, String host, int port) {
        SSLSocket tls = null;
        try {
            SSLContext sc = contextFor(host);
            if (sc == null) { sendStatus(rawOut, 502, "Bad Gateway"); return; }
            SSLSocketFactory f = sc.getSocketFactory();
            tls = (SSLSocket) f.createSocket(client, host, port, true);
            tls.setUseClientMode(false);
            live.add(tls);
            tls.setAttachment(host);
            tls.startHandshake();
            BufferedReader in = reader(tls.getInputStream());
            RequestLine rl = readHead(in);
            String path = rl == null ? "/" : (rl.target.startsWith("/") ? rl.target : "/");
            String url = "https://" + host + path;
            if (rl != null && rl.body != null && isApiPath(path)) {
                handleApprove(tls.getOutputStream(), rl.body, host, url);
            } else {
                writeBlockPage(tls.getOutputStream(), host, url);
            }
        } catch (IOException e) {
            // browser refused our cert / went away: fall back to killing the tunnel
            try { client.close(); } catch (IOException ignored) {}
        } finally {
            if (tls != null) live.remove(tls);
        }
    }

    // ---------------------------------------------------------- plain HTTP

    private void forwardHttp(Socket client, BufferedReader in, OutputStream out,
                             RequestLine rl, String host, int port) throws IOException {
        Socket up = new Socket(InetAddress.getByName(host), port);
        live.add(up);
        up.setAttachment(host);
        StringBuilder req = new StringBuilder();
        req.append(rl.method).append(' ').append(rl.target).append(" HTTP/1.1\r\n");
        for (String h : rl.headers) {
            String l = h.toLowerCase(Locale.US);
            if (l.startsWith("proxy-connection") || l.startsWith("connection")) continue;
            req.append(h).append("\r\n");
        }
        req.append("Connection: close\r\n\r\n");
        up.getOutputStream().write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (rl.bodyBytes != null && rl.bodyBytes.length > 0) {
            up.getOutputStream().write(rl.bodyBytes);
        }
        up.getOutputStream().flush();
        InputStream uin = up.getInputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = uin.read(buf)) > 0) { out.write(buf, 0, n); out.flush(); }
        up.close();
    }

    private void serveBlock(OutputStream out, String host, String url) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeBlockPage(body, host, url);
        byte[] b = body.toByteArray();
        out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + b.length + "\r\nCache-Control: no-store\r\n"
                + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(b);
        out.flush();
    }

    // ------------------------------------------------------- approve endpoint

    private boolean isApiPath(String path) {
        return path.startsWith("/__lwf/") || path.equals("/approve");
    }

    private void handleApprove(OutputStream out, String jsonBody, String host, String url) throws IOException {
        String pin = json(jsonBody, "pin");
        String site = json(jsonBody, "site");
        String minStr = json(jsonBody, "minutes");
        boolean permanent = "true".equals(json(jsonBody, "permanent"));
        Map<String, Object> res = new HashMap<>();
        if (site == null || site.isEmpty()) site = host;
        if (cfg.approvalLocked()) {
            res.put("ok", false);
            res.put("error", "too many wrong PINs, wait " + Math.ceil(cfg.approvalLockRemainingMs() / 60000.0) + " minute(s)");
        } else if (pin == null || !cfg.checkAccessPin(pin)) {
            cfg.recordWrongPin();
            res.put("ok", false);
            res.put("error", "wrong PIN");
        } else {
            cfg.clearWrongPins();
            int minutes = 30;
            try { if (minStr != null) minutes = Integer.parseInt(minStr.trim()); } catch (NumberFormatException ignored) {}
            if (permanent) minutes = 0;
            cfg.approve(site, minutes);
            res.put("ok", true);
            res.put("redirect", url);
            res.put("site", Config.mainDomain(site));
        }
        String j = mapToJson(res);
        byte[] b = j.getBytes(StandardCharsets.UTF_8);
        out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + b.length + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.write(b);
        out.flush();
    }

    // ------------------------------------------------------------ block page

    private void writeBlockPage(OutputStream out, String host, String url) throws IOException {
        cfg.noteBlocked(host);
        String tpl = loadTemplate();
        String html = tpl.replace("{{SITE}}", esc(Config.mainDomain(host)))
                .replace("{{URL}}", esc(url))
                .replace("{{MODE}}", cfg.isAllowlist() ? "allowlist" : "blocklist");
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + b.length + "\r\nCache-Control: no-store\r\n"
                + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(b);
        out.flush();
    }

    private String loadTemplate() {
        File custom = new File(cfg.stateDir(), "block_page.html");
        if (custom.exists()) {
            try (InputStream is = new FileInputStream(custom)) {
                return new String(readAll(is), StandardCharsets.UTF_8);
            } catch (IOException ignored) {}
        }
        try (InputStream is = ctx.getAssets().open("block_page.html")) {
            return new String(readAll(is), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "<html><body><h1>Blocked: {{SITE}}</h1></body></html>";
        }
    }

    // ------------------------------------------------------ certificate work

    public byte[] caCertificateDer() { return caDer == null ? new byte[0] : caDer.clone(); }

    private synchronized void loadOrMakeCa() throws Exception {
        File keyF = new File(cfg.stateDir(), "ca.key");
        File crtF = new File(cfg.stateDir(), "ca.crt");
        if (keyF.exists() && crtF.exists()) {
            try {
                caKey = readKeyPem(keyF);
                caCert = readCertPem(crtF);
                caDer = caCert.getEncoded();
                return;
            } catch (Exception e) {
                Log.write("CA reload failed, regenerating: " + e);
            }
        }
        makeCa(keyF, crtF);
    }

    private void makeCa(File keyF, File crtF) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048, new SecureRandom());
        KeyPair kp = g.generateKeyPair();
        long now = System.currentTimeMillis();
        X500Name name = new X500Name("CN=Local Web Filter CA (this device only), O=Local Web Filter, C=US");
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now - 86400_000L),
                new Date(now + 3650L * 86400_000L), name, kp.getPublic());
        cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        caCert = new JcaX509CertificateConverter().getCertificate(cb.build(signer));
        caKey = kp.getPrivate();
        caDer = caCert.getEncoded();
        writePem(keyF, "PRIVATE KEY", kp.getPrivate().getEncoded());
        writePem(crtF, "CERTIFICATE", caDer);
        Log.write("created device-local CA");
    }

    private SSLContext contextFor(String host) {
        SSLSocketFactory cached = ctxCache.get(host);
        if (cached != null) {
            try {
                SSLContext c = SSLContext.getInstance("TLS");
                // rebuild cheaply: store contexts instead of factories
            } catch (Exception ignored) {}
        }
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048, new SecureRandom());
            KeyPair leaf = g.generateKeyPair();
            X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
            X500Name subj = new X500Name("CN=" + host);
            long now = System.currentTimeMillis();
            JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                    issuer, BigInteger.valueOf(now + host.hashCode()),
                    new Date(now - 86400_000L), new Date(now + 825 * 86400_000L),
                    subj, leaf.getPublic());
            cb.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);
            X509CertificateHolder h = cb.build(cs);
            X509Certificate leafCert = new JcaX509CertificateConverter().getCertificate(h);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            SecretKey sk = new SecretKeySpec(new byte[]{1}, "AES"); // dummy password for in-memory ks
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            char[] pw = "lwf".toCharArray();
            ks.load(null, pw);
            ks.setKeyEntry("k", leaf.getPrivate(), pw, new java.security.cert.Certificate[]{leafCert, caCert});

            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(kmf.getKeyManagers(), null, new SecureRandom());
            ctxCache.put(host, sc.getSocketFactory());
            return sc;
        } catch (Exception e) {
            Log.write("leaf cert for " + host + ": " + e);
            return null;
        }
    }

    // ------------------------------------------------------------- plumbing

    static final class RequestLine {
        String method, target, version;
        List<String> headers = new ArrayList<>();
        String body;
        byte[] bodyBytes;
    }

    private RequestLine readHead(BufferedReader in) throws IOException {
        String line = in.readLine();
        if (line == null) return null;
        RequestLine r = new RequestLine();
        String[] sp = line.split(" ");
        if (sp.length < 2) return null;
        r.method = sp[0];
        r.target = sp[1];
        r.version = sp.length > 2 ? sp[2] : "HTTP/1.1";
        int len = -1;
        while ((line = in.readLine()) != null && !line.isEmpty()) r.headers.add(line);
        for (String h : r.headers) {
            String l = h.toLowerCase(Locale.US);
            if (l.startsWith("content-length:")) {
                try { len = Integer.parseInt(h.substring(15).trim()); } catch (Exception ignored) {}
            }
        }
        if (len > 0) {
            char[] cbuf = new char[Math.min(len, 1 << 20)];
            int off = 0;
            while (off < cbuf.length) {
                int n = in.read(cbuf, off, cbuf.length - off);
                if (n < 0) break;
                off += n;
            }
            r.body = new String(cbuf, 0, off);
            r.bodyBytes = r.body.getBytes(StandardCharsets.UTF_8);
        }
        return r;
    }

    private static String header(List<String> hs, String name) {
        String p = name.toLowerCase(Locale.US) + ":";
        for (String h : hs) if (h.toLowerCase(Locale.US).startsWith(p))
            return h.substring(p.length()).trim();
        return null;
    }

    private static String targetHost(String t) {
        try {
            if (t.regionMatches(true, 0, "http", 0, 4)) {
                int a = t.indexOf("//") + 2;
                int z = t.indexOf('/', a);
                String hp = z < 0 ? t.substring(a) : t.substring(a, z);
                int c = hp.indexOf(':');
                return c < 0 ? hp : hp.substring(0, c);
            }
            int c = t.indexOf(':');
            return c < 0 ? t : t.substring(0, c);
        } catch (Exception e) { return null; }
    }

    private static int targetPort(String t, int dflt) {
        try {
            String hp;
            if (t.regionMatches(true, 0, "http", 0, 4)) {
                int a = t.indexOf("//") + 2;
                int z = t.indexOf('/', a);
                hp = z < 0 ? t.substring(a) : t.substring(a, z);
            } else hp = t;
            int c = hp.indexOf(':');
            return c < 0 ? dflt : Integer.parseInt(hp.substring(c + 1));
        } catch (Exception e) { return dflt; }
    }

    private static void sendStatus(OutputStream o, int code, String msg) {
        try {
            o.write(("HTTP/1.1 " + code + " " + msg + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            o.flush();
        } catch (IOException ignored) {}
    }

    private static BufferedReader reader(InputStream is) {
        return new BufferedReader(new InputStreamReader(is, StandardCharsets.ISO_8859_1));
    }

    private static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) b.write(buf, 0, n);
        return b.toByteArray();
    }

    private static void close(Socket s) { try { s.close(); } catch (IOException ignored) {} }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String json(String body, String key) {
        if (body == null) return null;
        String k = "\"" + key + "\"";
        int i = body.indexOf(k);
        if (i < 0) return null;
        int c = body.indexOf(':', i + k.length());
        if (c < 0) return null;
        int j = c + 1;
        while (j < body.length() && Character.isWhitespace(body.charAt(j))) j++;
        if (j >= body.length()) return null;
        if (body.charAt(j) == '"') {
            int e = body.indexOf('"', j + 1);
            return e < 0 ? null : body.substring(j + 1, e);
        }
        int e = j;
        while (e < body.length() && (Character.isLetterOrDigit(body.charAt(e)) || body.charAt(e) == '.'
                || body.charAt(e) == '-')) e++;
        return body.substring(j, e);
    }

    private static String mapToJson(Map<String, Object> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append("\":");
            Object v = e.getValue();
            if (v instanceof Number || v instanceof Boolean) sb.append(v);
            else sb.append('"').append(String.valueOf(v).replace("\"", "\\\"")).append('"');
        }
        return sb.append('}').toString();
    }

    private static void writePem(File f, String type, byte[] der) throws IOException {
        try (FileOutputStream fo = new FileOutputStream(f);
             BufferedWriter w = new BufferedWriter(new OutputStreamWriter(fo, StandardCharsets.US_ASCII))) {
            PemWriter pw = new PemWriter(w);
            pw.writeObject(new PemObject(type, der));
            pw.flush();
        }
    }

    private static PrivateKey readKeyPem(File f) throws Exception {
        try (PEMParser p = new PEMParser(new StringReader(slurp(f)))) {
            Object o = p.readObject();
            byte[] der;
            if (o instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                der = ((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) o).getEncoded();
                return KeyFactory.getInstance("RSA").generatePrivate(
                        org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(der));
            }
            throw new IOException("not a key");
        }
    }

    private static X509Certificate readCertPem(File f) throws Exception {
        try (PEMParser p = new PEMParser(new StringReader(slurp(f)))) {
            Object o = p.readObject();
            if (o instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) o);
            }
            throw new CertificateException("not a cert");
        }
    }

    private static String slurp(File f) throws IOException {
        try (InputStream is = new FileInputStream(f)) {
            return new String(readAll(is), StandardCharsets.US_ASCII);
        }
    }

    static ThreadFactory namedThreadFactory(String prefix) {
        return r -> { Thread t = new Thread(r, prefix); t.setDaemon(true); return t; };
    }

    /** Base64 of the CA cert, for the VPN's APPLICATION layer bypass UI / export. */
    public String caBase64() { return Base64.encodeToString(caDer, Base64.NO_WRAP); }
}
