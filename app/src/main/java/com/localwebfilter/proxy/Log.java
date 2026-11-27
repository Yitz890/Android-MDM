package com.localwebfilter.proxy;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Writes state/service.log next to the app data, like upstream's state dir. */
public final class Log {

    private static File dir;
    private static Writer w;

    public static synchronized void init(Context c) {
        if (dir != null) return;
        dir = new File(c.getFilesDir(), "state");
        if (!dir.exists()) dir.mkdirs();
    }

    public static synchronized void write(String msg) {
        try {
            Log.i("LWF", msg);
            String line = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                    .format(new Date()) + " " + msg + "\n";
            File f = new File(dir, "service.log");
            Writer o = new OutputStreamWriter(new FileOutputStream(f, true), StandardCharsets.UTF_8);
            o.write(line);
            o.close();
        } catch (Exception ignored) {}
    }
}
