package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.RandomAccessFile;

/**
 * Crash trace to a file, because the clipboard is not reliable.
 *
 * Three problems drove this.
 *
 * 1. The old handler copied to the clipboard and killed the process. That works
 *    while the activity is in front. It does not work for a crash on the way to
 *    the background - which is exactly when a tap happens - because the process
 *    is usually dead before the clip write lands. So the clipboard is no longer
 *    the transport; it is an optional export from a live app instead.
 *
 * 2. It wrote to Environment.getExternalStoragePublicDirectory(DOWNLOADS), and
 *    the app declares no storage permission with targetSdk 34. On API 30+ that
 *    write simply fails, and the catch swallowed it - so the "readable by every
 *    file manager" copy never existed on any modern device. It is gone. What is
 *    left is a location that always works.
 *
 * 3. getExternalFilesDir() lives under Android/data, and since Android 11 the
 *    stock file managers do not list it. That is fine as a SECOND write - it is
 *    reachable over USB and by adb - but it cannot be the only one.
 *
 * So: an app-private copy in getFilesDir() as the guaranteed record, the
 * Android/data copy beside it for adb, and read()/clear() for the in-app export
 * in the key-tools menu. Both writes are guarded independently, so a failure in
 * one cannot skip the other.
 *
 * INSTALLED FROM BOTH onCreate()s - the activity and the service. A tap can
 * start the process through the service alone, in which case the activity's
 * onCreate never runs and a handler installed only there would miss the crash.
 */
final class CrashLog {

    private static final String TAG = "CrashLog";
    private static final String NAME = "crash.txt";

    /** Past this, the file is started again rather than grown forever. */
    private static final long MAX_BYTES = 200_000L;

    private static boolean installed;

    private CrashLog() { }

    static synchronized void install(final Context ctx) {
        if (installed) return;
        installed = true;

        final Context app = ctx.getApplicationContext();
        final Thread.UncaughtExceptionHandler prior =
                Thread.getDefaultUncaughtExceptionHandler();

        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                String trace = Log.getStackTraceString(e);
                Log.e(TAG, "uncaught on " + t.getName(), e);

                String body = header(app, t) + trace + "\n\n";

                File[] targets = files(app);
                for (File f : targets) {
                    try {
                        write(f, body);
                    } catch (Throwable ignored) { }
                }

                // Give the writers a moment before the process goes, then hand
                // back to whatever was installed before us so the system dialog
                // still appears.
                try { Thread.sleep(300); } catch (Throwable ignored) { }

                if (prior != null) prior.uncaughtException(t, e);
                else android.os.Process.killProcess(android.os.Process.myPid());
            }
        });
    }

    /**
     * The newest trace, or "" when there is none.
     *
     * Newest, not longest: a crash right after a clear should not be masked by
     * an older, bigger one in the other location.
     */
    static String read(Context ctx) {
        File best = null;
        for (File f : files(ctx.getApplicationContext())) {
            try {
                if (!f.exists() || f.length() == 0) continue;
                if (best == null || f.lastModified() > best.lastModified()) best = f;
            } catch (Throwable ignored) { }
        }
        if (best == null) return "";

        try {
            long len = Math.min(best.length(), MAX_BYTES);
            byte[] b = new byte[(int) len];
            RandomAccessFile raf = new RandomAccessFile(best, "r");
            raf.seek(best.length() - len);
            raf.readFully(b);
            raf.close();
            return new String(b, "UTF-8");
        } catch (Throwable t) {
            return "could not read the crash log: " + t + "\n";
        }
    }

    /** Drop every copy. */
    static void clear(Context ctx) {
        for (File f : files(ctx.getApplicationContext())) {
            try {
                if (f.exists()) f.delete();
            } catch (Throwable ignored) { }
        }
    }

    /**
     * Internal first, then app-external.
     *
     * Internal is the one that cannot fail. The external entry is null when
     * external storage is unmounted, and the loop skips it.
     */
    private static File[] files(Context app) {
        File internal = new File(app.getFilesDir(), NAME);

        File external = null;
        try {
            if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
                external = new File(app.getExternalFilesDir(null), NAME);
            }
        } catch (Throwable ignored) { }

        return external == null
                ? new File[]{internal}
                : new File[]{internal, external};
    }

    /**
     * Enough to place the crash: when, on what, and which build.
     *
     * The version comes from the package manager rather than BuildConfig,
     * because BuildConfig is not generated for this module's variant here and a
     * missing symbol in the crash handler is a bad trade.
     */
    private static String header(Context app, Thread t) {
        StringBuilder sb = new StringBuilder();
        sb.append("---- ").append(t.getName()).append(" ----\n");

        try {
            sb.append("when   : ")
              .append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                      java.util.Locale.US).format(new java.util.Date()))
              .append('\n');
        } catch (Throwable ignored) { }

        try {
            sb.append("device : ").append(Build.MANUFACTURER).append(' ')
              .append(Build.MODEL).append(" / API ").append(Build.VERSION.SDK_INT)
              .append('\n');
        } catch (Throwable ignored) { }

        try {
            sb.append("version: ").append(app.getPackageManager()
                    .getPackageInfo(app.getPackageName(), 0).versionName).append('\n');
        } catch (Throwable ignored) { }

        sb.append('\n');
        return sb.toString();
    }

    private static void write(File f, String body) {
        if (f == null) return;
        try {
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            if (f.length() > MAX_BYTES) f.delete();
            FileWriter w = new FileWriter(f, true);
            w.write(body);
            w.close();
        } catch (Throwable ignored) { }
    }
}
