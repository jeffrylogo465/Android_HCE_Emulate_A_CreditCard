package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;

/**
 * Crash trace to a file, because the clipboard is not reliable.
 *
 * Two problems drove the location.
 *
 * 1. The old handler copied to the clipboard and killed the process. That works
 *    while the activity is in front. It does not work for a crash on the way to
 *    the background - which is exactly when a tap happens - because the process
 *    is usually dead before the clip write lands.
 * 2. getExternalFilesDir() lives under Android/data, and since Android 11 the
 *    stock file managers do not list the contents of that folder. The trace was
 *    being written somewhere the user could not open. Download is readable by
 *    every file manager, so that is the primary target; the app-private copy is
 *    kept as a second write for adb.
 *
 * INSTALLED FROM BOTH onCreate()s - the activity and the service. A tap can
 * start the process through the service alone, in which case the activity's
 * onCreate never runs and a handler installed only there would miss the crash.
 */
final class CrashLog {

    private static final String NAME = "crash.txt";

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
                String s = Log.getStackTraceString(e);
                Log.e("CrashLog", "uncaught on " + t.getName(), e);

                String body = "---- " + t.getName() + " ----\n" + s + "\n\n";

                try {
                    File dl = Environment.getExternalStoragePublicDirectory(
                            Environment.DIRECTORY_DOWNLOADS);
                    write(new File(dl, NAME), body);
                } catch (Throwable ignored) { }

                try {
                    write(new File(app.getExternalFilesDir(null), NAME), body);
                } catch (Throwable ignored) { }

                // Give the writer a moment before the process goes, then hand
                // back to whatever was installed before us so the system dialog
                // still appears.
                try { Thread.sleep(300); } catch (Throwable ignored) { }

                if (prior != null) prior.uncaughtException(t, e);
                else android.os.Process.killProcess(android.os.Process.myPid());
            }
        });
    }

    private static void write(File f, String body) {
        if (f == null) return;
        try {
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            FileWriter w = new FileWriter(f, true);
            w.write(body);
            w.close();
        } catch (Throwable ignored) { }
    }
}
