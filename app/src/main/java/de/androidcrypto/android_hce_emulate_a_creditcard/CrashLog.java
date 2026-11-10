package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;

/**
 * Crash trace to a file, because the clipboard is not reliable.
 *
 * The old handler copied to the clipboard and then killed the process. That
 * works while the activity is in front. It does not work for a crash on the way
 * to the background - which is exactly when a tap happens - because the process
 * is usually dead before the clip write lands, so the buffer comes back empty
 * and there is nothing to paste.
 *
 * The file is app-scoped external storage: readable with a file manager at
 * Android/data/<pkg>/files/crash.txt, and mirrored to logcat. It is appended,
 * so several crashes stack up instead of overwriting each other.
 *
 * INSTALLED FROM BOTH onCreate()s - the activity and the service. A tap can
 * start the process through the service alone, in which case the activity's
 * onCreate never runs and a handler installed only there would miss the crash
 * entirely.
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

                try {
                    File f = new File(app.getExternalFilesDir(null), NAME);
                    File parent = f.getParentFile();
                    if (parent != null && !parent.exists()) parent.mkdirs();
                    FileWriter w = new FileWriter(f, true);
                    w.write("---- " + t.getName() + " ----\n" + s + "\n\n");
                    w.close();
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
}
