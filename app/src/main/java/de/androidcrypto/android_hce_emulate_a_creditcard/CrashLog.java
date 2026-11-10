package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;

/**
 * Crash trace to a file, because the clipboard is not reliable.
 *
 * The handler in MainActivity copies to the clipboard and then kills the
 * process. That works when the activity is in front. It does not work for a
 * crash on the way to the background - which is exactly when a tap happens -
 * because the process is often dead before the clip write lands, so the buffer
 * comes back empty and there is nothing to paste.
 *
 * The file is app-scoped external storage: readable with a file manager at
 * Android/data/<pkg>/files/crash.txt, and mirrored to logcat.
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
                    FileWriter w = new FileWriter(f, true);
                    w.write("---- " + t.getName() + " ----\n" + s + "\n\n");
                    w.close();
                } catch (Throwable ignored) { }
                try { Thread.sleep(300); } catch (Throwable ignored) { }

                if (prior != null) prior.uncaughtException(t, e);
                else android.os.Process.killProcess(android.os.Process.myPid());
            }
        });
    }
}
