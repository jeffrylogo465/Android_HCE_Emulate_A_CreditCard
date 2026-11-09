package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;

import java.io.File;
import java.io.FileWriter;
import java.io.RandomAccessFile;

/**
 * Per-card terminal tap log, buffered.
 *
 * TWO problems this exists to fix, both of which were real:
 *
 * 1. The old writer opened, wrote and closed a file on EVERY APDU - a tap is
 *    eight to fifteen of them, all on the binder thread, inside the response
 *    path. Lines now accumulate in memory and land in one write when the tap
 *    ends.
 *
 * 2. There was ONE file for the whole wallet, so clearing card B's capture took
 *    card A's tap history with it. The name is per slot now.
 *
 * Still on getExternalFilesDir, not internal storage: the point of this log is
 * that you can pull it off the phone. It is app-scoped but readable over USB and
 * by a file manager, and it contains PANs.
 *
 * Rotation truncates mid-line, which is accepted - the tail of a cut line is
 * less bad than an unbounded file.
 *
 * Everything is synchronized because the binder thread appends while the main
 * thread may be reading the capture screen.
 */
final class TapLog {

    private static final long ROTATE_AT = 60000;
    private static final long KEEP = 30000;

    private static final StringBuilder buf = new StringBuilder();
    private static String bufSlot = null;

    private TapLog() { }

    private static File file(Context c, String slot) {
        return new File(c.getExternalFilesDir(null), "term_" + slot + "log.txt");
    }

    /** Buffer one line. Flushes first if the slot changed under us. */
    static synchronized void append(Context c, String slot, String line) {
        if (bufSlot != null && !bufSlot.equals(slot)) flush(c);
        bufSlot = slot;
        buf.append(line).append('\n');
        if (buf.length() > 64000) buf.delete(0, buf.length() - 48000);
    }

    /** One write, one close. Called when the tap ends, not per APDU. */
    static synchronized void flush(Context c) {
        if (bufSlot == null || buf.length() == 0) return;
        File f = file(c, bufSlot);
        try {
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            FileWriter w = new FileWriter(f, true);
            w.write(buf.toString());
            w.close();
            buf.setLength(0);
            rotate(f);
        } catch (Throwable ignored) { }
    }

    /** Trim the head back to KEEP once past ROTATE_AT. */
    private static void rotate(File f) {
        try {
            if (f.length() <= ROTATE_AT) return;
            byte[] keep = new byte[(int) KEEP];
            RandomAccessFile raf = new RandomAccessFile(f, "rw");
            raf.seek(f.length() - KEEP);
            raf.readFully(keep);
            raf.setLength(0);
            raf.write(keep);
            raf.close();
        } catch (Throwable ignored) { }
    }

    /** Last {@code max} bytes of the slot's log, for the capture screen. */
    static synchronized String readTail(Context c, String slot, int max) {
        flush(c);
        File f = file(c, slot);
        if (!f.exists() || f.length() == 0) return "";
        try {
            long keep = Math.min(f.length(), max);
            byte[] b = new byte[(int) keep];
            RandomAccessFile raf = new RandomAccessFile(f, "r");
            raf.seek(f.length() - keep);
            raf.readFully(b);
            raf.close();
            String head = f.length() > keep
                    ? "...(" + (f.length() - keep) + " bytes trimmed)\n" : "";
            return head + new String(b, "UTF-8");
        } catch (Exception e) {
            return "could not read the log: " + e + "\n";
        }
    }

    /** Drop this slot's log. Other cards keep theirs. */
    static synchronized void clear(Context c, String slot) {
        if (slot.equals(bufSlot)) buf.setLength(0);
        File f = file(c, slot);
        if (f.exists()) f.delete();
    }
}
