package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Where a pasted card block lives: an app-private file, not the encrypted
 * Prefs store - this is a free-text blob of arbitrary size, not a short
 * pref value, and CrashLog's own file in getFilesDir() is the precedent for
 * that distinction in this app.
 *
 * save()/clear() are the write side (a future "load card" screen calls
 * these); activeCard() is what ShadowApduService.assetCard() reads back at
 * the same lazy-init moment it loads profile.json, so a loaded card
 * survives a process restart exactly as the asset card's own ATC does.
 */
final class LoadedCardStore {

    private static final String NAME = "loaded_card.txt";

    private LoadedCardStore() { }

    private static File file(Context ctx) {
        return new File(ctx.getApplicationContext().getFilesDir(), NAME);
    }

    /**
     * Parses and validates the block BEFORE writing anything, so a bad
     * paste never overwrites a card that was working. Throws
     * IllegalArgumentException (see LoadedCard.parse()) on a bad block and
     * leaves the stored file untouched.
     */
    static void save(Context ctx, String block) throws IOException {
        LoadedCard.parse(block); // throws before any write on a bad block
        try (FileOutputStream out = new FileOutputStream(file(ctx))) {
            out.write(block.getBytes(StandardCharsets.UTF_8));
        }
    }

    static void clear(Context ctx) {
        File f = file(ctx);
        if (f.exists()) f.delete();
    }

    /**
     * The stored block's raw text, unparsed, or "" when none is stored - for
     * prefilling an edit screen with exactly what was last saved, even if it
     * no longer parses. Never throws.
     */
    static String rawBlock(Context ctx) {
        File f = file(ctx);
        if (!f.exists()) return "";
        try (FileInputStream in = new FileInputStream(f)) {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return new String(bo.toByteArray(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /** The stored block, re-parsed, or null when none is stored. Never throws on a read. */
    static LoadedCard activeCard(Context ctx) {
        File f = file(ctx);
        if (!f.exists()) return null;
        try (FileInputStream in = new FileInputStream(f)) {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return LoadedCard.parse(new String(bo.toByteArray(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            // A file that no longer parses (hand-edited, truncated) must not
            // crash every tap - the test-card/profile.json path still works.
            return null;
        }
    }
}
