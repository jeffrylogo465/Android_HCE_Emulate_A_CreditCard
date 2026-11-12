package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.File;
import java.util.Map;

/**
 * The one place the card store is opened.
 *
 * WHY THIS EXISTS. Every field the app holds - PAN, track 2, the DD with the
 * CSC in it, the issuer key, the capture - sits in a plaintext XML file today.
 * On a rooted device, or through an adb backup, that file is the whole card.
 * EncryptedSharedPreferences moves the keys behind a Keystore-held AES-256 key
 * so the XML alone is worthless.
 *
 * THE PLAINTEXT FILE IS THE MIRROR, NOT THE OLD VERSION. It is migrated once
 * and then kept, unwritten, as a fallback. It is deliberately not deleted:
 *
 *   - A Keystore key can be lost - device restore, factory reset of the secure
 *     hardware, a key invalidation from a lock-screen change. create() then
 *     throws and there is nothing to read. The mirror is what makes that a
 *     degraded app rather than an empty one.
 *   - The mirror is only ever written in plaintext mode, so it cannot drift
 *     while the encrypted store is healthy.
 *
 * A FAILURE IS REMEMBERED. FORCE_PLAIN goes into the mirror on the first failed
 * open and every later start reads it and goes straight to plaintext. Without
 * that flag a device whose Keystore is broken re-attempts create() on every
 * launch, throws on every launch, and the app is unusable rather than merely
 * unencrypted. reset() clears the flag if the Keystore is ever fixed.
 *
 * ON A FALLBACK THE ENCRYPTED FILE IS DELETED. Otherwise the app comes up,
 * reads the mirror, writes to it, and the moment the Keystore recovers the stale
 * encrypted file wins and the edits are gone.
 *
 * THIS IS NOT DEFENCE AGAINST A LIVE ATTACKER. Anyone with code execution as the
 * app can call these getters. It stops the XML from being a plaintext dump.
 */
final class Prefs {

    /** The plaintext file. Also the migration source and the fallback. */
    private static final String PLAIN = "hce_card";

    /** The encrypted file. Only opened when the Keystore works. */
    private static final String ENCRYPTED = "hce_card_enc";

    /** Set in the encrypted store once the mirror has been copied across. */
    private static final String MIGRATED = "store_migrated";

    /** Set in the MIRROR when the encrypted store has failed at least once. */
    private static final String FORCE_PLAIN = "store_plain";

    private static SharedPreferences cached;
    private static volatile boolean encrypted;

    private Prefs() { }

    /**
     * The store. Encrypted when the Keystore works, plaintext when it does not,
     * and plaintext for good once it has failed.
     *
     * Synchronised and cached: create() does Keystore work, and get() is called
     * from the service on a binder thread as well as from every UI read. Without
     * the cache a single tap would rebuild the master key dozens of times.
     *
     * NOTHING ESCAPES. Every failure path ends at the mirror, because this is
     * called from processCommandApdu() where an exception becomes a 6F00 and a
     * dead tap with no explanation.
     */
    static synchronized SharedPreferences get(Context ctx) {
        if (cached != null) return cached;

        final Context app = ctx.getApplicationContext();
        final SharedPreferences plain = app.getSharedPreferences(PLAIN, Context.MODE_PRIVATE);

        if (plain.getBoolean(FORCE_PLAIN, false)) {
            cached = plain;
            encrypted = false;
            return cached;
        }

        SharedPreferences enc = null;
        try {
            MasterKey key = new MasterKey.Builder(app)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();

            enc = EncryptedSharedPreferences.create(
                    app,
                    ENCRYPTED,
                    key,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);

            // A store that opens but cannot be read is worse than one that
            // throws, so the migration is inside the try as well.
            migrateOnce(app, enc);

            cached = enc;
            encrypted = true;
            return cached;
        } catch (Throwable t) {
            android.util.Log.w("Prefs", "encrypted store unusable, using the mirror", t);

            // Remember it before anything else, so the next launch does not
            // repeat this. The mirror is still intact and holds every card.
            try {
                plain.edit().putBoolean(FORCE_PLAIN, true).apply();
            } catch (Throwable ignored) { }

            deleteEncrypted(app);
            cached = plain;
            encrypted = false;
            return cached;
        }
    }

    /** Whether the live store is the encrypted one. For the status line. */
    static boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Forget the failure and try the Keystore again on the next call.
     *
     * Only useful when the encrypted store was never successfully written, so
     * the mirror is still authoritative. Everything written in plaintext mode
     * is re-migrated on the next open.
     */
    static synchronized void reset(Context ctx) {
        Context app = ctx.getApplicationContext();
        try {
            app.getSharedPreferences(PLAIN, Context.MODE_PRIVATE).edit()
                    .remove(FORCE_PLAIN).apply();
        } catch (Throwable ignored) { }
        deleteEncrypted(app);
        cached = null;
        encrypted = false;
    }

    /**
     * Copy the mirror across, once.
     *
     * The ints that the service reads through a getString helper are written as
     * strings here - 'selected', the per-card 'msd' and 'usescript' - so the
     * encrypted store is uniformly string-typed on those and nothing has to lean
     * on the ClassCastException fallbacks afterwards. Everything else keeps its
     * type; card_count stays an int.
     *
     * FORCE_PLAIN is skipped so it does not travel into the encrypted store,
     * where a stale true would send the next launch back to the mirror.
     *
     * APPLY, NOT COMMIT. This runs on whatever thread opened the store - and in
     * the service that is the main thread, during onCreate, with a terminal
     * already waiting on the first APDU. commit() is a synchronous rewrite of
     * the whole encrypted file and the single biggest reason a first tap froze
     * the app. apply() returns immediately; reads still see every value because
     * they come out of the editor's in-memory map.
     *
     * The cost of losing the boolean that commit() returned: the caller no
     * longer learns the write failed. That is acceptable - get() is wrapped in
     * try/catch by every caller and falls back to the mirror on any throw, and a
     * migration that silently does not land just re-runs on the next open.
     */
    private static void migrateOnce(Context app, SharedPreferences enc) {
        if (enc.getBoolean(MIGRATED, false)) return;

        SharedPreferences plain = app.getSharedPreferences(PLAIN, Context.MODE_PRIVATE);
        Map<String, ?> all = plain.getAll();

        SharedPreferences.Editor e = enc.edit();

        if (!all.isEmpty()) {
            for (Map.Entry<String, ?> en : all.entrySet()) {
                String k = en.getKey();
                if (FORCE_PLAIN.equals(k)) continue;

                Object v = en.getValue();
                if (v == null) continue;

                if (isStringlyInt(k)) {
                    e.putString(k, String.valueOf(v));
                } else if (v instanceof Integer) {
                    e.putInt(k, (Integer) v);
                } else if (v instanceof Boolean) {
                    e.putBoolean(k, (Boolean) v);
                } else if (v instanceof Long) {
                    e.putLong(k, (Long) v);
                } else if (v instanceof Float) {
                    e.putFloat(k, (Float) v);
                } else {
                    e.putString(k, v.toString());
                }
            }
        }

        e.putBoolean(MIGRATED, true);
        e.apply();
    }

    /** Keys the service reads as strings, whatever they were stored as. */
    private static boolean isStringlyInt(String k) {
        return "selected".equals(k) || k.endsWith("_msd") || k.endsWith("_usescript");
    }

    private static void deleteEncrypted(Context app) {
        try {
            File f = new File(app.getApplicationInfo().dataDir,
                    "shared_prefs/" + ENCRYPTED + ".xml");
            if (f.exists()) f.delete();
        } catch (Throwable ignored) { }
    }
}
