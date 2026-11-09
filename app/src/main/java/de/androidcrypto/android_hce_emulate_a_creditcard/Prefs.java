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
 * ON A FALLBACK THE ENCRYPTED FILE IS DELETED. Otherwise the app comes up,
 * reads the mirror, writes to it, and the moment the Keystore recovers the stale
 * encrypted file wins and the edits are gone. Dropping it means the next
 * successful start migrates the mirror again.
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

    private static SharedPreferences cached;
    private static boolean encrypted;

    private Prefs() { }

    /**
     * The store. Encrypted when the Keystore works, plaintext when it does not.
     *
     * Synchronised and cached: create() does Keystore work, and get() is called
     * from the service on a binder thread as well as from every UI read. Without
     * the cache a single tap would rebuild the master key dozens of times.
     */
    static synchronized SharedPreferences get(Context ctx) {
        if (cached != null) return cached;

        Context app = ctx.getApplicationContext();

        try {
            MasterKey key = new MasterKey.Builder(app)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();

            SharedPreferences enc = EncryptedSharedPreferences.create(
                    app,
                    ENCRYPTED,
                    key,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);

            migrateOnce(app, enc);

            cached = enc;
            encrypted = true;
            return cached;
        } catch (Throwable t) {
            // Keystore unavailable, key invalidated, or the encrypted file is
            // unreadable. Drop it so the next start rebuilds from the mirror.
            deleteEncrypted(app);
            cached = app.getSharedPreferences(PLAIN, Context.MODE_PRIVATE);
            encrypted = false;
            return cached;
        }
    }

    /** Whether the live store is the encrypted one. For the status line. */
    static boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Copy the mirror across, once.
     *
     * The ints that the service reads through a getString helper are written as
     * strings here - 'selected', the per-card 'msd' and 'usescript' - so the
     * encrypted store is uniformly string-typed on those and nothing has to lean
     * on the ClassCastException fallbacks afterwards. Everything else keeps its
     * type; card_count stays an int.
     */
    private static void migrateOnce(Context app, SharedPreferences enc) {
        if (enc.getBoolean(MIGRATED, false)) return;

        SharedPreferences plain = app.getSharedPreferences(PLAIN, Context.MODE_PRIVATE);
        Map<String, ?> all = plain.getAll();

        if (!all.isEmpty()) {
            SharedPreferences.Editor e = enc.edit();
            for (Map.Entry<String, ?> en : all.entrySet()) {
                String k = en.getKey();
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
            // commit(), not apply(): the caller is about to read straight back.
            e.putBoolean(MIGRATED, true).commit();
        } else {
            enc.edit().putBoolean(MIGRATED, true).apply();
        }
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
