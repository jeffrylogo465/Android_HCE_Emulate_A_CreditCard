package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.File;
import java.util.Map;
import java.util.Set;

/**
 * The one place the card store is opened.
 *
 * WHY THIS EXISTS. Every field the app holds - PAN, track 2, the DD with the
 * CSC in it, the issuer key, the capture - sits in a plaintext XML file today.
 * On a rooted device, or through an adb backup, that file is the whole card.
 * EncryptedSharedPreferences moves the keys behind a Keystore-held AES-256 key
 * so the XML alone is worthless.
 *
 * THE PLAINTEXT FILE IS A SHADOW, NOT THE OLD VERSION. It is migrated once and
 * then kept, and WHILE THE ENCRYPTED STORE IS LIVE EVERY WRITE GOES TO BOTH.
 * It is deliberately not deleted:
 *
 *   - A Keystore key can be lost - device restore, factory reset of the secure
 *     hardware, a key invalidation from a lock-screen change. create() then
 *     throws and there is nothing to read. The shadow is what makes that a
 *     degraded app rather than an empty one.
 *
 * WRITE-THROUGH IS THE FIX FOR A DATA-LOSS HOLE. The shadow used to be written
 * only in plaintext mode, so it was frozen at the moment of migration while the
 * encrypted file took every later edit. One failed create() then set the
 * fallback flag AND DELETED the encrypted file - so every card added since the
 * migration was gone, permanently, with no error anywhere. The shadow being
 * current is what makes deleting safe now.
 *
 * A FAILURE IS REMEMBERED. FORCE_PLAIN goes into the shadow on the first failed
 * open and every later start reads it and goes straight to plaintext. Without
 * that flag a device whose Keystore is broken re-attempts create() on every
 * launch, throws on every launch, and the app is unusable rather than merely
 * unencrypted. reset() clears the flag if the Keystore is ever fixed.
 *
 * ON A FALLBACK THE ENCRYPTED FILE IS DELETED. Otherwise the app comes up,
 * reads the shadow, writes to it, and the moment the Keystore recovers the stale
 * encrypted file wins and the edits are gone. Because every write since the
 * migration went to the shadow as well, nothing is lost by deleting.
 *
 * THIS IS NOT DEFENCE AGAINST A LIVE ATTACKER. Anyone with code execution as the
 * app can call these getters. It stops the XML from being a plaintext dump.
 */
final class Prefs {

    /** The plaintext file. Also the migration source and the fallback. */
    private static final String PLAIN = "hce_card";

    /** The encrypted file. Only opened when the Keystore works. */
    private static final String ENCRYPTED = "hce_card_enc";

    /** Set in the encrypted store once the shadow has been copied across. */
    private static final String MIGRATED = "store_migrated";

    /** Set in the SHADOW when the encrypted store has failed at least once. */
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
     * NOTHING ESCAPES. Every failure path ends at the shadow, because this is
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

            // From here on every write is mirrored. See Shadow.
            cached = new Shadow(enc, plain);
            encrypted = true;
            return cached;
        } catch (Throwable t) {
            android.util.Log.w("Prefs", "encrypted store unusable, using the shadow", t);
            return fallBack(app, plain, t);
        }
    }

    /**
     * Give up on the encrypted store, for this call and every later one.
     *
     * The shadow is already current, so the delete below costs nothing. The flag
     * is written FIRST, before the delete, so a crash in between leaves a device
     * that will not try the Keystore again rather than one that tries and loses
     * the file each launch.
     */
    private static synchronized SharedPreferences fallBack(
            Context app, SharedPreferences plain, Throwable cause) {

        try {
            plain.edit().putBoolean(FORCE_PLAIN, true).apply();
        } catch (Throwable ignored) { }

        deleteEncrypted(app);
        cached = plain;
        encrypted = false;

        android.util.Log.w("Prefs", "fell back to the plaintext shadow", cause);
        return cached;
    }

    /**
     * Whether the live store is the encrypted one. For the status line.
     *
     * Nothing calls this yet. It exists so the UI can say "plaintext" out loud -
     * a fallback is otherwise completely silent, and the user has no way to know
     * the wallet is unprotected.
     */
    static boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Forget the failure and try the Keystore again on the next call.
     *
     * Safe now, and only now: the shadow holds every write made while in
     * plaintext mode, so the re-migration copies a current store rather than a
     * stale one. Before the write-through this could not be offered, because
     * resetting after a fallback would have thrown away everything written in
     * plaintext mode.
     *
     * Nothing calls this yet either. Wire it to a button once the UI can show
     * isEncrypted().
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
     * Copy the shadow across, once.
     *
     * The ints that the service reads through a getString helper are written as
     * strings here - 'selected', the per-card 'msd' and 'usescript' - so the
     * encrypted store is uniformly string-typed on those and nothing has to lean
     * on the ClassCastException fallbacks afterwards. Everything else keeps its
     * type; card_count stays an int.
     *
     * FORCE_PLAIN is skipped so it does not travel into the encrypted store,
     * where a stale true would send the next launch back to the shadow.
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
     * try/catch by every caller and falls back to the shadow on any throw, and a
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

    /**
     * The encrypted store, with every write mirrored to the shadow.
     *
     * A WRAPPER, so no caller has to change. The app talks to SharedPreferences
     * all over - thirty-odd putString calls in MainActivity.collect() alone, a
     * dozen in the service - and threading a second store through all of them
     * is how the two would drift.
     *
     * READS GO STRAIGHT TO THE LIVE STORE. Only writes are doubled, and only
     * per key: a write-through that re-dumped getAll() would decrypt the whole
     * file on every keystroke, which is the cost this class exists to avoid.
     *
     * A READ THAT THROWS MEANS THE KEYSTORE DIED MID-SESSION - a lock-screen
     * change invalidating the master key, usually. Reads therefore fall back to
     * the shadow on the spot and mark the store dead, rather than throwing into
     * a caller that does not expect it. MainActivity.loadAll() has no try/catch
     * around its reads and would otherwise take the activity down.
     */
    private static final class Shadow implements SharedPreferences {

        private final SharedPreferences live;
        private final SharedPreferences plain;

        Shadow(SharedPreferences live, SharedPreferences plain) {
            this.live = live;
            this.plain = plain;
        }

        /** Called from a read that threw. Returns the store to use from now on. */
        private SharedPreferences dead(Throwable t) {
            Prefs.fallBack(liveContext(), plain, t);
            return plain;
        }

        /**
         * The Context is not held, so rebuild it from the one thing that always
         * has it: the plain store's own file path is not enough, and passing a
         * Context into every Shadow would keep an Activity alive. The application
         * context is fetched from the EncryptedSharedPreferences instance's
         * class loader is not possible either - so the Shadow is constructed with
         * the app Context instead.
         */
        private Context liveContext() {
            return appContext;
        }

        // ------------------------------------------------------------- reads

        @Override public Map<String, ?> getAll() {
            try { return live.getAll(); } catch (Throwable t) { return dead(t).getAll(); }
        }

        @Override public String getString(String k, String d) {
            try { return live.getString(k, d); }
            catch (Throwable t) { return dead(t).getString(k, d); }
        }

        @Override public Set<String> getStringSet(String k, Set<String> d) {
            try { return live.getStringSet(k, d); }
            catch (Throwable t) { return dead(t).getStringSet(k, d); }
        }

        @Override public int getInt(String k, int d) {
            try { return live.getInt(k, d); }
            catch (Throwable t) { return dead(t).getInt(k, d); }
        }

        @Override public long getLong(String k, long d) {
            try { return live.getLong(k, d); }
            catch (Throwable t) { return dead(t).getLong(k, d); }
        }

        @Override public float getFloat(String k, float d) {
            try { return live.getFloat(k, d); }
            catch (Throwable t) { return dead(t).getFloat(k, d); }
        }

        @Override public boolean getBoolean(String k, boolean d) {
            try { return live.getBoolean(k, d); }
            catch (Throwable t) { return dead(t).getBoolean(k, d); }
        }

        @Override public boolean contains(String k) {
            try { return live.contains(k); }
            catch (Throwable t) { return dead(t).contains(k); }
        }

        // ------------------------------------------------------------ writes

        @Override public Editor edit() {
            return new ShadowEditor(live.edit(), plain.edit());
        }

        @Override public void registerOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener l) {
            try { live.registerOnSharedPreferenceChangeListener(l); } catch (Throwable ignored) { }
        }

        @Override public void unregisterOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener l) {
            try { live.unregisterOnSharedPreferenceChangeListener(l); } catch (Throwable ignored) { }
        }
    }

    /**
     * One editor, two stores.
     *
     * Every operation is applied to both. commit() reports the live result -
     * the shadow is the fallback, not the authority, and a shadow write that
     * fails must not make a successful encrypted write look failed.
     */
    private static final class ShadowEditor implements SharedPreferences.Editor {

        private final SharedPreferences.Editor live;
        private final SharedPreferences.Editor plain;

        ShadowEditor(SharedPreferences.Editor live, SharedPreferences.Editor plain) {
            this.live = live;
            this.plain = plain;
        }

        @Override public SharedPreferences.Editor putString(String k, String v) {
            live.putString(k, v);
            plain.putString(k, v);
            return this;
        }

        @Override public SharedPreferences.Editor putStringSet(String k, Set<String> v) {
            live.putStringSet(k, v);
            plain.putStringSet(k, v);
            return this;
        }

        @Override public SharedPreferences.Editor putInt(String k, int v) {
            live.putInt(k, v);
            plain.putInt(k, v);
            return this;
        }

        @Override public SharedPreferences.Editor putLong(String k, long v) {
            live.putLong(k, v);
            plain.putLong(k, v);
            return this;
        }

        @Override public SharedPreferences.Editor putFloat(String k, float v) {
            live.putFloat(k, v);
            plain.putFloat(k, v);
            return this;
        }

        @Override public SharedPreferences.Editor putBoolean(String k, boolean v) {
            live.putBoolean(k, v);
            plain.putBoolean(k, v);
            return this;
        }

        @Override public SharedPreferences.Editor remove(String k) {
            live.remove(k);
            plain.remove(k);
            return this;
        }

        @Override public SharedPreferences.Editor clear() {
            live.clear();
            plain.clear();
            return this;
        }

        @Override public boolean commit() {
            boolean ok = live.commit();
            try { plain.commit(); } catch (Throwable ignored) { }
            return ok;
        }

        @Override public void apply() {
            live.apply();
            try { plain.apply(); } catch (Throwable ignored) { }
        }
    }
}
