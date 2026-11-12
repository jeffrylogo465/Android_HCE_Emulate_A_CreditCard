package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
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

    /**
     * Keys the service reads through getString, whatever type they were stored
     * as.
     *
     * THE LIST IS LONGER THAN IT LOOKS LIKE IT NEEDS TO BE, and every entry is a
     * 6F00 avoided. The service's p() calls getString on all of them; getString
     * on an int or a boolean throws ClassCastException, and p()'s fallback for
     * that is a full getAll() - a whole-file decrypt - on the binder thread, per
     * key, per tap. Stringifying at migration keeps the encrypted store
     * uniformly string-typed on those and the CCE path cold.
     *
     * card_count is deliberately NOT here: MainActivity reads it as an int.
     */
    private static final Set<String> STRINGLY = new HashSet<>(Arrays.asList(
            "selected", "atc", "atcfloor", "atccommitted", "psn", "pan", "expiry",
            "track2", "service", "discretionary", "name", "label", "aip", "iad",
            "mkac", "imkcvc3", "ivcvc3", "ivcvc3_t1", "keyvar", "cid", "msdloc",
            "msdrec", "afl", "aid", "pdol", "cdol1", "cdol2", "cvmlist", "profile",
            "script", "taplog", "lastverdict"));

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
     *
     * THE FORCE_PLAIN READ IS INSIDE A GUARD NOW. It used to sit outside the try,
     * ahead of everything, so a plaintext file that could not be parsed threw
     * before the fallback machinery was reachable - the one path that is
     * supposed to survive anything was the one path that could fail.
     */
    static synchronized SharedPreferences get(Context ctx) {
        if (cached != null) return cached;

        Context app = ctx == null ? null : ctx.getApplicationContext();
        if (app == null) app = ctx;

        final SharedPreferences plain = app.getSharedPreferences(PLAIN, Context.MODE_PRIVATE);

        boolean forced = false;
        try {
            forced = plain.getBoolean(FORCE_PLAIN, false);
        } catch (Throwable t) {
            android.util.Log.w("Prefs", "shadow unreadable, assuming a plain start", t);
        }
        if (forced) {
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
            cached = new Shadow(app, enc, plain);
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
     *
     * IDEMPOTENT AND CHEAP AFTER THE FIRST CALL. Every throwing read and write
     * comes through here, and there are dozens of them per tap - re-writing the
     * flag, re-deleting the file and re-logging each time was three syscalls and
     * a stack trace per key on a dead store.
     */
    private static synchronized SharedPreferences fallBack(
            Context app, SharedPreferences plain, Throwable cause) {

        if (encrypted) {
            try {
                plain.edit().putBoolean(FORCE_PLAIN, true).apply();
            } catch (Throwable ignored) { }

            deleteEncrypted(app);
            android.util.Log.w("Prefs", "fell back to the plaintext shadow", cause);
        }

        cached = plain;
        encrypted = false;
        return cached;
    }

    /**
     * Whether the live store is the encrypted one. For the status line.
     *
     * MainActivity reads this on resume to say "PLAINTEXT store" out loud - a
     * fallback is otherwise completely silent, and the user has no way to know
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
     * Wired to the key-tools menu item "Store: retry encryption".
     */
    static synchronized void reset(Context ctx) {
        Context app = ctx == null ? null : ctx.getApplicationContext();
        if (app == null) app = ctx;
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
     * strings here - see STRINGLY - so the encrypted store is uniformly
     * string-typed on those and nothing has to lean on the ClassCastException
     * fallbacks afterwards. Everything else keeps its type; card_count stays an
     * int.
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
        if (k == null) return false;
        if (STRINGLY.contains(k)) return true;
        return k.endsWith("_msd") || k.endsWith("_usescript")
                || k.startsWith("cap_") || k.endsWith("_taplog");
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
     *
     * THE SHADOW READ IS GUARDED TOO. dead() used to return the plain store and
     * the caller read from it bare, so a key the shadow holds as an int threw a
     * ClassCastException straight back out of the "safe" path - a fallback that
     * fails on exactly the values it exists to rescue. Every read now ends at
     * its own default.
     *
     * THE APP CONTEXT IS HELD, not an Activity one. dead() needs a Context to
     * hand to Prefs.fallBack(), and an application Context cannot leak.
     *
     * ONCE DEAD, ALWAYS DEAD - for this instance. `dead` short-circuits the live
     * store entirely, so a wallet with a dead Keystore does not pay a throwing
     * Keystore call per key per tap before reaching the shadow.
     */
    private static final class Shadow implements SharedPreferences {

        private final Context app;
        private final SharedPreferences live;
        private final SharedPreferences plain;

        /** Set by the first read or write that throws. Never cleared. */
        private volatile boolean dead;

        Shadow(Context app, SharedPreferences live, SharedPreferences plain) {
            this.app = app;
            this.live = live;
            this.plain = plain;
        }

        /**
         * The store died. Mark it, tell Prefs, and give back the shadow.
         *
         * Called from a read AND from a write now. The write half is the one
         * that mattered: the service commits the ATC with commit() on the binder
         * thread, and an unguarded throw there was a 6F00 after the cryptogram
         * had already been built.
         */
        private SharedPreferences dead(Throwable t) {
            dead = true;
            Prefs.fallBack(app, plain, t);
            return plain;
        }

        // ------------------------------------------------------------- reads

        @Override public Map<String, ?> getAll() {
            if (dead) return safeAll(plain);
            try { return live.getAll(); } catch (Throwable t) { return safeAll(dead(t)); }
        }

        @Override public String getString(String k, String d) {
            if (dead) return safeString(plain, k, d);
            try { return live.getString(k, d); }
            catch (Throwable t) { return safeString(dead(t), k, d); }
        }

        @Override public Set<String> getStringSet(String k, Set<String> d) {
            if (dead) return safeSet(plain, k, d);
            try { return live.getStringSet(k, d); }
            catch (Throwable t) { return safeSet(dead(t), k, d); }
        }

        @Override public int getInt(String k, int d) {
            if (dead) return safeInt(plain, k, d);
            try { return live.getInt(k, d); }
            catch (Throwable t) { return safeInt(dead(t), k, d); }
        }

        @Override public long getLong(String k, long d) {
            if (dead) return safeLong(plain, k, d);
            try { return live.getLong(k, d); }
            catch (Throwable t) { return safeLong(dead(t), k, d); }
        }

        @Override public float getFloat(String k, float d) {
            if (dead) return safeFloat(plain, k, d);
            try { return live.getFloat(k, d); }
            catch (Throwable t) { return safeFloat(dead(t), k, d); }
        }

        @Override public boolean getBoolean(String k, boolean d) {
            if (dead) return safeBool(plain, k, d);
            try { return live.getBoolean(k, d); }
            catch (Throwable t) { return safeBool(dead(t), k, d); }
        }

        @Override public boolean contains(String k) {
            if (dead) return safeContains(plain, k);
            try { return live.contains(k); }
            catch (Throwable t) { return safeContains(dead(t), k); }
        }

        // ------------------------------------------------------------ writes

        /**
         * One editor, both stores.
         *
         * live.edit() CAN THROW, so a null live editor is a normal case here,
         * not a broken one: the editor is still built and every write goes to
         * the shadow alone.
         */
        @Override public Editor edit() {
            SharedPreferences.Editor le = null;
            if (!dead) {
                try {
                    le = live.edit();
                } catch (Throwable t) {
                    dead(t);
                }
            }
            return new ShadowEditor(this, le, plain);
        }

        @Override public void registerOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener l) {
            if (dead) return;
            try { live.registerOnSharedPreferenceChangeListener(l); } catch (Throwable ignored) { }
        }

        @Override public void unregisterOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener l) {
            if (dead) return;
            try { live.unregisterOnSharedPreferenceChangeListener(l); } catch (Throwable ignored) { }
        }
    }

    /**
     * One editor, two stores.
     *
     * Every operation is applied to both. commit() reports the live result -
     * the shadow is the fallback, not the authority, and a shadow write that
     * fails must not make a successful encrypted write look failed.
     *
     * EVERY LIVE CALL IS GUARDED INDIVIDUALLY. The encryption happens in put*,
     * not in commit - commit only flushes - so guarding the flush alone would
     * have left the throw in the write path where the service actually meets it.
     * The first failure nulls the live editor for the rest of this edit and
     * marks the store dead through the owning Shadow, so the tail of a batch
     * (collect() writes thirty keys in one editor) does not throw thirty times.
     *
     * THE PLAIN WRITE RUNS FIRST AND UNCONDITIONALLY. If the live write throws,
     * the shadow still has the value - which is the entire point of the mirror.
     */
    private static final class ShadowEditor implements SharedPreferences.Editor {

        private final Shadow owner;
        private SharedPreferences.Editor live;
        private final SharedPreferences.Editor plain;

        /** True once the plain side has itself failed; commit() then reports false. */
        private boolean plainBroken;

        ShadowEditor(Shadow owner, SharedPreferences.Editor live,
                     SharedPreferences.Editor plain) {
            this.owner = owner;
            this.live = live;
            this.plain = plain;
        }

        /** Drop the live editor for the rest of this edit. */
        private void drop(Throwable t) {
            live = null;
            if (owner != null) owner.dead(t);
        }

        @Override public SharedPreferences.Editor putString(String k, String v) {
            plainPut(k, v, 0);
            if (live != null) {
                try { live.putString(k, v); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor putStringSet(String k, Set<String> v) {
            plainPut(k, v, 1);
            if (live != null) {
                try { live.putStringSet(k, v); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor putInt(String k, int v) {
            plainPut(k, v, 2);
            if (live != null) {
                try { live.putInt(k, v); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor putLong(String k, long v) {
            plainPut(k, v, 3);
            if (live != null) {
                try { live.putLong(k, v); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor putFloat(String k, float v) {
            plainPut(k, v, 4);
            if (live != null) {
                try { live.putFloat(k, v); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor putBoolean(String k, boolean v) {
            plainPut(k, v, 5);
            if (live != null) {
                try { live.putBoolean(k, v); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor remove(String k) {
            if (plain != null) {
                try { plain.remove(k); } catch (Throwable t) { plainBroken = true; }
            }
            if (live != null) {
                try { live.remove(k); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public SharedPreferences.Editor clear() {
            if (plain != null) {
                try { plain.clear(); } catch (Throwable t) { plainBroken = true; }
            }
            if (live != null) {
                try { live.clear(); } catch (Throwable t) { drop(t); }
            }
            return this;
        }

        @Override public boolean commit() {
            boolean ok;
            if (live == null) {
                ok = false;
            } else {
                try {
                    ok = live.commit();
                } catch (Throwable t) {
                    drop(t);
                    ok = false;
                }
            }
            try {
                if (plain != null) plain.commit();
            } catch (Throwable t) {
                plainBroken = true;
            }
            return ok && !plainBroken;
        }

        @Override public void apply() {
            if (live != null) {
                try {
                    live.apply();
                } catch (Throwable t) {
                    drop(t);
                }
            }
            try {
                if (plain != null) plain.apply();
            } catch (Throwable t) {
                plainBroken = true;
            }
        }

        /** One dispatcher for the plain side, so a throw cannot escape a put*. */
        private void plainPut(String k, Object v, int type) {
            if (plain == null) {
                plainBroken = true;
                return;
            }
            try {
                switch (type) {
                    case 0: plain.putString(k, (String) v); break;
                    case 1: @SuppressWarnings("unchecked")
                            Set<String> s = (Set<String>) v;
                            plain.putStringSet(k, s); break;
                    case 2: plain.putInt(k, (Integer) v); break;
                    case 3: plain.putLong(k, (Long) v); break;
                    case 4: plain.putFloat(k, (Float) v); break;
                    default: plain.putBoolean(k, (Boolean) v); break;
                }
            } catch (Throwable t) {
                plainBroken = true;
            }
        }
    }

    // ------------------------------------------------- guarded read helpers
    //
    // The plain store is a file on disk and can fail too - a full partition, a
    // corrupt XML, a key held as a type the caller did not ask for. Each of
    // these ends at the caller's default instead of throwing, because every one
    // of them is reachable from processCommandApdu.

    private static Map<String, ?> safeAll(SharedPreferences s) {
        try { return s.getAll(); } catch (Throwable t) { return new java.util.HashMap<>(); }
    }

    private static String safeString(SharedPreferences s, String k, String d) {
        try { return s.getString(k, d); } catch (Throwable t) { return d; }
    }

    private static Set<String> safeSet(SharedPreferences s, String k, Set<String> d) {
        try { return s.getStringSet(k, d); } catch (Throwable t) { return d; }
    }

    private static int safeInt(SharedPreferences s, String k, int d) {
        try { return s.getInt(k, d); } catch (Throwable t) { return d; }
    }

    private static long safeLong(SharedPreferences s, String k, long d) {
        try { return s.getLong(k, d); } catch (Throwable t) { return d; }
    }

    private static float safeFloat(SharedPreferences s, String k, float d) {
        try { return s.getFloat(k, d); } catch (Throwable t) { return d; }
    }

    private static boolean safeBool(SharedPreferences s, String k, boolean d) {
        try { return s.getBoolean(k, d); } catch (Throwable t) { return d; }
    }

    private static boolean safeContains(SharedPreferences s, String k) {
        try { return s.contains(k); } catch (Throwable t) { return false; }
    }
}
