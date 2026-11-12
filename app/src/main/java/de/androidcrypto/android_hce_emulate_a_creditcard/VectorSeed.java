package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Stage 2 seed. Writes the vector inputs into the selected card.
 *
 * The PAN is the vector PAN, not the card's own: kdCvc3() derives from pan(),
 * so a different number derives a different key and the tap can never match
 * the harness.
 *
 * THE STORE IS Prefs.get(), NOT getSharedPreferences("hce_card"). This class
 * used to open the plaintext mirror directly while the service, the activities
 * and the reader all go through Prefs - which hands back the ENCRYPTED file
 * whenever the Keystore works. So the seed landed in a file nothing was
 * looking at: the status line said "seeded" and the tap still ran the old card.
 * It only ever appeared to work on a device that had already fallen back to
 * plaintext, which is the one case where the mirror is the live store.
 *
 * 'selected' IS A STRING NOW and was read with getInt(). MainActivity writes it
 * with putString, so on a live store that call threw a ClassCastException -
 * uncaught, out of a dialog callback, straight to the crash handler. The read
 * below is the same guarded string-then-int form the service and the capture
 * screen use.
 *
 * EVERYTHING IS WRITTEN, not just the crypto fields. A seed that sets the key
 * but not the record gives a card with nothing to read: msdSanity() shouts "no
 * skeleton set" and the CCC never fires. The skeleton is built through the
 * profile so its lengths and bitmaps cannot drift from the PAN.
 *
 * THE PROFILE IS PINNED. Without profilepin, the first rebind runs
 * maybeProfile(), sees a 5413 PAN, resolves MASTERCARD and restamps the AID,
 * AIP, IAD and CID - throwing away the Amex shape this seed exists to test.
 *
 * THE CAPTURE IS WIPED. A captured PPSE, FCI or GPO sits in front of the
 * profile, so a stale capture from another card would answer the tap instead
 * and the vector would never be reached. The ATC floor and the committed
 * counter go with it, or a leftover floor from the plastic outranks the seed.
 *
 * CALLER CONTRACT: the prefs are now correct, the boxes on screen are not.
 * MainActivity.collect() runs on every pause and on every keystroke and writes
 * the boxes back over these values, so a caller that does not rebind loses the
 * seed at the first tap. Call bindCard(current) straight after this returns.
 */
public final class VectorSeed {

    /** Eight bytes of DD: CSC 2, ATC 2, nUN 2, two spare, all zero. */
    private static final String DD = "0000000000000000";

    private static final String ATC     = "001B";
    private static final String EXPIRY  = "3112";
    private static final String SERVICE = "201";
    private static final String LABEL   = "AMEX VECTOR";
    private static final String HOLDER  = "VECTOR CARD";
    private static final String AID     = "A00000002501";
    private static final String AIP     = "1880";

    public static String apply(Context c) {
        if (c == null) return "vector seed: no context";

        Context app = c.getApplicationContext();
        SharedPreferences p = Prefs.get(app);
        String slot = "card" + selectedIndex(p) + "_";

        // Built through the profile, so the offsets and the bitmaps follow the
        // PAN instead of being typed here.
        String rec = new ProfileAmex().msdRecord(Cvc3Vector.PAN, EXPIRY, SERVICE, DD);
        if (rec == null) {
            return "vector seed: the Amex record shape refused the vector PAN";
        }

        SharedPreferences.Editor e = p.edit();

        for (String k : p.getAll().keySet()) {
            if (k.startsWith(slot + "cap_") || k.startsWith("cap_")) e.remove(k);
        }

        e.putString(slot + "pan", Cvc3Vector.PAN)
                .putString(slot + "psn", Cvc3Vector.PSN)
                .putString(slot + "expiry", EXPIRY)
                .putString(slot + "service", SERVICE)
                .putString(slot + "discretionary", DD)
                .putString(slot + "track2", "")

                .putString(slot + "label", LABEL)
                .putString(slot + "name", HOLDER)

                // Pinned, so the PAN's own network cannot restamp the shape.
                .putString(slot + "profile", "AMEX")
                .putBoolean(slot + "profilepin", true)
                .putString(slot + "aid", AID)
                .putString(slot + "aip", AIP)
                .putString(slot + "iad", "")
                .putString(slot + "cid", "")
                .putString(slot + "afl", "")

                // Mag-stripe, with the skeleton at SFI 1 rec 1. msd is written
                // explicitly as well as coming from the profile, so the box on
                // screen agrees with the tap.
                .putString(slot + "msd", "1")
                .putString(slot + "msdloc", "0101")
                .putString(slot + "msdrec", rec)

                .putString(slot + "imkcvc3", Cvc3Vector.MK)
                .putString(slot + "ivcvc3", Cvc3Vector.IV)

                // Empty box, so the profile script runs and ccc() is reached.
                .putString(slot + "script", "")

                .putString(slot + "atc", ATC)
                .putString(slot + "seededfor", Cvc3Vector.PAN)
                .remove(slot + "atcfloor")
                .remove(slot + "atccommitted")
                .apply();

        return "seeded amex vector, pan " + Cvc3Vector.PAN + " in " + slot
                + " - rebind the card or the next pause overwrites it";
    }

    /**
     * The selected slot index, as a string.
     *
     * Raw read, guarded twice: a string on a current build, an int from an
     * older one or the plaintext mirror. "0" when neither works - slot 0 is what
     * every default in the app already assumes.
     */
    private static String selectedIndex(SharedPreferences p) {
        String raw = null;
        try {
            raw = p.getString("selected", null);
        } catch (ClassCastException storedAsInt) {
            try {
                raw = String.valueOf(p.getInt("selected", 0));
            } catch (Throwable ignored) {
                raw = null;
            }
        } catch (Throwable ignored) {
            raw = null;
        }
        if (raw == null || raw.trim().isEmpty()) raw = "0";
        return raw.trim();
    }

    private VectorSeed() { }
}
