package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Stage 2 seed. Writes the vector inputs into the selected card.
 *
 * The PAN is the vector PAN, not the card's own: kdCvc3() derives from pan(),
 * so a different number derives a different key and the tap can never match
 * the harness.
 */
public final class VectorSeed {

    public static String apply(Context c) {
        SharedPreferences p = c.getSharedPreferences("hce_card", Context.MODE_PRIVATE);
        String k = "card" + p.getInt("selected", 0) + "_";
        p.edit()
                .putString(k + "profile", "AMEX")
                .putString(k + "imkcvc3", Cvc3Vector.MK)
                .putString(k + "ivcvc3", Cvc3Vector.IV)
                .putString(k + "pan", Cvc3Vector.PAN)
                .putString(k + "psn", Cvc3Vector.PSN)
                .putString(k + "expiry", "3112")
                .putString(k + "service", "201")
                .putString(k + "msdloc", "0101")
                .putString(k + "script", "")
                .apply();
        return "seeded amex vector, pan " + Cvc3Vector.PAN + ", script cleared";
    }

    private VectorSeed() { }
}
