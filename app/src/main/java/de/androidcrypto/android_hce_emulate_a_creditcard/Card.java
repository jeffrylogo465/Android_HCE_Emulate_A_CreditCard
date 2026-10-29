package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.SharedPreferences;

/**
 * Typed view of one card's decisions, read once per transaction.
 *
 * WHY THIS EXISTS: 'msd' and 'usescript' are stored with putInt while everything
 * else is a string. SharedPreferences does no coercion, so getString on them
 * throws ClassCastException. That bug appeared in useScript(), was fixed there,
 * and reappeared in doDelete(). A boolean field cannot do it again.
 *
 * Same story for the CID: it was a string that might be "", "80", or junk. It is
 * now an enum or null.
 *
 * Only this class and load() know about prefs. Nothing downstream reads them.
 */
final class Card {

    /** What the card answers. Severity runs DECLINE < ONLINE_ARQC < OFFLINE_TC. */
    enum AcDecision { DECLINE, OFFLINE_TC, ONLINE_ARQC }

    final boolean msd;
    final AcDecision cidOverride;   // null = let the logic decide
    final byte[] mkac;              // null = no key
    private int atc;

    private Card(boolean msd, AcDecision cidOverride, byte[] mkac, int atc) {
        this.msd = msd;
        this.cidOverride = cidOverride;
        this.mkac = mkac;
        this.atc = atc;
    }

    static Card load(SharedPreferences p, String prefix) {
        boolean msd = p.getInt(prefix + "msd", 0) == 1;

        AcDecision over = null;
        String cid = p.getString(prefix + "cid", "");
        if (cid != null) {
            cid = cid.replaceAll("[^0-9A-Fa-f]", "");
            if (cid.length() == 2) {
                int v = Integer.parseInt(cid, 16);
                if (v == 0x00) over = AcDecision.DECLINE;
                else if (v == 0x40) over = AcDecision.OFFLINE_TC;
                else if (v == 0x80) over = AcDecision.ONLINE_ARQC;
            }
        }

        String mk = p.getString(prefix + "mkac", "");
        mk = mk == null ? "" : mk.replaceAll("[^0-9A-Fa-f]", "");
        byte[] mkac = mk.length() >= 32 ? Emv.hex(mk) : null;

        int atc = 0x001B;
        String a = p.getString(prefix + "atc", "001B");
        try {
            a = a == null ? "" : a.replaceAll("[^0-9A-Fa-f]", "");
            if (!a.isEmpty()) atc = Integer.parseInt(a, 16);
        } catch (Exception ignored) { }

        return new Card(msd, over, mkac, atc);
    }

    boolean haveKey() { return mkac != null; }

    /** Allocate the transaction ATC exactly once per tap and persist it. */
    String nextAtc(SharedPreferences p, String prefix) {
        atc = (atc + 1) & 0xFFFF;
        String h = String.format("%04X", atc);
        p.edit().putString(prefix + "atc", h).apply();
        return h;
    }

    /**
     * The single decision, in one place.
     *
     * FIX: three booleans used to overlap here, and an AAC request was answered
     * TC because the flags were tested before the request. CID severity is
     * DECLINE < ONLINE_ARQC < OFFLINE_TC and a card may only answer equal or
     * lower - never better than it was asked.
     */
    AcDecision decide(int requested) {
        if (requested == 0x00) return AcDecision.DECLINE;
        if (cidOverride != null) return cidOverride;
        return haveKey() ? AcDecision.ONLINE_ARQC : AcDecision.OFFLINE_TC;
    }
}
