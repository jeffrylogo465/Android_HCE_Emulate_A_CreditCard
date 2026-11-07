package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Locale;

/**
 * Visa.
 *
 * CONSTRUCTED, not replayed - there is no Visa dump behind this.
 *
 * The IAD is a real VIS shape: inner length 06, DKI 01, CVN 12, 4-byte CVR all
 * zero. It used to be the 17-byte M/Chip block with the institution digit
 * swapped, which was wrong on both shape and length.
 *
 * qVSDC folds the decision into the GPO, so this profile does carry the AC and
 * the CTQ - unlike Mastercard.
 *
 * WHAT THIS CANNOT DO: a qVSDC kernel treats a TC from a card with no DDA bit as
 * a failed offline authentication, and has no TVR/TAC path to fall back on. With
 * a zero ARQC the CTQ's b6 goes online and the issuer declines. A Visa TC here
 * can never approve until a real MK-AC exists.
 *
 * msdAip() returns 1880 so the dump path can run this card as MSD instead: byte 1
 * 0x18 is CV + TRM with qVSDC dropped, byte 2 0x80 is the MSD bit. The default
 * mask would clear that bit, which is why it has to be supplied rather than
 * derived - under Visa the bit IS MSD, the opposite of Mastercard.
 */
public final class ProfileVisa implements CardProfile {

    /** VIS IAD: inner length 06, DKI 01, CVN 12, CVR 00000000. */
    private static final String IAD = "06011200000000";

    @Override public String name() { return "VISA"; }

    @Override public String defaultAid() { return "A0000000031010"; }

    @Override public boolean matches(String pan) {
        return pan != null && pan.startsWith("4");
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null && aid.startsWith("A000000003");
    }

    @Override public String msdAip() { return "1880"; }

    /**
     * Bare 57 in a 70, CSC 3 digits (dCVV) at a fixed offset.
     *
     * Visa defines no bitmaps and no UDOL for mag-stripe, so there is nothing to
     * describe - the CCC data field is the UN alone and the position is fixed by
     * the spec.
     */
    @Override public String msdRecord(String pan, String exp, String svc, String dd) {
        if (pan == null || pan.length() < 12 || pan.length() > 19) return null;
        if (!pan.matches("[0-9]+")) return null;

        String e = (exp == null || exp.length() < 4) ? "3112" : exp;
        String s = svc == null ? "" : svc;
        while (s.length() < 3) s = "0" + s;
        String d = dd == null ? "" : dd.toUpperCase(Locale.ROOT).replaceAll("[^0-9A-F]", "");

        StringBuilder t = new StringBuilder(pan).append('D')
                .append(e, 0, 4).append(s, 0, 3).append(d);
        if (t.length() % 2 != 0) t.append('F');

        byte[] track = Hex.hex(t.toString());
        if (track.length > 37) return null;
        return Hex.toHex(Tlv.t(0x70, Tlv.t(0x57, track)));
    }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(Profiles.hex(Profiles.oneAppPpse(aid)));
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{
                "00A4040007" + aid + "=" + Profiles.hex(Profiles.labelFci(aid, label)) + "9000",
        };
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoVisa(IAD, atc, arqc);
    }

    /**
     * For TlvValidator. Visa generates its directory and FCI instead of holding
     * them as constants, so these are the same builders selectPpse() and
     * selectApp() use - not a copy that can drift.
     *
     * The AID comes from defaultAid() rather than a literal, so the validator
     * cannot keep passing after the profile's own AID changes.
     */
    @Override public String[] scriptConstants() {
        String aid = defaultAid();
        return new String[]{
                Profiles.hex(Profiles.oneAppPpse(aid)),
                Profiles.hex(Profiles.labelFci(aid, "VISA")),
        };
    }
}
