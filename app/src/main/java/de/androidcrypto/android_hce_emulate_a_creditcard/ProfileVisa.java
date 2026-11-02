package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Visa.
 *
 * CONSTRUCTED, not replayed - there is no Visa dump behind this.
 *
 * The IAD is a real VIS shape: inner length 06, DKI 01, CVN 12, 4-byte CVR all
 * zero. It used to be the 17-byte M/Chip block with the institution digit
 * swapped, which was wrong on both the shape and the length.
 *
 * The GPO carries a CTQ, which qVSDC needs and Kernel 2 doesn't have.
 *
 * WHAT THIS CANNOT DO: a qVSDC kernel treats a TC from a card with no DDA bit
 * as a failed offline authentication - it has no TVR/TAC path to fall back on.
 * With a zero ARQC the CTQ's b6 goes online and the issuer declines. So a Visa
 * TC here can never approve until a real MK-AC exists; the profile is for
 * completeness and for reading logs, not for a receipt.
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
}
