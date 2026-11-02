package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Mastercard, replayed from the reference card.
 *
 * The directory, the FCI and the second applet are the plastic's own, lifted
 * off it in the reader log byte for byte. The Maestro entry stops a second
 * SELECT from falling through to a generated FCI that would carry 9F2A and a
 * 9F38 PDOL.
 *
 * The FCI deliberately has no 9F38, so the terminal sends a PDOL-free GPO.
 * The label is "CHIP Base 01", 13 characters, which is what the 500D, the A50F
 * and the 6F1A around it all agree with.
 *
 * The GPO is AIP + AFL only - see Profiles.gpoMastercard. The AC comes later,
 * in GENERATE AC.
 */
public final class ProfileMastercard implements CardProfile {

    private static final String PPSE =
            "6F46840E325041592E5359532E4444463031A534BF0C3161184F07A0000000041010500A4D617374657263617264870101"
          + "61154F07A000000004306050074D41455354524F870102";

    private static final String FCI =
            "6F1A8407A0000000041010A50F500D434849502042617365203031";

    private static final String MAESTRO_FCI =
            "6F1A8407A0000000043060A50F500D434849502042617365203031";

    @Override public String name() { return "MASTERCARD"; }

    @Override public String defaultAid() { return "A0000000041010"; }

    @Override public boolean matches(String pan) {
        return pan != null && (pan.startsWith("5") || pan.startsWith("2"));
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null
                && (aid.startsWith("A000000004") || aid.startsWith("A000000005"));
    }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(PPSE);
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{
                "00A4040007A0000000041010=" + FCI + "9000",
                "00A4040007A0000000043060=" + MAESTRO_FCI + "9000",
        };
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoMastercard(atc, arqc);
    }
}
