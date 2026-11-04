package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Mastercard, replayed from the reference card.
 *
 * The directory, the FCI and the second applet are the plastic's own, lifted off
 * it in the reader log byte for byte. That pair is proven on a till and the
 * Maestro entry stops a second SELECT from falling through to a generated FCI
 * that would carry 9F2A and a 9F38 PDOL.
 *
 * The FCI deliberately has no 9F38, so the terminal sends a PDOL-free GPO.
 *
 * LENGTHS: every outer length is the byte count of what it covers, and the label
 * is 12 bytes. "CHIP Base 01" is 12 characters - it was written against a 500D
 * before, which made the FCI one byte longer in its headers than in its content
 * and would desync a length-parsing kernel. The PPSE had the same fault one
 * level up. Both are now self-consistent.
 *
 * The PPSE closes at 6F46 / A534 / BF0C31 / 6118 / 6115 - 70, 52, 49, 24 and 21
 * bytes of content. It was 6F45 / A533, one short at two levels, which truncated
 * the final 02 of the Maestro 87 01 02 and made a length-validating kernel drop
 * the field after the directory SELECT.
 *
 * The GPO comes from Profiles.gpoMastercard, which builds AIP and AFL and
 * nothing else - Kernel 2 does not carry the cryptogram in the GPO.
 *
 * IAD: defaultIad() returns the reference card's own block. It used to be a
 * constant nothing read, so the service fell through to the generic M/Chip
 * default - byte 2 of which is CVN 10 against this card's 16. Both are SKD so
 * the scheme never changed, which is why it worked; but the IAD goes into the
 * MAC input, so a correct key would still have produced a wrong ARQC.
 */
public final class ProfileMastercard implements CardProfile {

    private static final String PPSE =
            "6F46840E325041592E5359532E4444463031A534BF0C3161184F07A0000000041010500A4D617374657263617264870101"
          + "61154F07A000000004306050074D41455354524F870102";

    private static final String FCI =
            "6F198407A0000000041010A50E500C434849502042617365203031";

    private static final String MAESTRO_FCI =
            "6F198407A0000000043060A50E500C434849502042617365203031";

    /** The reference card's own IAD. Byte 2 is the CVN: 0x10 = 16, so SKD. */
    private static final String IAD = "0110A000092400000102000000000000FF";

    @Override public String name() { return "MASTERCARD"; }

    @Override public String defaultAid() { return "A0000000041010"; }

    @Override public boolean matches(String pan) {
        return pan != null && (pan.startsWith("5") || pan.startsWith("2"));
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null
                && (aid.startsWith("A000000004") || aid.startsWith("A000000005"));
    }

    @Override public String defaultIad() { return IAD; }

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

    /** For TlvValidator. Its own directory and both FCIs. */
    static String[] scriptConstants() {
        return new String[]{PPSE, FCI, MAESTRO_FCI};
    }
}
