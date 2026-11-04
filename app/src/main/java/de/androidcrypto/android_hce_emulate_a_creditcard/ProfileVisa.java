package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * American Express, mag-stripe mode.
 *
 * Mag-stripe mode is one COMPUTE CRYPTOGRAPHIC CHECKSUM exchange yielding a
 * dynamic CSC. There is no second GENERATE AC and no ARPC, which is why the
 * AIP claims nothing online: CV and TRM only.
 *
 * AIP 1880: byte 1 0x18 is CV (0x10) + TRM (0x08), byte 2 0x80 is the MSD bit.
 * Byte 1 b8 is RFU under Visa and ExpressPay both - it is not a rung on the
 * ladder, whatever the older notes said. If 1880 is refused, the only live
 * bits left to vary are 0x10 and 0x08: 1080, then 0080.
 *
 * THE AIP IS AN ASSUMPTION, not a verified spec value. Byte 2 b8 is *called*
 * the MSD bit here, but whether ExpressPay assigns it that meaning could not be
 * confirmed - across the contactless kernels, MSD-vs-EMV is driven more by the
 * GPO response format than by one canonical bit. 1880 is what the reference
 * card declares and Amex is mag-stripe by nature, so it stands; the ladder above
 * is a live thing to try, not trivia.
 *
 * There are NO bitmaps. 9F65/9F66/9F67 are Mastercard Kernel 2 only; under
 * Visa and ExpressPay the CSC's position in the DD is fixed by the spec, so
 * the record is 70 [ 57 <track> ] and nothing else. There is no UDOL either -
 * 9F69 is Card Authentication Related Data here, and the CCC data field is
 * the UN alone.
 *
 * 9F2A 04 goes in the directory and the FCI so kernel 4 is picked by
 * identifier. That one is verified: ExpressPay is EMVCo Kernel 4.
 *
 * No IAD: Amex has no CVN block, so defaultIad() is empty.
 *
 * gpo() goes through Profiles.gpoAmex, which emits FORMAT 1 - a raw 80 with
 * AIP and AFL and no inner tags. gpoWithAip would emit a 77, and a mag-stripe
 * kernel rejects a format 2 body carrying no 5A and no 57.
 *
 * LENGTHS: the AID A00000002501 is SIX bytes, so every 4F and 84 that names it
 * is 06. Both constants previously declared 09 and every outer length was
 * wrong with them - the PPSE was inconsistent at two levels, not uniformly off,
 * so nothing could be fixed by subtracting a constant. The PPSE closes at
 * 6F34 / A522 / BF0C1F / 611D and the FCI at 6F1F / A515. TlvValidator proves
 * both, and ProfileMastercard is the clean baseline to compare against.
 */
public final class ProfileAmex implements CardProfile {

    private static final String PPSE =
            "6F34840E325041592E5359532E4444463031A522BF0C1F611D4F06A00000002501500C414D455820426173652030318701019F2A0104";

    private static final String FCI =
            "6F1F8406A00000002501A515500C414D455820426173652030318701019F2A0104";

    private static final String AIP = "1880";

    @Override public String name() { return "AMEX"; }

    @Override public String defaultAid() { return "A00000002501"; }

    @Override public boolean matches(String pan) {
        return pan != null && (pan.startsWith("34") || pan.startsWith("37"));
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null && aid.startsWith("A000000025");
    }

    @Override public boolean msd() { return true; }

    @Override public String msdAip() { return AIP; }

    @Override public String defaultIad() { return ""; }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(PPSE);
    }

    @Override public String[] selectApp(String aid, String label) {
        // Lc 06 for a 6-byte AID. Le is omitted from the match key so a
        // terminal that does not send one still hits.
        return new String[]{"00A4040006A00000002501=" + FCI + "9000"};
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoAmex(AIP, atc);
    }

    /** For TlvValidator. Both hardcoded TLVs this profile serves. */
    static String[] scriptConstants() {
        return new String[]{PPSE, FCI};
    }
}
