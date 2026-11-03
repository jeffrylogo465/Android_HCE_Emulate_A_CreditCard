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
 * There are NO bitmaps. 9F65/9F66/9F67 are Mastercard Kernel 2 only; under
 * Visa and ExpressPay the CSC's position in the DD is fixed by the spec, so
 * the record is 70 [ 57 <track> ] and nothing else. There is no UDOL either -
 * 9F69 is Card Authentication Related Data here, and the CCC data field is
 * the UN alone.
 *
 * 9F2A 04 goes in the directory and the FCI so kernel 4 is picked by
 * identifier. No IAD: Amex has no CVN block, so defaultIad() is empty.
 *
 * gpo() goes through Profiles.gpoAmex, which emits FORMAT 1 - a raw 80 with
 * AIP and AFL and no inner tags. gpoWithAip would emit a 77, and a mag-stripe
 * kernel rejects a format 2 body carrying no 5A and no 57.
 */
public final class ProfileAmex implements CardProfile {

    private static final String PPSE = "6F36840E325041592E5359532E4444463031A524BF0C2261204F09A00000002501500C414D455820426173652030318701019F2A0104";

    private static final String FCI = "6F228409A00000002501A515500C414D455820426173652030318701019F2A0104";

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
        return new String[]{"00A4040009A0000000250100=" + FCI + "9000"};
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoAmex(AIP, atc);
    }
}
