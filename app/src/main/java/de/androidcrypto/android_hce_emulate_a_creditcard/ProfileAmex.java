package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Locale;

/**
 * American Express, mag-stripe mode.
 *
 * Mag-stripe mode is one COMPUTE CRYPTOGRAPHIC CHECKSUM exchange yielding a
 * dynamic CSC. There is no second GENERATE AC and no ARPC, which is why the AIP
 * claims nothing online: CV and TRM only.
 *
 * AIP 1880: byte 1 0x18 is CV (0x10) + TRM (0x08), byte 2 0x80 is the MSD bit.
 * Byte 1 b8 is RFU under Visa and ExpressPay both - it is not a rung on the
 * ladder, whatever the older notes said. If 1880 is refused, the only live bits
 * left to vary are 0x10 and 0x08: 1080, then 0080.
 *
 * THE AIP IS AN ASSUMPTION, not a verified spec value. Byte 2 b8 is *called* the
 * MSD bit here, but whether ExpressPay assigns it that meaning could not be
 * confirmed - across the contactless kernels, MSD-vs-EMV is driven more by the
 * GPO response format than by one canonical bit. 1880 is what the reference card
 * declares and Amex is mag-stripe by nature, so it stands.
 *
 * THE BITMAPS ARE 9F62 AND 9F63, not the Mastercard 9F65/9F66/9F67. ExpressPay
 * uses PCVC3 to mark the CSC and PUNATC to mark the ATC, exactly as Kernel 2
 * uses 9F66 and 9F67 for the same job. A record with no bitmaps leaves the
 * kernel unable to place the CSC against the track, and it quits straight after
 * the read - the "unable to record" drop on a dispenser.
 *
 * THE UDOL IS 9F69 AND IT IS MANDATORY. Without it the terminal reads the record
 * and then stops: it has nothing naming the CCC data field, so it never sends
 * COMPUTE CRYPTOGRAPHIC CHECKSUM and never gets a CSC to judge. The tap ends
 * with no verdict at all rather than a decline, which is a much harder thing to
 * read from a till. 9F69 names 9F6A over four digits - the nUN - matching
 * udolLen() returning 4 and the 8C 03 9F3704 in the FCI.
 *
 * 9F6E is the Form Factor Indicator. Byte 1 bits 8-6 are the form factor, all
 * zero meaning "no information", so 0000 is safe.
 *
 * 9F2A 04 goes in the directory and the FCI so kernel 4 is picked by identifier.
 * That one is verified: ExpressPay is EMVCo Kernel 4.
 *
 * No IAD: Amex has no CVN block, so defaultIad() is EMPTY (not null).
 *
 * gpo() goes through Profiles.gpoAmex, which emits FORMAT 1 - a raw 80 with AIP
 * and AFL and no inner tags. gpoWithAip would emit a 77, and a mag-stripe kernel
 * rejects a format 2 body carrying no 5A and no 57.
 *
 * LENGTHS: the AID A00000002501 is SIX bytes, so every 4F and 84 that names it
 * is 06. Both constants previously declared 09 and every outer length was wrong
 * with them. The PPSE closes at 6F34 / A522 / BF0C1F / 611D and the FCI at 6F1F /
 * A515. TlvValidator proves both.
 */
public final class ProfileAmex implements CardProfile {

    private static final String PPSE =
            "6F34840E325041592E5359532E4444463031A522BF0C1F611D4F06A00000002501500C414D455820426173652030318701019F2A0104";

    private static final String FCI =
            "6F1F8406A00000002501A515500C414D455820426173652030318701019F2A0104";

    private static final String AIP = "1880";

    /** CSC digits. Amex carries four, like Mastercard. */
    private static final int CSC_LEN = 4;

    /** ATC digits, always four. */
    private static final int ATC_LEN = 4;

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

    /**
     * 57 in a 70, with the CSC and ATC positions marked by 9F62 and 9F63.
     *
     * The offsets are derived from the PAN length, so the bitmaps cannot drift
     * from the track layout: the DD begins one separator, four expiry digits and
     * three service digits after the PAN ends. 9F62 covers the four CSC digits
     * there, 9F63 the four ATC digits behind them.
     *
     * 9F69 follows the bitmaps and names 9F6A over the four nUN digits. The
     * terminal needs it to build COMPUTE CRYPTOGRAPHIC CHECKSUM - the card does
     * not volunteer a CCC field, and without the UDOL the terminal stops after
     * the read with no verdict.
     *
     * The 37-byte cap on the track keeps both Tlv.t length fields in BER short
     * form, one byte each. A track past 127 bytes would need the long form, so
     * raising this without checking Tlv.t breaks the record silently.
     *
     * PAN is checked for digits as well as length - Hex.hex throws on a non-hex
     * character, and a throw here reads as a crash rather than a refusal.
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

        int ddOff = pan.length() + 1 + 4 + 3;

        return Hex.toHex(Tlv.t(0x70, Tlv.cat(
                Tlv.t(0x57, track),
                Tlv.t(0x9F62, Profiles.bits(ddOff, CSC_LEN)),
                Tlv.t(0x9F63, Profiles.bits(ddOff + CSC_LEN, ATC_LEN)),
                Tlv.t(0x9F69, Tlv.t(0x9F6A, new byte[]{0x04})),
                Tlv.t(0x9F6E, new byte[]{0x00, 0x00}))));
    }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(PPSE);
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{"00A4040006A00000002501=" + FCI + "9000"};
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoAmex(AIP, atc);
    }

    /**
     * For TlvValidator. Both hardcoded TLVs this profile serves.
     *
     * public and instance, not static: CardProfile declares it, and a static
     * package-private method cannot implement an interface method. The same
     * applies to ProfileMastercard - if one of these is still `static`, the
     * build stops with "cannot implement scriptConstants() in CardProfile".
     */
    @Override public String[] scriptConstants() {
        return new String[]{PPSE, FCI};
    }
}
