package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The profile registry, and the byte builders both profiles share.
 *
 * forPan() is the automatic path - it reads the network off the PAN prefix.
 * byName() is the manual override from the selector. AUTO means "ask the PAN",
 * and an unrecognised prefix falls through to Mastercard.
 */
public final class Profiles {

    public static final String AUTO = "AUTO";

    private static final String PPSE = "325041592E5359532E4444463031";

    /**
     * AIP for the Mastercard profile: 18 80.
     *
     * BYTE 1 - classic EMV, not the Visa meaning:
     *   0x80 RFU        0x40 SDA        0x20 DDA        0x10 CV
     *   0x08 TRM        0x04 issuer auth 0x02 on-device CVM 0x01 CDA
     *
     * 0x18 = CV + TRM. SDA (0x40) is cleared because a clone cannot sign
     * static data and has no 9F4A or certificates - claiming it invites a check
     * that fails. DDA, CDA and issuer auth are cleared for the same reason.
     *
     * BYTE 2 b8 is the one that matters: "EMV mode supported". Without it the
     * kernel does not run EMV mode at all - it drops to mag-stripe mode, which
     * needs 9F6B, PCVC3, PUNATC, NATC, a UDOL and a COMPUTE CRYPTOGRAPHIC
     * CHECKSUM command. This build implements none of those, so the bit is on.
     *
     * The reference card's 5980 is 0x40 SDA + 0x10 + 0x08 + 0x01 CDA, byte 2
     * 0x80 - it can sign, so it keeps SDA and CDA.
     */
    private static final String AIP_MC = "1880";

    /**
     * AIP for the Visa profile: 58 00.
     *
     * Visa numbers byte 1 differently: b8 is mag-stripe, b7 is qVSDC. 0x58 is
     * 0x40 qVSDC + 0x10 CV + 0x08 TRM, with no mag-stripe bit. Byte 2 carries
     * no mode bit for qVSDC.
     */
    private static final String AIP_VISA = "5800";

    /** One AFL entry: SFI 1, rec 1 to 1, none for offline auth. */
    private static final String AFL_ONE = "940408010100";

    /**
     * Visa CTQ (9F6C) as sent by the card.
     *
     * 30 = b6 + b5: go online if ODA fails, switch interface if ODA fails.
     * 80 in byte 2 = Consumer Device CVM performed - correct for a phone.
     *
     * With no CTQ the kernel treats every bit as zero, so a failed
     * authentication is a silent offline decline. Neither fallback reaches an
     * approval while the ARQC is zeros, though - they only classify the decline.
     *
     * VISA ONLY. In Kernel 2 the same tag is the Mag-stripe Application Version
     * Number and has no qualifier bits.
     */
    private static final String CTQ_VISA = "9F6C023080";

    private static final CardProfile[] ALL = {
            new ProfileMastercard(),
            new ProfileVisa(),
    };

    private Profiles() { }

    /** Selector entries, AUTOMATICO first like the reference app. */
    public static String[] names() {
        String[] out = new String[ALL.length + 1];
        out[0] = AUTO;
        for (int i = 0; i < ALL.length; i++) out[i + 1] = ALL[i].name();
        return out;
    }

    public static CardProfile byName(String name) {
        if (name == null) return null;
        for (CardProfile p : ALL) if (p.name().equalsIgnoreCase(name.trim())) return p;
        return null;
    }

    /** The profile a PAN belongs to, or null when no prefix matches. */
    public static CardProfile forPan(String pan) {
        if (pan == null || pan.isEmpty()) return null;
        for (CardProfile p : ALL) if (p.matches(pan)) return p;
        return null;
    }

    /** The profile an AID belongs to, or null. Used to sanity-check a typed AID. */
    public static CardProfile forAid(String aid) {
        if (aid == null || aid.isEmpty()) return null;
        for (CardProfile p : ALL) if (p.matchesAid(aid)) return p;
        return null;
    }

    // ---------- shared builders ----------

    static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    private static byte[] cat(byte[]... arrs) {
        int n = 0;
        for (byte[] a : arrs) n += a.length;
        byte[] out = new byte[n];
        int p = 0;
        for (byte[] a : arrs) { System.arraycopy(a, 0, out, p, a.length); p += a.length; }
        return out;
    }

    static byte[] tlv(int tag, byte[] v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if ((tag & 0xFF00) != 0) {
            o.write((tag >> 8) & 0xFF);
            o.write(tag & 0xFF);
        } else {
            o.write(tag & 0xFF);
        }
        int n = v.length;
        if (n < 0x80) o.write(n);
        else if (n <= 0xFF) { o.write(0x81); o.write(n); }
        else { o.write(0x82); o.write((n >> 8) & 0xFF); o.write(n & 0xFF); }
        o.write(v, 0, n);
        return o.toByteArray();
    }

    /** SELECT PPSE line. The response is passed as hex so a constant can be used. */
    static String selectPpse(String ppseHex) {
        return "00A404000E" + PPSE + "=" + ppseHex + "9000";
    }

    /** A one-applet directory around an AID, with no label and no 9F2A. */
    static byte[] oneAppPpse(String aidHex) {
        byte[] entry = cat(tlv(0x4F, Hex.hex(aidHex)), tlv(0x87, new byte[]{0x01}));
        byte[] dir = tlv(0xBF0C, tlv(0x61, entry));
        return tlv(0x6F, cat(tlv(0x84, Hex.hex(PPSE)), tlv(0xA5, dir)));
    }

    /** A label-only FCI with no 9F38, so the terminal sends a PDOL-free GPO. */
    static byte[] labelFci(String aidHex, String label) {
        String l = (label == null || label.isEmpty()) ? "CARD" : label;
        if (l.length() > 16) l = l.substring(0, 16);
        byte[] prop = cat(
                tlv(0x50, l.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{0x01}));
        return tlv(0x6F, cat(tlv(0x84, Hex.hex(aidHex)), tlv(0xA5, prop)));
    }

    /**
     * Mastercard GPO: AIP and AFL and NOTHING ELSE.
     *
     * Kernel 2 does not put the cryptogram in the GPO in either mode - that is
     * qVSDC's design, not Mastercard's. The AC arrives later in the GENERATE AC
     * response, after the terminal's own risk management and Terminal Action
     * Analysis. So this builder ignores the ARQC it is handed.
     *
     * 10 bytes of body, 0x0A: 82/1880, 94/08010100.
     */
    static String gpoMastercard(String atc, String arqc) {
        String body = "8202" + AIP_MC + AFL_ONE;
        return "80A80000=77" + String.format("%02X", body.length() / 2) + body + "9000";
    }

    /**
     * Visa qVSDC GPO: AIP, AFL, the AC, the IAD and a CTQ.
     *
     * qVSDC really does fold the decision into the GPO, so here the cryptogram
     * and CID belong in the response and there is no GENERATE AC round trip.
     *
     * Both lengths are computed. The 9F10 length used to be the literal 0x11,
     * which pinned every profile to a 17-byte IAD - wrong for the 7-byte VIS
     * shape, and a wrong TLV length desynchronises the parser and kills the tap.
     *
     * 45 bytes of body, 0x2D.
     */
    static String gpoVisa(String iad, String atc, String arqc) {
        String body = "8202" + AIP_VISA
                + AFL_ONE
                + "9F2608" + arqc
                + "9F270140"
                + "9F3602" + atc
                + "9F10" + String.format("%02X", iad.length() / 2) + iad
                + CTQ_VISA;
        return "80A80000=77" + String.format("%02X", body.length() / 2) + body + "9000";
    }

    /** Not used yet, kept so a future profile can reuse the AIP mapping. */
    static int kernelFor(String aidHex) {
        String a = aidHex == null ? "" : aidHex.toUpperCase();
        if (a.startsWith("A000000152")) return 6;
        if (a.startsWith("A000000015")) return 6;
        if (a.startsWith("A000000004")) return 2;
        if (a.startsWith("A000000065")) return 5;
        if (a.startsWith("A000000025")) return 4;
        if (a.startsWith("A000000333")) return 7;
        return 3;
    }

    /** Convenience for a caller holding bytes rather than hex. */
    static String of(byte[] d) { return hex(Arrays.copyOf(d, d.length)); }
}
