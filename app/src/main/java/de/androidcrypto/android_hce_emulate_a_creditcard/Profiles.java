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
     * Visa CTQ (9F6C) as sent by the card.
     *
     * 30 = b6 + b5: go online if ODA fails, switch interface if ODA fails.
     * 80 in byte 2 = Consumer Device CVM performed - correct for a phone, and
     * it satisfies a CVM demand without PIN or signature.
     *
     * Why it matters: with no CTQ the kernel treats every bit as zero, and zero
     * means no permission to go online and no permission to switch interface,
     * so a failed authentication becomes a silent offline decline.
     *
     * Neither fallback reaches an approval while the ARQC is zeros - b6 leads
     * to an online decline and b5 to "insert card". They only convert a hard
     * local decline into a classified one.
     *
     * VISA ONLY. In Mastercard Kernel 2 the same tag is the Mag-stripe
     * Application Version Number - a 2-byte version with no qualifier bits -
     * so sending this value on a Mastercard GPO is nonsense. Kernel 2 has no
     * CTQ at all: offline authentication is CDA tied to GENERATE AC and the
     * TAC/IAC pair decides from the TVR.
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
     * The GPO line, Kernel 2 shape: no 9F6C.
     *
     * AIP 5800, one AFL entry over SFI 1 rec 1, the ARQC, CID 40, the live ATC
     * and the network's IAD. The 77 length is computed from the body, so it can
     * never disagree with the bytes it covers.
     *
     * CID 40 means approve offline, so the ARQC is never checked - which is why
     * eight zero bytes are fine when no issuer key is set.
     *
     * WHY THE 9F10 LENGTH IS COMPUTED: it used to be the literal 0x11, which
     * pinned every profile to a 17-byte IAD. Mastercard's IAD is 17 bytes and
     * Visa's VIS IAD is 7, so the literal was wrong for one of them, and a
     * wrong TLV length desynchronises the kernel's parser and kills the
     * transaction outright.
     *
     * 50 bytes of body, 0x32: 82/5800, 94/08010100, 9F26/8, 9F27/40,
     * 9F36/<atc>, 9F10/<len>.
     */
    static String gpo(String iad, String atc, String arqc) {
        return gpo(iad, atc, arqc, "");
    }

    /** The same body plus a Visa CTQ. See CTQ_VISA. */
    static String gpoVisa(String iad, String atc, String arqc) {
        return gpo(iad, atc, arqc, CTQ_VISA);
    }

    private static String gpo(String iad, String atc, String arqc, String extra) {
        String body = "82025800"
                + "940408010100"
                + "9F2608" + arqc
                + "9F270140"
                + "9F3602" + atc
                + "9F10" + String.format("%02X", iad.length() / 2) + iad
                + extra;
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
