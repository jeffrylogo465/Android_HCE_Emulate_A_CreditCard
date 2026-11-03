package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The profile registry, and the byte builders every profile shares.
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
     *   0x80 RFU  0x40 SDA  0x20 DDA  0x10 CV
     *   0x08 TRM  0x04 issuer auth  0x02 on-device CVM  0x01 CDA
     *
     * 0x18 = CV + TRM. Every ODA bit is clear - a clone cannot sign static data
     * and has no 9F4A or certificates, so claiming them invites a failed check.
     *
     * BYTE 2 b8 is "EMV mode supported". It stays on here; the MSD path is
     * entered from the other side, by the service masking this byte.
     */
    private static final String AIP_MC = "1880";

    /** Visa: 58 00. b8 is mag-stripe, b7 is qVSDC. 0x58 = qVSDC + CV + TRM. */
    private static final String AIP_VISA = "5800";

    /**
     * AIP for Amex: 1C 00.
     *
     * Classic numbering. 0x1C = CV + TRM + issuer auth, every ODA bit clear.
     * BYTE 2 is 00 deliberately: no EMV-mode bit, so the kernel takes the
     * mag-stripe path and runs the CVC3 exchange - the one offline decision a
     * card can make without the issuer's key.
     */
    private static final String AIP_AMEX = "1C00";

    /** One AFL entry: SFI 1, rec 1 to 1, none for offline auth. */
    private static final String AFL_ONE = "940408010100";

    /**
     * Visa CTQ (9F6C): 30 = go online and switch interface if ODA fails.
     * VISA ONLY - in Kernel 2 the same tag is the mag-stripe app version.
     */
    private static final String CTQ_VISA = "9F6C023080";

    private static final CardProfile[] ALL = {
            new ProfileMastercard(),
            new ProfileVisa(),
            new ProfileAmex(),
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
     * Kernel 2 GPO with a caller-supplied AIP: AIP and AFL and nothing else.
     *
     * The AIP is a parameter because the MSD path cannot use the profile
     * constant - reaching mag-stripe mode means the EMV-mode bit has to go, so
     * the service masks the AIP on the way in. Everything else is identical.
     *
     * The AC is NOT here. Kernel 2 puts the cryptogram in GENERATE AC in both
     * modes. 10 bytes of body, 0x0A.
     */
    static String gpoWithAip(String aip, String atc) {
        String body = "8202" + aip + AFL_ONE;
        return "80A80000=77" + String.format("%02X", body.length() / 2) + body + "9000";
    }

    /** Mastercard GPO on the profile AIP. ARQC unused, see above. */
    static String gpoMastercard(String atc, String arqc) {
        return gpoWithAip(AIP_MC, atc);
    }

    /** Amex GPO on the profile AIP. Same shape, same unused ARQC. */
    static String gpoAmex(String atc, String arqc) {
        return gpoWithAip(AIP_AMEX, atc);
    }

    /**
     * Visa qVSDC GPO: AIP, AFL, AC, IAD and CTQ.
     *
     * qVSDC does fold the decision into the GPO, so the cryptogram and CID
     * belong here and there is no GENERATE AC round trip. Both lengths are
     * computed - the 9F10 length used to be the literal 0x11, which pinned
     * every profile to a 17-byte IAD and desynchronised the parser.
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
