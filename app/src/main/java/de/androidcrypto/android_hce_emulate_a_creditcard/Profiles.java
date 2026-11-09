package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// The profile registry, and the byte builders every profile shares.
// forPan() reads the network off the PAN prefix; byName() is the manual override.
// AUTO means "ask the PAN", and an unrecognised prefix falls through to Mastercard.
public final class Profiles {

    public static final String AUTO = "AUTO";

    private static final String PPSE = "325041592E5359532E4444463031";

    // Mastercard AIP 18 80. Byte 1: 0x80 RFU 0x40 SDA 0x20 DDA 0x10 CV
    // 0x08 TRM 0x04 issuer auth 0x02 on-device CVM 0x01 CDA.
    // 0x18 = CV + TRM. Every ODA bit clear - a clone cannot sign and has no
    // certificates, so claiming them invites a failed check. Byte 2 b8 is
    // "EMV mode supported" and stays on; the MSD path masks it in the service.
    private static final String AIP_MC = "1880";

    // Visa 58 00. b8 is mag-stripe, b7 is qVSDC. 0x58 = qVSDC + CV + TRM.
    //
    // qVSDC STAYS SET even though 0x40 is also the SDA bit and no certificate
    // exists to satisfy SDA. A Visa kernel needs qVSDC or it rejects the app, so
    // the bit cannot be cleared the way Mastercard's can. The consequence is a
    // failed ODA attempt, the TVR bit, and the CTQ's b6 sending the tap online -
    // which is why the CID below follows the key rather than a constant.
    private static final String AIP_VISA = "5800";

    // One AFL entry, TLV-wrapped: SFI 1, rec 1 to 1, none for offline auth.
    private static final String AFL_ONE = "940408010100";

    // The same AFL entry RAW, for format 1. A tag 80 body is AIP || AFL with no
    // inner TLVs - the 94 wrapper is format 2 shape and belongs only in a 77.
    private static final String AFL_RAW = "08010100";

    // Visa CTQ (9F6C): 30 = go online and switch interface if ODA fails.
    // VISA ONLY - in Kernel 2 the same tag is the mag-stripe app version.
    private static final String CTQ_VISA = "9F6C023080";

    private static final CardProfile[] ALL = {
            new ProfileMastercard(),
            new ProfileVisa(),
            new ProfileAmex(),
    };

    private Profiles() { }

    // Selector entries, AUTOMATICO first like the reference app.
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

    // The profile a PAN belongs to, or null when no prefix matches.
    public static CardProfile forPan(String pan) {
        if (pan == null || pan.isEmpty()) return null;
        for (CardProfile p : ALL) if (p.matches(pan)) return p;
        return null;
    }

    // The profile an AID belongs to, or null. Used to sanity-check a typed AID.
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

    // Bitmap of `len` bits starting at `from`, MSB first. Used by the Kernel 2
    // MSD record to describe where the terminal patches the CSC, ATC and nUN.
    // Derived from the real offsets so the bitmap cannot drift from the layout.
    static byte[] bits(int from, int len) {
        byte[] b = new byte[(from + len + 7) / 8];
        for (int i = 0; i < len; i++) {
            int p = from + i;
            b[p / 8] |= (byte) (0x80 >> (p % 8));
        }
        return b;
    }

    // SELECT PPSE line. The response is passed as hex so a constant can be used.
    static String selectPpse(String ppseHex) {
        return "00A404000E" + PPSE + "=" + ppseHex + "9000";
    }

    // A one-applet directory around an AID, with no label.
    //
    // 9F2A names the kernel by identifier so the terminal does not have to infer
    // it from the AID. It is required on a directory this app BUILDS: Visa's
    // qVSDC kernel is 3, and without the tag a reader falls back to its AID
    // table and can land on a different kernel than the one the AIP and GPO
    // were shaped for. Replayed directories (Mastercard, Amex) are the plastic's
    // own bytes and keep whatever the card carried.
    //
    // The value is one byte and comes from kernelFor(), so the id cannot drift
    // from the AID in the same entry.
    static byte[] oneAppPpse(String aidHex) {
        byte[] entry = cat(
                tlv(0x4F, Hex.hex(aidHex)),
                tlv(0x87, new byte[]{0x01}),
                tlv(0x9F2A, new byte[]{(byte) kernelFor(aidHex)}));
        byte[] dir = tlv(0xBF0C, tlv(0x61, entry));
        return tlv(0x6F, cat(tlv(0x84, Hex.hex(PPSE)), tlv(0xA5, dir)));
    }

    // A label-only FCI with no 9F38, so the terminal sends a PDOL-free GPO.
    static byte[] labelFci(String aidHex, String label) {
        String l = (label == null || label.isEmpty()) ? "CARD" : label;
        if (l.length() > 16) l = l.substring(0, 16);
        byte[] prop = cat(
                tlv(0x50, l.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{0x01}));
        return tlv(0x6F, cat(tlv(0x84, Hex.hex(aidHex)), tlv(0xA5, prop)));
    }

    // Kernel 2 GPO in format 2, with a caller-supplied AIP: AIP and AFL only.
    // The AIP is a parameter because the MSD path cannot use the profile
    // constant. The AC is NOT here - Kernel 2 puts it in GENERATE AC.
    static String gpoWithAip(String aip, String atc) {
        String body = "8202" + aip + AFL_ONE;
        return "80A80000=77" + String.format("%02X", body.length() / 2) + body + "9000";
    }

    // Mastercard GPO on the profile AIP. ARQC unused, see above.
    static String gpoMastercard(String atc, String arqc) {
        return gpoWithAip(AIP_MC, atc);
    }

    // Amex MSD GPO: FORMAT 1. Raw AIP || AFL, no 82, no 94. A 77 carrying only
    // 82 and 94 is format 2 shape and a mag-stripe kernel rejects it.
    static String gpoAmex(String aip, String atc) {
        String body = aip + AFL_RAW;
        return "80A80000=80" + String.format("%02X", body.length() / 2) + body + "9000";
    }

    // Visa qVSDC GPO: AIP, AFL, AC, IAD and CTQ. qVSDC folds the decision into
    // the GPO, so the cryptogram and CID belong here and there is no GENERATE
    // AC round trip. Both lengths are computed.
    //
    // THE CID FOLLOWS THE CRYPTOGRAM. It used to be a hardcoded 9F270140 - TC
    // always - even when a real ARQC was being carried in the same template. A
    // qVSDC kernel treats a TC from a card with no DDA bit as a failed offline
    // authentication and has no TVR/TAC path to fall back on, so the tap died
    // with a correct ARQC sitting right next to it. Eight zero bytes mean no
    // key, and only then is TC the honest answer.
    static String gpoVisa(String iad, String atc, String arqc) {
        boolean keyed = arqc != null && arqc.length() == 16 && !arqc.matches("0{16}");
        String cid = keyed ? "80" : "40";
        String body = "8202" + AIP_VISA
                + AFL_ONE
                + "9F2608" + arqc
                + "9F2701" + cid
                + "9F3602" + atc
                + "9F10" + String.format("%02X", iad.length() / 2) + iad
                + CTQ_VISA;
        return "80A80000=77" + String.format("%02X", body.length() / 2) + body + "9000";
    }

    // Kernel id for an AID, used by oneAppPpse() to fill 9F2A.
    //
    // The contactless kernels are numbered by scheme: 2 Mastercard, 3 Visa
    // qVSDC, 4 ExpressPay, 5 JCB, 6 Discover, 7 UnionPay. A Visa AID used to
    // fall through to the 7 branch here, which put UnionPay's id in a Visa
    // directory - the terminal then picked a kernel the AIP and GPO were not
    // shaped for. The default is 3 because every AID that reaches this call
    // comes from a profile, and the unrecognised-prefix fallback is Mastercard.
    static int kernelFor(String aidHex) {
        String a = aidHex == null ? "" : aidHex.toUpperCase();
        if (a.startsWith("A000000152")) return 6;
        if (a.startsWith("A000000065")) return 5;
        if (a.startsWith("A000000025")) return 4;
        if (a.startsWith("A000000333")) return 7;
        if (a.startsWith("A000000004")) return 2;
        if (a.startsWith("A000000015")) return 6;
        return 3;
    }

    // Convenience for a caller holding bytes rather than hex.
    static String of(byte[] d) { return hex(Arrays.copyOf(d, d.length)); }
}
