package de.androidcrypto.android_hce_emulate_a_creditcard;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A card that answers from app/src/main/assets/profile.json instead of from
 * hand-typed bytes: the mrautio/emv-card-simulator test card (Zlib licence),
 * AID AFFFFFFFFF1234.
 *
 * Pure Java, no Android types, so the whole PPSE-to-GENERATE-AC flow runs as a
 * plain unit test. ShadowApduService owns one and persists the ATC around it.
 *
 * What it does, and the one place it differs from the source simulator:
 *  - GPO answers a format-2 template, as the simulator's own setup does:
 *    77 { 82 AIP, 94 AFL }.
 *  - The PDOL is read out of the selected application's A5 template (tag 9F38).
 *    The published profile has none, so for this card the GPO data is "83 00".
 *  - READ RECORD walks the AFL and builds each record from the tag list the
 *    profile gives for that SFI/record.
 *  - GENERATE AC derives SK from MK_AC and the ATC (Book 2 A1.3.1) and computes
 *    the AC with ISO 9797-1 MAC Algorithm 3 over CDOL1 data || AIP || ATC || 9F10.
 *    The second GENERATE AC of a transaction is parsed against CDOL2 and its AC
 *    is computed the same way over the CDOL2 data, so it differs from the first.
 *    The CID in both responses is the profile's 9F27. A third one is refused
 *    with 6985.
 *  - The ATC advances once per GPO, as in the simulator.
 */
final class AssetCardEngine {

    static final String AID = "AFFFFFFFFF1234";
    static final String ASSET = "profile.json";

    private static final byte[] PPSE = Hex.hex("325041592E5359532E4444463031");

    // Tag order of the GENERATE AC response, from the profile's setup
    // "80 02 00 03 08 9F27 9F36 9F26 9F10".
    private static final int[] GENAC_TEMPLATE = {0x9F27, 0x9F36, 0x9F26, 0x9F10};

    private static final byte[] SW_OK = Hex.hex("9000");

    private final Map<String, String> tags = new HashMap<>();
    private final Map<String, String[]> records = new HashMap<>();
    private final String pan;
    private final String expiry;
    private final String serviceCode;
    private final String track2;
    private final String afl;
    private final String aip;
    private final String cdol1;
    private final String cdol2;
    private final String mkAc;

    private int atc;

    private boolean selected;
    private boolean gpoOk;
    /** GENERATE ACs answered since the last GPO: 0, 1 or 2. */
    private int acCount;
    private final Map<String, String> terminal = new HashMap<>();

    private AssetCardEngine(JsonObject o) {
        pan = str(o, "pan");
        expiry = str(o, "expiry");
        serviceCode = str(o, "serviceCode");
        track2 = str(o, "track2");
        afl = str(o, "afl");
        aip = str(o, "aip");
        cdol1 = str(o, "cdol1");
        cdol2 = str(o, "cdol2");
        mkAc = str(o, "mkAc");
        atc = Integer.parseInt(str(o, "atc"), 16);

        for (Map.Entry<String, JsonElement> e : o.getAsJsonObject("tags").entrySet()) {
            tags.put(e.getKey().toUpperCase(Locale.ROOT), e.getValue().getAsString());
        }
        for (Map.Entry<String, JsonElement> e : o.getAsJsonObject("records").entrySet()) {
            JsonArray a = e.getValue().getAsJsonArray();
            String[] list = new String[a.size()];
            for (int i = 0; i < list.length; i++) list[i] = a.get(i).getAsString();
            records.put(e.getKey(), list);
        }
        if (Hex.hex(mkAc).length != 16) {
            throw new IllegalArgumentException("MK_AC must be a double-length 3DES key");
        }
        if (Hex.hex(afl).length % 4 != 0 || Hex.hex(aip).length != 2) {
            throw new IllegalArgumentException("bad AIP or AFL in profile");
        }
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        if (e == null || e.isJsonNull()) throw new IllegalArgumentException("profile has no " + k);
        return e.getAsString().toUpperCase(Locale.ROOT);
    }

    static AssetCardEngine load(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        String json = new String(bo.toByteArray(), StandardCharsets.UTF_8);
        return new AssetCardEngine(JsonParser.parseString(json).getAsJsonObject());
    }

    // ---------- profile accessors ----------

    String pan() { return pan; }
    String expiry() { return expiry; }
    String serviceCode() { return serviceCode; }
    String track2() { return track2; }
    String afl() { return afl; }
    String aip() { return aip; }
    String cdol1() { return cdol1; }
    String cdol2() { return cdol2; }
    String mkAc() { return mkAc; }
    String tag(String t) { return tags.get(t.toUpperCase(Locale.ROOT)); }

    int atc() { return atc; }
    void setAtc(int v) { atc = v & 0xFFFF; }

    /** A terminal data object received in the last GPO or GENERATE AC, or null. */
    String terminalData(String t) { return terminal.get(t.toUpperCase(Locale.ROOT)); }

    boolean isSelected() { return selected; }

    // ---------- dispatch ----------

    byte[] process(byte[] apdu) {
        if (apdu == null || apdu.length < 4) return sw("6700");
        int ins = apdu[1] & 0xFF;
        switch (ins) {
            case 0xA4: return select(apdu);
            case 0xA8: return gpo(apdu);
            case 0xB2: return readRecord(apdu);
            case 0xAE: return generateAc(apdu);
            default:   return sw("6D00");
        }
    }

    private static byte[] sw(String hex) { return Hex.hex(hex); }

    /** Command data, or null when Lc promises more than the APDU holds. */
    private static byte[] dataOf(byte[] apdu) {
        if (apdu.length < 5) return new byte[0];
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return null;
        return Arrays.copyOfRange(apdu, 5, 5 + lc);
    }

    private static byte[] ok(byte[] body) { return Tlv.cat(body, SW_OK); }

    private void clearState() {
        selected = false;
        gpoOk = false;
        acCount = 0;
        terminal.clear();
    }

    // ---------- SELECT ----------

    private byte[] select(byte[] apdu) {
        byte[] name = dataOf(apdu);
        if (name == null) return sw("6700");

        if (Arrays.equals(name, PPSE)) {
            byte[] entry = Tlv.t(0x61, Tlv.cat(
                    Tlv.t(0x4F, Hex.hex(AID)),
                    Tlv.t(0x50, Hex.hex(need("50"))),
                    Tlv.t(0x87, Hex.hex(need("87")))));
            byte[] fci = Tlv.t(0x6F, Tlv.cat(
                    Tlv.t(0x84, PPSE),
                    Tlv.t(0xA5, Tlv.t(0xBF0C, entry))));
            return ok(fci);
        }

        if (!Arrays.equals(name, Hex.hex(AID))) return sw("6A82");

        clearState();
        selected = true;
        return ok(Tlv.t(0x6F, Tlv.cat(
                Tlv.t(0x84, Hex.hex(need("84"))),
                Tlv.t(0xA5, Hex.hex(need("A5"))))));
    }

    private String need(String t) {
        String v = tags.get(t);
        if (v == null) throw new IllegalStateException("profile has no tag " + t);
        return v;
    }

    // ---------- GET PROCESSING OPTIONS ----------

    private byte[] gpo(byte[] apdu) {
        if (!selected) return sw("6985");
        byte[] data = dataOf(apdu);
        if (data == null || data.length < 2 || (data[0] & 0xFF) != 0x83) return sw("6700");
        int len = data[1] & 0xFF;
        if (data.length != 2 + len) return sw("6700");

        int[] pdol = parseDol(pdolBytes());
        if (len != dolLength(pdol)) return sw("6700");
        if (atc >= 0xFFFF) return sw("6985");

        terminal.clear();
        takeTerminalData(pdol, Arrays.copyOfRange(data, 2, data.length));

        atc++;
        gpoOk = true;
        acCount = 0;
        return ok(Tlv.t(0x77, Tlv.cat(
                Tlv.t(0x82, Hex.hex(aip)),
                Tlv.t(0x94, Hex.hex(afl)))));
    }

    /** The PDOL out of the A5 template of the selected record, empty if it has none. */
    private byte[] pdolBytes() {
        byte[] v = findTag(Hex.hex(need("A5")), 0x9F38);
        return v == null ? new byte[0] : v;
    }

    private void takeTerminalData(int[] dol, byte[] data) {
        int pos = 0;
        for (int i = 0; i < dol.length; i += 2) {
            terminal.put(String.format(Locale.ROOT, "%X", dol[i]),
                    Hex.toHex(Arrays.copyOfRange(data, pos, pos + dol[i + 1])));
            pos += dol[i + 1];
        }
    }

    // ---------- READ RECORD ----------

    private byte[] readRecord(byte[] apdu) {
        if (!gpoOk) return sw("6985");
        int rec = apdu[2] & 0xFF;
        int p2 = apdu[3] & 0xFF;
        if ((p2 & 0x07) != 0x04) return sw("6A86");
        int sfi = p2 >> 3;

        byte[] a = Hex.hex(afl);
        boolean inAfl = false;
        for (int i = 0; i + 4 <= a.length; i += 4) {
            if (((a[i] & 0xFF) >> 3) == sfi && rec >= (a[i + 1] & 0xFF) && rec <= (a[i + 2] & 0xFF)) {
                inAfl = true;
            }
        }
        String[] list = records.get(sfi + ":" + rec);
        if (!inAfl || list == null) return sw("6A83");

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (String t : list) {
            byte[] enc = Tlv.t(Integer.parseInt(t, 16), Hex.hex(need(t)));
            body.write(enc, 0, enc.length);
        }
        return ok(Tlv.t(0x70, body.toByteArray()));
    }

    // ---------- GENERATE AC ----------

    private byte[] generateAc(byte[] apdu) {
        if (!gpoOk || acCount >= 2) return sw("6985");
        byte[] data = dataOf(apdu);
        int[] dol = parseDol(Hex.hex(acCount == 0 ? cdol1 : cdol2));
        if (data == null || data.length != dolLength(dol)) return sw("6700");

        takeTerminalData(dol, data);

        byte[] atcBytes = EmvCrypto.atcField(atc);
        byte[] iad = Hex.hex(need("9F10"));
        byte[] macIn = Tlv.cat(Tlv.cat(data, Hex.hex(aip)), Tlv.cat(atcBytes, iad));
        byte[] ac;
        try {
            ac = EmvCrypto.mac(sessionKey(Hex.hex(mkAc), atcBytes), macIn);
        } catch (Exception e) {
            throw new IllegalStateException("AC computation failed: " + e.getMessage(), e);
        }

        acCount++;
        byte[] body = new byte[0];
        for (int t : GENAC_TEMPLATE) {
            byte[] v;
            if (t == 0x9F36) v = atcBytes;
            else if (t == 0x9F26) v = ac;
            else v = Hex.hex(need(String.format(Locale.ROOT, "%X", t)));
            body = Tlv.cat(body, Tlv.t(t, v));
        }
        return ok(Tlv.t(0x77, body));
    }

    /**
     * EMV Book 2 A1.3.1, Common Session Key Derivation Option.
     * SK = DES3(MK)[ATC || F0 || 00 x 5] || DES3(MK)[ATC || 0F || 00 x 5].
     * MK_AC is used as the ICC master key as it stands, as the simulator does.
     */
    static byte[] sessionKey(byte[] mk16, byte[] atc2) throws Exception {
        byte[] l = new byte[8];
        byte[] r = new byte[8];
        System.arraycopy(atc2, 0, l, 0, 2);
        System.arraycopy(atc2, 0, r, 0, 2);
        l[2] = (byte) 0xF0;
        r[2] = (byte) 0x0F;
        return Tlv.cat(EmvCrypto.des3(mk16, l), EmvCrypto.des3(mk16, r));
    }

    // ---------- DOL and TLV helpers ----------

    /** A DOL as [tag, length, tag, length, ...]. Throws on a list that stops mid-entry. */
    static int[] parseDol(byte[] dol) {
        int[] out = new int[dol.length];   // upper bound
        int n = 0;
        int i = 0;
        while (i < dol.length) {
            int tag = dol[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                int b;
                do {
                    if (i >= dol.length) throw new IllegalArgumentException("DOL ends inside a tag");
                    b = dol[i++] & 0xFF;
                    tag = (tag << 8) | b;
                } while ((b & 0x80) != 0);
            }
            if (i >= dol.length) throw new IllegalArgumentException("DOL entry has no length");
            out[n++] = tag;
            out[n++] = dol[i++] & 0xFF;
        }
        return Arrays.copyOf(out, n);
    }

    private static int dolLength(int[] dol) {
        int sum = 0;
        for (int i = 1; i < dol.length; i += 2) sum += dol[i];
        return sum;
    }

    /** First occurrence of a tag at the top level of a TLV sequence, or null. */
    static byte[] findTag(byte[] tlv, int wanted) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                int b;
                do {
                    if (i >= tlv.length) return null;
                    b = tlv[i++] & 0xFF;
                    tag = (tag << 8) | b;
                } while ((b & 0x80) != 0);
            }
            if (i >= tlv.length) return null;
            int len = tlv[i++] & 0xFF;
            if (len == 0x81) {
                if (i >= tlv.length) return null;
                len = tlv[i++] & 0xFF;
            } else if (len == 0x82) {
                if (i + 1 >= tlv.length) return null;
                len = ((tlv[i] & 0xFF) << 8) | (tlv[i + 1] & 0xFF);
                i += 2;
            } else if (len > 0x82) {
                return null;
            }
            if (i + len > tlv.length) return null;
            if (tag == wanted) return Arrays.copyOfRange(tlv, i, i + len);
            i += len;
        }
        return null;
    }
}
