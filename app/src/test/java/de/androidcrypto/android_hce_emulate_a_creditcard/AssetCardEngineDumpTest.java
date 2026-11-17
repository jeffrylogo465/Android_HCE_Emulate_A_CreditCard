package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Dump mode: loadDump() wires a captured TLV blob into AssetCardEngine as a
 * separate mode from AssetSchemeProfile - the scheme profiles themselves are
 * untouched, and neither test here selects one.
 *
 * Both dumps reuse profile.json's own real chain/records (same bytes
 * DumpChainTest proves close against the real CA key); only the presence of
 * a synthesized tag 93 differs between them, same reasoning as there.
 */
public class AssetCardEngineDumpTest {

    private static final String PROFILE = "src/main/assets/profile.json";
    private static final String ISSUER_PEM = "src/test/resources/iin_313233343536_e3_private_key.pem";

    private static final String SELECT_AID = "00A4040007AFFFFFFFFF123400";
    private static final String GPO = "80A8000002830000";
    private static final String INT_AUTH = "0088000004" + "11223344" + "00";

    private static Map<String, String> tags;
    private static Map<String, String[]> records;
    private static String afl, aip;
    private static BigInteger issuerModulus, issuerPrivateExponent;

    private AssetCardEngine eng;

    @BeforeClass
    public static void loadFixtures() throws Exception {
        JsonObject o = JsonParser.parseString(readAll(PROFILE)).getAsJsonObject();
        afl = o.get("afl").getAsString();
        aip = o.get("aip").getAsString();
        tags = new LinkedHashMap<>();
        for (Map.Entry<String, com.google.gson.JsonElement> e : o.getAsJsonObject("tags").entrySet()) {
            tags.put(e.getKey().toUpperCase(), e.getValue().getAsString());
        }
        records = new LinkedHashMap<>();
        for (Map.Entry<String, com.google.gson.JsonElement> e : o.getAsJsonObject("records").entrySet()) {
            JsonArray a = e.getValue().getAsJsonArray();
            String[] list = new String[a.size()];
            for (int i = 0; i < list.length; i++) list[i] = a.get(i).getAsString();
            records.put(e.getKey(), list);
        }
        byte[] der = org.bouncycastle.util.encoders.Base64.decode(
                readAll(ISSUER_PEM).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
        RSAPrivateKey issuer = RSAPrivateKey.getInstance(ASN1Primitive.fromByteArray(der));
        issuerModulus = issuer.getModulus();
        issuerPrivateExponent = issuer.getPrivateExponent();
    }

    @Before
    public void setUp() throws Exception {
        try (InputStream in = new FileInputStream(PROFILE)) {
            eng = AssetCardEngine.load(in);
        }
    }

    private static String readAll(String path) throws IOException {
        try (InputStream in = new FileInputStream(path)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return new String(bo.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private String send(String apdu) { return Hex.toHex(eng.process(Hex.hex(apdu))); }

    private static byte[] record(String key) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (String t : records.get(key)) {
            byte[] enc = Tlv.t(Integer.parseInt(t, 16), Hex.hex(tags.get(t)));
            body.write(enc, 0, enc.length);
        }
        return Tlv.t(0x70, body.toByteArray());
    }

    private static byte[] allRecordsInAflOrder() {
        return Tlv.cat(record("1:2"), record("2:1"), record("2:2"), record("3:1"), record("3:2"));
    }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        byte[] t = java.util.Arrays.copyOfRange(raw, start, raw.length);
        byte[] out = new byte[len];
        System.arraycopy(t, 0, out, len - t.length, t.length);
        return out;
    }

    private static byte[] synthesizeSsad(byte[] staticData) throws Exception {
        int len = (issuerModulus.bitLength() + 7) / 8;
        byte[] body = Tlv.cat(new byte[]{0x6A, 0x03, 0x01}, new byte[]{0x00, 0x00});
        byte[] pad = new byte[len - body.length - 21];
        java.util.Arrays.fill(pad, (byte) 0xBB);
        body = Tlv.cat(body, pad);
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(body, 1, body.length - 1);
        sha1.update(staticData);
        byte[] block = Tlv.cat(body, sha1.digest(), new byte[]{(byte) 0xBC});
        BigInteger s = new BigInteger(1, block).modPow(issuerPrivateExponent, issuerModulus);
        return unsigned(s, len);
    }

    /** A captured-dump blob built from profile.json's own chain, with or without a synthesized SSAD (tag 93). */
    private static byte[] dumpBlob(boolean withSsad) throws Exception {
        byte[] base = Tlv.cat(
                Tlv.t(0x84, Hex.hex(tags.get("84"))),
                allRecordsInAflOrder(),
                Tlv.t(0x77, Tlv.cat(Tlv.t(0x82, Hex.hex(aip)), Tlv.t(0x94, Hex.hex(afl)))));
        if (!withSsad) return base;

        byte[] staticData = OdaVerifier.buildStaticData(Hex.hex(afl), new OdaVerifier.RecordSource() {
            @Override
            public byte[] read(int sfi, int rec) {
                String[] list = records.get(sfi + ":" + rec);
                if (list == null) return null;
                ByteArrayOutputStream body = new ByteArrayOutputStream();
                for (String t : list) {
                    byte[] enc = Tlv.t(Integer.parseInt(t, 16), Hex.hex(tags.get(t)));
                    body.write(enc, 0, enc.length);
                }
                return Tlv.t(0x70, body.toByteArray());
            }
        }, Hex.hex(aip), Hex.hex(tags.get("9F4A")));
        return Tlv.cat(base, Tlv.t(0x93, synthesizeSsad(staticData)));
    }

    // --------------------------------------------------------------------------

    @Test
    public void sourceAipWithDdaAndTag93_setsSdaClearsDda_6985OnInternalAuthenticate() throws Exception {
        eng.loadDump(dumpBlob(true), null);
        send(SELECT_AID);

        // Provenance, not a mask: profile.json's own captured AIP is 3C00
        // (0011_1100 - DDA(0x20) and Issuer Authentication(0x04) already
        // set, CV(0x10)/TRM(0x08) too). CDA(0x01) and Issuer Authentication
        // (0x04) are always cleared in dump mode (0x04 needs an ARPC from
        // the issuer's own authorisation network, which a dump cannot
        // obtain any more than it can sign a cryptogram) -> 0x38. With tag
        // 93 present, SDA(0x40) is then set and DDA(0x20) cleared:
        // 0x38 | 0x40 = 0x78, & ~0x20 = 0x58. Byte 2 is the source's own (00).
        assertTrue(send(GPO).startsWith("771282025800940C080202001001020018010201"));
        assertEquals("5800", eng.aip());
        assertEquals("5800", eng.tag("82"));
        int b1 = Integer.parseInt(eng.aip().substring(0, 2), 16);
        assertEquals("SDA bit", 0x40, b1 & 0x40);
        assertEquals("DDA bit", 0, b1 & 0x20);
        assertEquals("CDA bit", 0, b1 & 0x01);
        assertEquals("Issuer Authentication bit, cleared even though the source had it", 0, b1 & 0x04);

        assertFalse("no CA key was given to loadDump(), so this must not claim to verify",
                eng.lastDumpVerify().ok);

        // SFI 2 record 2 (P2 = (2<<3)|4 = 0x14): 8F/9F32/92/90, served
        // verbatim, byte for byte, from the dump - not rebuilt from a tag
        // list, so this is exactly profile.json's own record bytes.
        assertEquals(Hex.toHex(record("2:2")) + "9000", send("00B2021400"));

        assertEquals("6985 - the dump has no ICC key, even though the served AIP no longer claims DDA",
                "6985", send(INT_AUTH));
    }

    @Test
    public void sourceAipWithDdaAndNoTag93_preservesDda_6985OnInternalAuthenticate() throws Exception {
        eng.loadDump(dumpBlob(false), null);
        send(SELECT_AID);

        // No tag 93, so nothing supersedes the source's own SDA/DDA bits:
        // the provenance rule leaves them exactly as the source card had
        // them. profile.json's captured AIP (3C00) already had DDA(0x20)
        // set and SDA(0x40) clear. CDA(0x01) and Issuer Authentication
        // (0x04) are still always cleared in dump mode regardless (0x04
        // needs an ARPC a dump cannot obtain) - 0x01 was already 0 here,
        // 0x04 was not, so 3C00 becomes 3800, not unchanged.
        assertEquals("3800", eng.aip());
        int b1 = Integer.parseInt(eng.aip().substring(0, 2), 16);
        assertEquals("SDA bit", 0, b1 & 0x40);
        assertEquals("DDA bit, preserved from the source", 0x20, b1 & 0x20);
        assertEquals("CDA bit", 0, b1 & 0x01);
        assertEquals("Issuer Authentication bit, cleared even though the source had it", 0, b1 & 0x04);

        send(GPO);
        // 6985, not 6D00: the card still claims DDA (see above), so this is
        // a real refusal of a capability it claims, not "no such command".
        assertEquals("6985", send(INT_AUTH));
    }

    @Test
    public void clearDump_restoresTheSchemeOnlyAip() throws Exception {
        eng.loadDump(dumpBlob(true), null);
        send(SELECT_AID);
        assertEquals("58", eng.aip().substring(0, 2));

        eng.clearDump();
        send(SELECT_AID);
        assertEquals("3C00", eng.aip());
        assertFalse(eng.hasDump());
    }
}
