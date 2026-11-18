package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * The chain is generated here (CA -> issuer -> ICC), so no vector is copied
 * from anywhere. The builders below follow the same Book 2 layout the verifier
 * reads, which proves round-trip consistency and the failure paths, NOT
 * agreement with a real card. Real-card vectors belong in a separate test.
 *
 * Key sizes differ on purpose: CA 1024, issuer 1024 (needs a remainder, since
 * the CA block only has room for len-36 bytes), ICC 512 (needs BB padding).
 */
public class OdaVerifierTest {

    private static final byte[] RID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x04};
    private static final int CA_INDEX = 0x92;

    private static KeyPair ca, issuer, issuerSmall, icc;
    private static final byte[] ISSUER_ID = {0x12, 0x34, 0x56, (byte) 0xFF};
    private static final byte[] PAN = {0x12, 0x34, 0x56, 0x00, 0x12, 0x34, 0x56, 0x08, (byte) 0xFF, (byte) 0xFF};

    @BeforeClass
    public static void keys() throws Exception {
        ca = gen(1024);
        issuer = gen(1024);
        issuerSmall = gen(512);
        icc = gen(512);
    }

    private static KeyPair gen(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    // ---------------------------------------------------------------- builders

    private static byte[] mod(KeyPair k) {
        return unsigned(((RSAPublicKey) k.getPublic()).getModulus(), -1);
    }

    private static byte[] exp(KeyPair k) {
        return unsigned(((RSAPublicKey) k.getPublic()).getPublicExponent(), -1);
    }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        byte[] t = Arrays.copyOfRange(raw, start, raw.length);
        if (len < 0) return t;
        byte[] out = new byte[len];
        System.arraycopy(t, 0, out, len - t.length, t.length);
        return out;
    }

    private static byte[] sha1(byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        for (byte[] p : parts) md.update(p);
        return md.digest();
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    private static byte[] fill(int n, int v) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    /** raw RSA private operation over a block of exactly signer-modulus length */
    private static byte[] sign(KeyPair signer, byte[] block) {
        RSAPrivateKey p = (RSAPrivateKey) signer.getPrivate();
        BigInteger s = new BigInteger(1, block).modPow(p.getPrivateExponent(), p.getModulus());
        return unsigned(s, block.length);
    }

    /** Issuer certificate (tag 90) signed by the CA. remainder is returned via out[0]. */
    private static byte[] issuerCert(KeyPair signer, KeyPair subject, byte[][] remainderOut) throws Exception {
        byte[] n = mod(subject), e = exp(subject);
        int len = mod(signer).length;
        int region = len - 15 - 21;
        int leftmost = Math.min(n.length, region);
        byte[] rem = Arrays.copyOfRange(n, leftmost, n.length);
        remainderOut[0] = rem;
        byte[] head = cat(new byte[]{0x6A, 0x02}, ISSUER_ID, new byte[]{0x12, 0x30}, new byte[]{0, 0, 1},
                new byte[]{0x01, 0x01, (byte) n.length, (byte) e.length});
        byte[] body = cat(head, Arrays.copyOfRange(n, 0, leftmost), fill(region - leftmost, 0xBB));
        byte[] hash = sha1(Arrays.copyOfRange(body, 1, body.length), rem, e);
        return sign(signer, cat(body, hash, new byte[]{(byte) 0xBC}));
    }

    private static byte[] iccCert(KeyPair signer, KeyPair subject, byte[] staticData, byte[][] remainderOut) throws Exception {
        byte[] n = mod(subject), e = exp(subject);
        int len = mod(signer).length;
        int region = len - 21 - 21;
        int leftmost = Math.min(n.length, region);
        byte[] rem = Arrays.copyOfRange(n, leftmost, n.length);
        remainderOut[0] = rem;
        byte[] head = cat(new byte[]{0x6A, 0x04}, PAN, new byte[]{0x12, 0x30}, new byte[]{0, 0, 2},
                new byte[]{0x01, 0x01, (byte) n.length, (byte) e.length});
        byte[] body = cat(head, Arrays.copyOfRange(n, 0, leftmost), fill(region - leftmost, 0xBB));
        byte[] hash = sha1(Arrays.copyOfRange(body, 1, body.length), rem, e, staticData);
        return sign(signer, cat(body, hash, new byte[]{(byte) 0xBC}));
    }

    private static byte[] sdad(KeyPair signer, byte[] dyn, byte[] ddol) throws Exception {
        int len = mod(signer).length;
        byte[] body = cat(new byte[]{0x6A, 0x05, 0x01, (byte) dyn.length}, dyn, fill(len - 25 - dyn.length, 0xBB));
        byte[] hash = sha1(Arrays.copyOfRange(body, 1, body.length), ddol);
        return sign(signer, cat(body, hash, new byte[]{(byte) 0xBC}));
    }

    private static byte[] ssad(KeyPair signer, byte[] dac, byte[] staticData) throws Exception {
        int len = mod(signer).length;
        byte[] body = cat(new byte[]{0x6A, 0x03, 0x01}, dac, fill(len - 26, 0xBB));
        byte[] hash = sha1(Arrays.copyOfRange(body, 1, body.length), staticData);
        return sign(signer, cat(body, hash, new byte[]{(byte) 0xBC}));
    }

    private static CaKeySet.Key caKey() {
        return new CaKeySet.Key(RID, CA_INDEX, exp(ca), mod(ca));
    }

    // ------------------------------------------------------------------- tests

    @Test
    public void issuerCert_withRemainder_recoversFullModulus() throws Exception {
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuer, rem);
        assertTrue("issuer key must overflow the CA block", rem[0].length > 0);

        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), cert, rem[0], exp(issuer));
        assertTrue(r.toString(), r.ok);
        assertArrayEquals(mod(issuer), r.modulus);
    }

    @Test
    public void issuerCert_withPadding_noRemainder() throws Exception {
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuerSmall, rem);
        assertEquals(0, rem[0].length);

        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), cert, null, exp(issuerSmall));
        assertTrue(r.toString(), r.ok);
        assertArrayEquals(mod(issuerSmall), r.modulus);
    }

    @Test
    public void issuerCert_flippedCertByte_failsAtRecoverOrHeader() throws Exception {
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuer, rem);
        cert[10] ^= 0x01;
        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), cert, rem[0], exp(issuer));
        assertFalse(r.ok);
    }

    @Test
    public void issuerCert_wrongRemainder_failsAtHash() throws Exception {
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuer, rem);
        byte[] bad = rem[0].clone();
        bad[0] ^= 0x01;
        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), cert, bad, exp(issuer));
        assertEquals(OdaVerifier.Step.ISSUER_HASH, r.failedStep);
    }

    @Test
    public void issuerCert_wrongExponent_failsAtHash() throws Exception {
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuer, rem);
        byte[] bad = exp(issuer).clone();
        bad[bad.length - 1] ^= 0x02;
        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), cert, rem[0], bad);
        assertEquals(OdaVerifier.Step.ISSUER_HASH, r.failedStep);
    }

    @Test
    public void issuerCert_remainderLongerThanKey_failsAtLayout() throws Exception {
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuer, rem);
        byte[] tooLong = new byte[300];
        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), cert, tooLong, exp(issuer));
        assertEquals(OdaVerifier.Step.ISSUER_LAYOUT, r.failedStep);
    }

    @Test
    public void issuerCert_missingCaKey() throws Exception {
        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(null, new byte[128], null, new byte[]{3});
        assertEquals(OdaVerifier.Step.CA_KEY, r.failedStep);
    }

    @Test
    public void issuerCert_wrongLengthSignature_failsAtRecover() throws Exception {
        OdaVerifier.Result r = OdaVerifier.verifyIssuerCert(caKey(), new byte[100], null, new byte[]{3});
        assertEquals(OdaVerifier.Step.ISSUER_RECOVER, r.failedStep);
    }

    @Test
    public void iccCert_paddedKey_roundTrip_andStaticDataIsHashed() throws Exception {
        byte[] sd = {1, 2, 3, 4, 5};
        byte[][] rem = new byte[1][];
        byte[] cert = iccCert(issuer, icc, sd, rem);
        assertEquals(0, rem[0].length);

        OdaVerifier.Result r = OdaVerifier.verifyIccCert(mod(issuer), exp(issuer), cert, null, exp(icc), sd);
        assertTrue(r.toString(), r.ok);
        assertArrayEquals(mod(icc), r.modulus);
        assertArrayEquals(PAN, r.pan);

        OdaVerifier.Result bad = OdaVerifier.verifyIccCert(mod(issuer), exp(issuer), cert, null, exp(icc), new byte[]{1, 2, 3, 4, 6});
        assertEquals(OdaVerifier.Step.ICC_HASH, bad.failedStep);
    }

    @Test
    public void iccCert_withRemainder() throws Exception {
        // ICC key as long as the issuer key: block has len-42 bytes of room.
        KeyPair big = gen(1024);
        byte[][] rem = new byte[1][];
        byte[] cert = iccCert(issuer, big, new byte[0], rem);
        assertTrue(rem[0].length > 0);
        OdaVerifier.Result r = OdaVerifier.verifyIccCert(mod(issuer), exp(issuer), cert, rem[0], exp(big), new byte[0]);
        assertTrue(r.toString(), r.ok);
        assertArrayEquals(mod(big), r.modulus);
    }

    @Test
    public void iccCert_issuerCertFormatIsRejected() throws Exception {
        // A format-02 block presented where format 04 is expected.
        byte[][] rem = new byte[1][];
        byte[] cert = issuerCert(ca, issuerSmall, rem);
        OdaVerifier.Result r = OdaVerifier.verifyIccCert(mod(ca), exp(ca), cert, null, exp(icc), new byte[0]);
        assertEquals(OdaVerifier.Step.ICC_HEADER, r.failedStep);
    }

    @Test
    public void sdad_roundTrip_returnsDynamicData() throws Exception {
        byte[] dyn = {0x08, 1, 2, 3, 4, 5, 6, 7, 8};
        byte[] un = {9, 8, 7, 6};
        byte[] sig = sdad(icc, dyn, un);

        OdaVerifier.Result r = OdaVerifier.verifySdad(mod(icc), exp(icc), sig, un);
        assertTrue(r.toString(), r.ok);
        assertArrayEquals(dyn, r.dynamicData);
    }

    @Test
    public void sdad_wrongUnpredictableNumber_failsAtHash() throws Exception {
        byte[] sig = sdad(icc, new byte[]{1, 2, 3}, new byte[]{9, 8, 7, 6});
        OdaVerifier.Result r = OdaVerifier.verifySdad(mod(icc), exp(icc), sig, new byte[]{9, 8, 7, 7});
        assertEquals(OdaVerifier.Step.SDAD_HASH, r.failedStep);
    }

    @Test
    public void sdad_wrongKey_failsBeforeHash() throws Exception {
        byte[] sig = sdad(icc, new byte[]{1}, new byte[]{1});
        OdaVerifier.Result r = OdaVerifier.verifySdad(mod(issuerSmall), exp(issuerSmall), sig, new byte[]{1});
        assertFalse(r.ok);
        assertTrue(r.failedStep == OdaVerifier.Step.SDAD_HEADER || r.failedStep == OdaVerifier.Step.SDAD_RECOVER);
    }

    @Test
    public void ssad_roundTrip_returnsDac() throws Exception {
        byte[] sd = {0x10, 0x20, 0x30};
        byte[] dac = {(byte) 0xAB, (byte) 0xCD};
        byte[] sig = ssad(issuer, dac, sd);

        OdaVerifier.Result r = OdaVerifier.verifySsad(mod(issuer), exp(issuer), sig, sd);
        assertTrue(r.toString(), r.ok);
        assertArrayEquals(dac, r.dac);
    }

    @Test
    public void ssad_changedStaticData_failsAtHash() throws Exception {
        byte[] sig = ssad(issuer, new byte[]{1, 2}, new byte[]{0x10, 0x20});
        OdaVerifier.Result r = OdaVerifier.verifySsad(mod(issuer), exp(issuer), sig, new byte[]{0x10, 0x21});
        assertEquals(OdaVerifier.Step.SSAD_HASH, r.failedStep);
    }

    @Test
    public void ssad_sdadFormatIsRejected() throws Exception {
        byte[] sig = sdad(issuer, new byte[]{1}, new byte[]{1});
        OdaVerifier.Result r = OdaVerifier.verifySsad(mod(issuer), exp(issuer), sig, new byte[]{1});
        assertEquals(OdaVerifier.Step.SSAD_HEADER, r.failedStep);
    }

    // ------------------------------------------------------------- static data

    private static Map<String, byte[]> records() {
        Map<String, byte[]> m = new HashMap<>();
        m.put("1/1", new byte[]{0x70, 0x03, 0x5A, 0x01, 0x11});          // SFI 1: strip 70 03
        m.put("1/2", new byte[]{0x70, 0x02, 0x5F, 0x24});
        m.put("2/1", new byte[]{0x70, 0x01, 0x07});                      // flagged count 0 below
        m.put("11/1", new byte[]{0x77, 0x02, 0x09, 0x09});               // SFI 11: whole record
        return m;
    }

    private static OdaVerifier.RecordSource source(final Map<String, byte[]> m) {
        return new OdaVerifier.RecordSource() {
            @Override
            public byte[] read(int sfi, int record) {
                return m.get(sfi + "/" + record);
            }
        };
    }

    @Test
    public void staticData_flaggedRecordsOnly_stripsTemplate_aipAfterRecords() {
        // SFI1 recs 1-2 (2 flagged), SFI2 rec 1 (0 flagged), SFI11 rec 1 (1 flagged)
        byte[] afl = {0x08, 0x01, 0x02, 0x02, 0x10, 0x01, 0x01, 0x00, 0x58, 0x01, 0x01, 0x01};
        byte[] aip = {0x18, 0x00};
        byte[] got = OdaVerifier.buildStaticData(afl, source(records()), aip, new byte[]{(byte) 0x82});
        // 11 content bytes, right-padded with 0x00 to 16 (STATIC_DATA_PAD).
        byte[] want = {0x5A, 0x01, 0x11, 0x5F, 0x24, 0x77, 0x02, 0x09, 0x09, 0x18, 0x00, 0, 0, 0, 0, 0};
        assertArrayEquals(want, got);
    }

    /**
     * Same three entries and expected output as
     * staticData_flaggedRecordsOnly_stripsTemplate_aipAfterRecords(), but
     * with a 5-byte RID spliced in, length-prefixed, between entry 1 and
     * entry 2 - the same non-spec appended-AID-list shape DumpChain.parse()
     * already accepts into DumpChain.afl (see that class's own doc), which
     * is exactly the afl this method is fed for a loaded dump via
     * verifySda(). Before buildStaticData() shared DumpChain's
     * afterAflEntry()/aflWellFormed() walk, this would have misread the
     * spliced bytes as a bogus further entry and corrupted the hash input
     * (or thrown it out via a spurious "missing record").
     */
    @Test
    public void staticData_aflWithAppendedAid_sameResultAsWithoutIt() {
        byte[] afl = {0x08, 0x01, 0x02, 0x02, 0x05, (byte) 0xA0, 0x00, 0x00, 0x00, 0x03,
                0x10, 0x01, 0x01, 0x00, 0x58, 0x01, 0x01, 0x01};
        byte[] aip = {0x18, 0x00};
        byte[] got = OdaVerifier.buildStaticData(afl, source(records()), aip, new byte[]{(byte) 0x82});
        byte[] want = {0x5A, 0x01, 0x11, 0x5F, 0x24, 0x77, 0x02, 0x09, 0x09, 0x18, 0x00, 0, 0, 0, 0, 0};
        assertArrayEquals(want, got);
    }

    @Test
    public void staticData_noTagList_noAip() {
        byte[] afl = {0x08, 0x01, 0x01, 0x01};
        byte[] got = OdaVerifier.buildStaticData(afl, source(records()), new byte[]{0x18, 0x00}, null);
        // 3 content bytes, right-padded with 0x00 to 8 (STATIC_DATA_PAD).
        assertArrayEquals(new byte[]{0x5A, 0x01, 0x11, 0, 0, 0, 0, 0}, got);
    }

    @Test
    public void staticData_unsupportedTagList_isRefused() {
        byte[] afl = {0x08, 0x01, 0x01, 0x01};
        assertNull(OdaVerifier.buildStaticData(afl, source(records()), new byte[]{0x18, 0x00}, new byte[]{(byte) 0x9F, 0x36}));
    }

    @Test
    public void staticData_nullAipWithSdaTagList_isNullNotNpe() {
        byte[] afl = {0x08, 0x01, 0x01, 0x01};
        assertNull(OdaVerifier.buildStaticData(afl, source(records()), null, new byte[]{(byte) 0x82}));
    }

    @Test
    public void staticData_missingRecord_isNull() {
        byte[] afl = {0x18, 0x01, 0x01, 0x01};   // SFI 3 rec 1 not served
        assertNull(OdaVerifier.buildStaticData(afl, source(records()), new byte[]{0, 0}, null));
    }

    @Test
    public void staticData_sfi1to10_recordWithout70_isNull() {
        Map<String, byte[]> m = new HashMap<>();
        m.put("1/1", new byte[]{0x77, 0x01, 0x00});
        assertNull(OdaVerifier.buildStaticData(new byte[]{0x08, 0x01, 0x01, 0x01}, source(m), new byte[]{0, 0}, null));
    }

    @Test
    public void staticData_feedsSsadAndIccCert_endToEnd() throws Exception {
        byte[] afl = {0x08, 0x01, 0x02, 0x02};
        byte[] aip = {0x3C, 0x00};
        byte[] sd = OdaVerifier.buildStaticData(afl, source(records()), aip, new byte[]{(byte) 0x82});
        assertNotNull(sd);

        byte[] sig = ssad(issuer, new byte[]{0x55, 0x66}, sd);
        assertTrue(OdaVerifier.verifySsad(mod(issuer), exp(issuer), sig, sd).ok);
    }

    // ---------------------------------------------------------------- CaKeySet

    @Test
    public void caKeySet_parsesAndFinds() throws Exception {
        String line = "A000000004 92 03 " + hex(mod(ca));
        CaKeySet set = CaKeySet.load(new StringReader("# comment\n\n" + line + "\n"));
        assertEquals(1, set.size());
        CaKeySet.Key k = set.find(RID, 0x92);
        assertNotNull(k);
        assertArrayEquals(mod(ca), k.modulus);
        assertArrayEquals(new byte[]{3}, k.exponent);
        assertNull(set.find(RID, 0x04));
        assertNull(set.find(new byte[]{1, 2, 3, 4, 5}, 0x92));
    }

    @Test(expected = IllegalArgumentException.class)
    public void caKeySet_badLine_throws() {
        CaKeySet.parseLine("A000000004 92 03");
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02X", x & 0xFF));
        return s.toString();
    }
}
