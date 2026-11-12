package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.util.Arrays;

/**
 * Pins the INS dispatch in ShadowApduService.processCommandApdu.
 *
 * Expected bytes are the service's current output for a fresh install with the
 * default profile (no key, so the application cryptogram is eight zero bytes).
 * Each test gets a fresh service and fresh SharedPreferences.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class ShadowApduServiceDispatchTest {

    private ShadowApduService svc;

    @Before
    public void setUp() {
        // Prefs caches its SharedPreferences in a static, which outlives the
        // per-test Robolectric application. Without this the ATC counter
        // carries over from one test to the next and the bytes depend on order.
        Prefs.reset(RuntimeEnvironment.getApplication());
        svc = Robolectric.buildService(ShadowApduService.class).create().get();
    }

    private byte[] send(String apduHex) {
        return svc.processCommandApdu(Hex.hex(apduHex), null);
    }

    private static byte[] sw(byte[] r) {
        return Arrays.copyOfRange(r, r.length - 2, r.length);
    }

    @Test
    public void select_ppse_returnsFciAnd9000() {
        assertEquals(
                "6F27840E325041592E5359532E4444463031A515BF0C1261104F07A00000000310108701019F2A01039000",
                Hex.toHex(send("00A404000E325041592E5359532E4444463031")));
    }

    @Test
    public void gpo_returnsFormat2TemplateAnd9000() {
        assertEquals(
                "772D820258009404080101009F260800000000000000009F2701409F3602001C"
                        + "9F1007060112000000009F6C0230809000",
                Hex.toHex(send("80A8000002830000")));
    }

    @Test
    public void readRecord_returnsRecordAnd9000() {
        assertEquals(
                "70818D9F420208405F24033112015A0841111111111111115F3401019F0702FFC0"
                        + "9F080200028C159F02069F03069F1A0295055F2A029A039C019F37048D18"
                        + "9F02069F03069F1A0295055F2A029A039C019F37049F34038E0C00000000"
                        + "00000000" + "1F031E039F0D0500000000009F0E0500000000009F0F05"
                        + "00000000005F28020840570C4111111111111111D31122019000",
                Hex.toHex(send("00B2010C00")));
    }

    @Test
    public void readRecord_missingRecord_returns6A83() {
        assertEquals("6A83", Hex.toHex(send("00B20000")));
    }

    @Test
    public void generateAc_returnsFormat2TemplateAnd9000() {
        assertEquals(
                "771E9F100706010A03A000009F260800000000000000009F2701009F3602001C9000",
                Hex.toHex(send("80AE00000000")));
    }

    @Test
    public void computeCryptographicChecksum_withoutRecordRead_returns6985() {
        assertEquals("6985", Hex.toHex(send("802A8E8004000000000000")));
    }

    @Test
    public void computeCryptographicChecksum_afterRecordRead_returnsCccTemplate() {
        send("00B2010C00");
        assertEquals("770A9F610200009F3602001C9000",
                Hex.toHex(send("802A8E8004000000000000")));
    }

    @Test
    public void getData_unknownTag_returns6A88() {
        assertEquals("6A88", Hex.toHex(send("80CA9F1700")));
    }

    @Test
    public void verify_returns9000() {
        assertEquals("9000", Hex.toHex(send("0020000800")));
    }

    @Test
    public void getChallenge_returnsEightBytesAnd9000() {
        byte[] r = send("0084000008");
        assertEquals(10, r.length);
        assertArrayEquals(Hex.hex("9000"), sw(r));
    }

    @Test
    public void unknownIns_returnsUnsupported6D00() {
        assertEquals("6D00", Hex.toHex(send("00FF000000")));
    }

    @Test
    public void tooShortApdu_returnsMalformed6700() {
        assertEquals("6700", Hex.toHex(send("80A8")));
    }

    @Test
    public void knownInsWithEmptyOrTruncatedData_doesNotThrow() {
        // Header only, then header plus a Lc that promises more than is there.
        String[] apdus = {
                "00A40400", "00A4040002AA",
                "80A80000", "80A80000028300",
                "00B20000", "00B2010C",
                "80AE0000", "80AE000002",
                "802A0000", "802A8E80", "802A8E8004",
                "80CA0000", "80CA9F17",
                "00200000", "00840000"};
        for (String a : apdus) {
            byte[] r = send(a);
            assertNotNull(a, r);
            assertTrue(a + " too short: " + Hex.toHex(r), r.length >= 2);
            // 6F00 is the catch-all for an exception swallowed inside the service.
            assertTrue(a + " hit the catch-all: " + Hex.toHex(r),
                    !Arrays.equals(sw(r), Hex.hex("6F00")));
        }
    }
}
