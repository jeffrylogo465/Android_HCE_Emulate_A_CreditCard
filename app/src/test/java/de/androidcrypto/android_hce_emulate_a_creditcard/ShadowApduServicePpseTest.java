package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.List;

/**
 * The tap that never leaves the PPSE: a real terminal selects the PPSE, reads
 * the directory, and never selects an AID. dumpsys nfc on the live tap shows
 * routing and the preferred service are both fine, so the only thing left for
 * the terminal to reject is the directory FCI itself.
 *
 * buildPpse() takes two paths: a captured PPSE is replayed close to verbatim,
 * a generated one is built from the active AID. The generated path has always
 * produced one bounded entry (see ShadowApduServiceDispatchTest's pinned
 * bytes) and EXTRA_AIDS is off, so these tests pin the other path: a captured
 * PPSE is validated the same way patchFci() already validates a captured FCI
 * (truncation falls back to generated) plus two checks that only a bad capture
 * can fail - too many entries, or the PPSE's own AID listed as an application.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class ShadowApduServicePpseTest {

    private static final String PPSE_NAME = "325041592E5359532E4444463031";
    private static final String SELECT_PPSE = "00A404000E" + PPSE_NAME;
    private static final String SELECT_AFFFFFFFFF1234 = "00A4040007AFFFFFFFFF1234";
    private static final String SELECT_A0000000041010 = "00A4040007A0000000041010";

    private ShadowApduService svc;

    @Before
    public void setUp() {
        Prefs.reset(RuntimeEnvironment.getApplication());
    }

    private void start() {
        svc = Robolectric.buildService(ShadowApduService.class).create().get();
    }

    private String send(String apduHex) {
        return Hex.toHex(svc.processCommandApdu(Hex.hex(apduHex), null));
    }

    private void putCapturedPpse(String hex) {
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("card0_cap_rawppse", hex).commit();
    }

    /**
     * Every profile arms its own default script - PPSE, FCI, GPO - which
     * answers the PPSE select before buildPpse() ever runs (scriptMatch() is
     * checked ahead of select() in processCommandApdu). A capture is only
     * reachable once that default is out of the way, exactly as it would be
     * for a real user who has typed anything at all into the script box -
     * useScript() then reads the box's own lines, not the profile default.
     */
    private void disableDefaultProfileScript() {
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("card0_script", "# no script armed").commit();
    }

    // ---- tiny BER-TLV reader, independent of ShadowApduService's own, so the
    // ---- test does not share a bug with the code it is checking ----

    private static int[] readTlv(byte[] b, int pos, int[] tagOut, int[] lenOut) {
        int tag = b[pos++] & 0xFF;
        if ((tag & 0x1F) == 0x1F) {
            int next;
            do {
                next = b[pos++] & 0xFF;
                tag = (tag << 8) | next;
            } while ((next & 0x80) != 0);
        }
        int len = b[pos++] & 0xFF;
        if ((len & 0x80) != 0) {
            int n = len & 0x7F, v = 0;
            for (int k = 0; k < n; k++) v = (v << 8) | (b[pos++] & 0xFF);
            len = v;
        }
        tagOut[0] = tag;
        lenOut[0] = len;
        return new int[]{pos};
    }

    /** Every 4F found anywhere under a 61 entry, walking the whole directory. */
    private static List<String> entryAids(byte[] ppse) {
        List<String> aids = new ArrayList<>();
        collectEntries(ppse, 0, ppse.length, aids);
        return aids;
    }

    private static void collectEntries(byte[] b, int from, int to, List<String> aids) {
        int i = from;
        while (i < to) {
            int[] tagOut = new int[1], lenOut = new int[1];
            int bodyPos = readTlv(b, i, tagOut, lenOut)[0];
            int tag = tagOut[0], len = lenOut[0];
            if (bodyPos + len > to) return;

            if (tag == 0x61) {
                int j = bodyPos, end = bodyPos + len;
                while (j < end) {
                    int[] t2 = new int[1], l2 = new int[1];
                    int v2 = readTlv(b, j, t2, l2)[0];
                    if (v2 + l2[0] > end) break;
                    if (t2[0] == 0x4F) {
                        aids.add(Hex.toHex(java.util.Arrays.copyOfRange(b, v2, v2 + l2[0])));
                    }
                    j = v2 + l2[0];
                }
            } else if (tag == 0xA5 || tag == 0xBF0C || tag == 0x6F) {
                collectEntries(b, bodyPos, bodyPos + len, aids);
            }
            i = bodyPos + len;
        }
    }

    private static String stripSw(String rHex) {
        return rHex.substring(0, rHex.length() - 4);
    }

    @Test
    public void generatedDirectory_isBoundedAndNeverListsThePpseAidItself() {
        disableDefaultProfileScript();
        start();
        String r = send(SELECT_PPSE);
        assertTrue("PPSE select must end 9000: " + r, r.endsWith("9000"));

        List<String> aids = entryAids(Hex.hex(stripSw(r)));
        assertFalse("generated directory has no entries", aids.isEmpty());
        assertTrue("generated directory has " + aids.size()
                        + " entries, more than a real card would (<=3)",
                aids.size() <= 3);
        for (String a : aids) {
            assertFalse("generated directory lists the PPSE's own AID as an app",
                    a.equalsIgnoreCase(PPSE_NAME));
        }
    }

    @Test
    public void capturedDirectory_tooManyEntries_fallsBackToGenerated() {
        // Five applications in one directory - a real card lists one to three.
        putCapturedPpse("6F4C840E325041592E5359532E4444463031A53ABF0C37"
                + "61094F07A000000003101061094F07A000000003101161094F07A0000000031012"
                + "61094F07A000000003101361094F07A0000000031014");
        disableDefaultProfileScript();
        start();
        String r = send(SELECT_PPSE);
        assertTrue(r.endsWith("9000"));

        List<String> aids = entryAids(Hex.hex(stripSw(r)));
        assertTrue("fallback directory should be bounded like the generated one",
                aids.size() <= 3);
        // It fell back to the generated single-AID directory, not the 5-entry capture.
        assertFalse(aids.contains("A0000000031011"));
    }

    @Test
    public void capturedDirectory_listsThePpseAidAsAnApp_fallsBackToGenerated() {
        // One entry, but its 4F is the PPSE's own name - the directory selecting
        // itself as if it were an application.
        putCapturedPpse("6F27840E325041592E5359532E4444463031A515BF0C12"
                + "61104F0E325041592E5359532E4444463031");
        disableDefaultProfileScript();
        start();
        String r = send(SELECT_PPSE);
        assertTrue(r.endsWith("9000"));

        List<String> aids = entryAids(Hex.hex(stripSw(r)));
        for (String a : aids) {
            assertFalse("fallback directory must not list the PPSE AID either",
                    a.equalsIgnoreCase(PPSE_NAME));
        }
    }

    @Test
    public void capturedDirectory_outerLengthOverruns_fallsBackToGenerated() {
        // 6F claims 0x7F (127) bytes of content but only ~74 actually follow -
        // the same truncation patchFci() already guards against for the FCI.
        putCapturedPpse("6F7F840E325041592E5359532E4444463031A53ABF0C37"
                + "61094F07A000000003101061094F07A000000003101161094F07A0000000031012"
                + "61094F07A000000003101361094F07A0000000031014");
        disableDefaultProfileScript();
        start();
        String r = send(SELECT_PPSE);
        assertTrue("a malformed capture must still answer 9000 with the generated "
                + "directory, not malfunction: " + r, r.endsWith("9000"));

        List<String> aids = entryAids(Hex.hex(stripSw(r)));
        assertTrue(aids.size() <= 3);
    }

    @Test
    public void capturedDirectory_wellFormedSingleEntry_isServedAsCaptured() {
        // A legitimate one-application capture must still be trusted verbatim -
        // the fix tightens validation, it does not stop honouring a good capture.
        String good = "6F20840E325041592E5359532E4444463031A50EBF0C0B"
                + "61094F07A0000000041010";
        putCapturedPpse(good);
        disableDefaultProfileScript();
        start();
        String r = send(SELECT_PPSE);
        assertEquals(good + "9000", r);
    }

    @Test
    public void selectAffffffffff1234_stillSucceedsAfterPpseSelect() {
        start();
        send(SELECT_PPSE);
        assertTrue(send(SELECT_AFFFFFFFFF1234).endsWith("9000"));
    }

    @Test
    public void selectA0000000041010_stillSucceedsAfterPpseSelect() {
        start();
        send(SELECT_PPSE);
        assertTrue(send(SELECT_A0000000041010).endsWith("9000"));
    }

    // ---- honest AID rejection: select() answers only what it actually is ----

    private void setProfile(String name) {
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("card0_profile", name).commit();
    }

    /**
     * Each profile's own default AID still selects clean once its canned
     * script is disarmed (disableDefaultProfileScript()) and select() itself
     * has to answer it - not a regression from the new rejection below.
     */
    @Test
    public void eachProfileAid_stillSelectsCleanThroughSelect() {
        disableDefaultProfileScript();
        setProfile("MASTERCARD");
        start();
        send(SELECT_PPSE);
        assertTrue(send(SELECT_A0000000041010).endsWith("9000"));

        disableDefaultProfileScript();
        setProfile("VISA");
        start();
        send(SELECT_PPSE);
        assertTrue(send("00A4040007A0000000031010").endsWith("9000"));

        disableDefaultProfileScript();
        setProfile("AMEX");
        start();
        send(SELECT_PPSE);
        assertTrue(send("00A4040006A00000002501").endsWith("9000"));
    }

    /**
     * JCB's AID is declared in apduservice.xml's own aid-group (so Android
     * routes it here at all), but no CardProfile answers for JCB - select()
     * must say so (6A82), not fabricate an FCI claiming to be a card this
     * app is not.
     */
    @Test
    public void unknownAid_jcb_isRejectedNotFabricated() {
        disableDefaultProfileScript();
        start();
        send(SELECT_PPSE);
        assertTrue(send("00A4040007A0000000651010").endsWith("6A82"));
    }

    // ---- F01: the synthetic GPO branch must clear ODA bits too ----

    /**
     * A typed/boxed AIP with SDA(0x40)/DDA(0x20)/Issuer Auth(0x04)/CDA(0x01)
     * all set must come back with all four cleared and CV(0x10)/TRM(0x08)
     * untouched - Emv.clearOda()'s mask is now 0x65, not 0x61, so this
     * branch and the captured-replay branch (gpo()'s line 2248) agree on
     * what "cleared" means. This engine has no cert chain, no CA key and no
     * way to get an ARPC, so claiming any of the four bought nothing but a
     * failed ODA attempt on a real terminal.
     */
    @Test
    public void syntheticGpo_clearsOdaBitsOnATypedAip_keepsCvAndTrm() {
        // 0x7D = 0111_1101: SDA/DDA/IssuerAuth/CDA (0x40/0x20/0x04/0x01) set,
        // plus CV/TRM (0x10/0x08) also set, so the test can tell "cleared"
        // from "never there in the first place".
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("card0_aip", "7D00").commit();
        disableDefaultProfileScript();
        start();
        send(SELECT_PPSE);
        send(SELECT_A0000000041010);

        String gpo = send("80A8000002830000");
        assertTrue("GPO must not refuse: " + gpo, gpo.endsWith("9000"));

        int at = gpo.indexOf("8202") + 4;
        String aip = gpo.substring(at, at + 4);
        int b1 = Integer.parseInt(aip.substring(0, 2), 16);

        assertEquals("SDA bit must be cleared", 0, b1 & 0x40);
        assertEquals("DDA bit must be cleared", 0, b1 & 0x20);
        assertEquals("Issuer Authentication bit must be cleared", 0, b1 & 0x04);
        assertEquals("CDA bit must be cleared", 0, b1 & 0x01);
        assertEquals("CV bit must survive", 0x10, b1 & 0x10);
        assertEquals("TRM bit must survive", 0x08, b1 & 0x08);
        assertEquals("0x1800 exactly", "1800", aip);
    }
}
