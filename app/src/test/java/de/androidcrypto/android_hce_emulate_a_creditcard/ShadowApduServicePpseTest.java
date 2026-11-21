package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
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
        // F02: gpo() now also ORs in Emv.AIP_CDCVM unconditionally in the
        // non-MSD case, so 0x18's survivors pick up 0x02 too - see F02's own
        // test just below for that bit in isolation.
        assertEquals("0x1A00 - 0x18 survivors plus F02's CDCVM bit", "1A00", aip);
    }

    /**
     * F02. The typed AIP has every ODA bit set and CDCVM clear, same shape
     * as the test above - clearOda() must still clear the four ODA bits
     * (its mask, ~0x65, does not even cover 0x02), and separately gpo()
     * must now OR in Emv.AIP_CDCVM. Both are checked on the SAME served
     * byte so one cannot mask a regression in the other. The READ RECORD
     * that follows checks the served CVMLIST is the new CDCVM-first list,
     * not the old signature-bearing one.
     */
    @Test
    public void syntheticGpo_setsCdcvmBit_andServesTheCdcvmFirstCvmList() {
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

        assertEquals("SDA bit must still be cleared", 0, b1 & 0x40);
        assertEquals("DDA bit must still be cleared", 0, b1 & 0x20);
        assertEquals("Issuer Authentication bit must still be cleared", 0, b1 & 0x04);
        assertEquals("CDA bit must still be cleared", 0, b1 & 0x01);
        assertEquals("CDCVM bit must be set", Emv.AIP_CDCVM, b1 & Emv.AIP_CDCVM);
        assertEquals("0x1A00 exactly - 0x18 survivors plus CDCVM", "1A00", aip);

        String rec = send("00B2010C00");
        int rAt = rec.indexOf("8E0C") + 4;
        String list = rec.substring(rAt, rAt + 24);
        assertEquals("00000000000000005E071F03", list);
    }

    /**
     * F02, the captured-replay branch's half of the same fix: a captured
     * GPO (card0_cap_rawgpo) with CDCVM clear must come back with it set,
     * through the same Emv.setCdcvm() the synthetic branch above now also
     * calls - one behaviour for both paths, the same argument F01 already
     * established for clearOda().
     */
    @Test
    public void capturedGpoReplay_setsCdcvmBitToo() {
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("card0_cap_rawgpo", "770F82027D009404080101009F36020001").commit();
        disableDefaultProfileScript();
        start();
        send(SELECT_PPSE);
        send(SELECT_A0000000041010);

        String gpo = send("80A8000002830000");
        assertTrue("GPO must not refuse: " + gpo, gpo.endsWith("9000"));

        int at = gpo.indexOf("8202") + 4;
        String aip = gpo.substring(at, at + 4);
        int b1 = Integer.parseInt(aip.substring(0, 2), 16);

        assertEquals("SDA bit must still be cleared", 0, b1 & 0x40);
        assertEquals("DDA bit must still be cleared", 0, b1 & 0x20);
        assertEquals("CDA bit must still be cleared", 0, b1 & 0x01);
        assertEquals("CDCVM bit must be set", Emv.AIP_CDCVM, b1 & Emv.AIP_CDCVM);
        assertEquals("0x1A00 - 0x18 survivors plus the CDCVM bit", "1A00", aip);
    }

    // ---- term-new6.log fix: the scripted Mastercard GPO is built, not replayed ----

    /**
     * A real Mastercard contactless kernel reads the AIP right after GPO and,
     * with every ODA bit clear, judged this card offered no CAM at all and
     * ended the tap there - before a single READ RECORD (term-new6.log).
     * The default profile script's canned GPO line for Mastercard's shape
     * (format 2, no AC yet) is no longer served verbatim:
     * mastercardGpoFromCard() builds 82/94 fresh instead, and this is
     * what a terminal receives with the default script still armed - no
     * disableDefaultProfileScript() here, unlike the synthetic-branch tests
     * above.
     *
     * SDA IS NO LONGER CLAIMED. Claiming it (AIP_MC 5840) got a real kernel
     * past the no-CAM stop above and, once 9F38 reached the FCI, into a
     * PDOL-driven GPO - but every tap since (term-new9.log, term-new10.log)
     * still stalled at the same place, GPO answered 9000 and no READ RECORD
     * followed. Profiles.AIP_MC is back to 1800 (no ODA bit at all, byte 2
     * clear) to isolate whether the unbacked SDA claim is itself what a
     * later check now rejects, now that the PDOL round trip is not the
     * blocker. clearOdaKeepSda()/setCdcvm() still run on top of that, so
     * the served byte 1 is CV + TRM + CDCVM (0x1A), not the bare 0x18.
     *
     * 94 (AFL) is the plain one-entry SFI-1-record-1 shape too -
     * AFL_MC_PROBE_WITH_AID dropped its non-spec appended-AID-list tail for
     * the same reason: no tap ever showed a kernel reading past the first
     * 4 bytes, so the probe bought nothing and is gone.
     *
     * 9F6B IS back in this GPO. 7a74a93 added it, 0ad3dea dropped it when
     * byte 2 went to 0x40 ("MSD track 2 equivalent, has no business in an
     * EMV-mode response"), then 5be6324 added 9F38 - so no tap has ever
     * carried 9F6B and 9F38 together. That reasoning is reopened: kernel 2
     * lists 9F6B in the GPO response for both modes, and real M/Chip cards
     * carry it regardless. Restored, sourced the same way 7a74a93 built it
     * (msdRecord()'s 9F6B, then its 57, then a synthesized track2()).
     */
    @Test
    public void scriptedMastercardGpo_isBuiltFromTheCard_notReplayed() {
        setProfile("MASTERCARD");
        start();
        send(SELECT_PPSE);
        send(SELECT_A0000000041010);

        String gpo = send("80A8000002830000");
        assertTrue("GPO must not refuse: " + gpo, gpo.endsWith("9000"));

        byte[] body = Hex.hex(gpo.substring(0, gpo.length() - 4));
        assertNotNull("82 (AIP) missing", Emv.findTag(body, 0x82));
        assertNotNull("94 (AFL) missing", Emv.findTag(body, 0x94));
        assertNotNull("9F6B (track 2 equivalent) must be served - kernel 2 expects it in both modes",
                Emv.findTag(body, 0x9F6B));

        byte[] aip = Emv.findTag(body, 0x82);
        int b1 = aip[0] & 0xFF;
        assertEquals("SDA bit (0x40) must not be claimed", 0, b1 & 0x40);
        assertEquals("DDA bit (0x20) must stay clear", 0, b1 & 0x20);
        assertEquals("CDA bit (0x01) must stay clear", 0, b1 & 0x01);
        assertEquals("CDCVM bit must be set", Emv.AIP_CDCVM, b1 & Emv.AIP_CDCVM);
        assertEquals("0x1A - 0x18 survivors plus the CDCVM bit", 0x1A, b1);

        int b2 = aip[1] & 0xFF;
        assertEquals("byte 2 must be exactly 0x00 - no mag-stripe, no EMV-mode claim",
                0x00, b2);

        byte[] afl = Emv.findTag(body, 0x94);
        assertEquals("AFL must be the plain one-entry shape, no appended AID tail",
                "08010100", Hex.toHex(afl));
    }

    /**
     * mastercardGpoFromCard() now honours a typed "aip" box the same way the
     * synthetic/boxed-AIP branch in gpo() does, instead of always building
     * from Profiles.aipMc(). The box value (0x7D00: every ODA bit plus
     * CV/TRM set) is chosen to distinguish this method's own mask from
     * clearOda()'s: clearOdaKeepSda() clears DDA/IssuerAuth/CDA (0x25) but
     * leaves SDA (0x40) alone, so 0x7D survives as 0x58, and setCdcvm() then
     * ORs in 0x02 - 0x5A, not the 0x1A the un-boxed default serves.
     */
    @Test
    public void scriptedMastercardGpo_honoursATypedAipBox() {
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("card0_aip", "7D00").commit();
        setProfile("MASTERCARD");
        start();
        send(SELECT_PPSE);
        send(SELECT_A0000000041010);

        String gpo = send("80A8000002830000");
        assertTrue("GPO must not refuse: " + gpo, gpo.endsWith("9000"));

        byte[] body = Hex.hex(gpo.substring(0, gpo.length() - 4));
        byte[] aip = Emv.findTag(body, 0x82);
        int b1 = aip[0] & 0xFF;

        assertEquals("SDA bit (0x40) must survive - this mask keeps it", 0x40, b1 & 0x40);
        assertEquals("DDA bit (0x20) must be cleared", 0, b1 & 0x20);
        assertEquals("Issuer Authentication bit (0x04) must be cleared", 0, b1 & 0x04);
        assertEquals("CDA bit (0x01) must be cleared", 0, b1 & 0x01);
        assertEquals("CDCVM bit must be set", Emv.AIP_CDCVM, b1 & Emv.AIP_CDCVM);
        assertEquals("0x5A - 0x7D's survivors plus the CDCVM bit", 0x5A, b1);

        int b2 = aip[1] & 0xFF;
        assertEquals("byte 2 comes from the box too, unmasked", 0x00, b2);
    }
}
