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

/**
 * The asset card (profile.json) served through the real service. Off by default,
 * so ShadowApduServiceDispatchTest is untouched; switched on by one pref.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class ShadowApduServiceAssetCardTest {

    private static final String SELECT_PPSE = "00A404000E325041592E5359532E444446303100";
    private static final String SELECT_AID = "00A4040007AFFFFFFFFF123400";
    private static final String GPO = "80A8000002830000";
    private static final String GENAC = "80AE80001D"
            + "00000000100000000000000008400000000000084026111200" + "12345678" + "00";

    private static final String GENAC2 = "80AE40001F5A33"
            + "00000000100000000000000008400000000000084026111200" + "12345678" + "00";

    private ShadowApduService svc;

    private void start(boolean assetCard) {
        Prefs.reset(RuntimeEnvironment.getApplication());
        if (assetCard) {
            Prefs.get(RuntimeEnvironment.getApplication()).edit()
                    .putString("asset_profile", "1").commit();
        }
        svc = Robolectric.buildService(ShadowApduService.class).create().get();
    }

    private String send(String apdu) {
        return Hex.toHex(svc.processCommandApdu(Hex.hex(apdu), null));
    }

    @Test
    public void flag_off_ppseStillListsTheConfiguredAid() {
        start(false);
        assertTrue(send(SELECT_PPSE).contains("A0000000031010"));
    }

    /**
     * No real terminal kernel recognises AFFFFFFFFF1234. A real tap reads the
     * directory, finds only that fictional AID, and never selects anything -
     * the "quit after one SELECT" tap. buildAssetPpse() fixes this by adding
     * a second, real entry (Mastercard) with a correctly-lengthed label, so
     * the directory is never a dead end.
     */
    @Test
    public void flag_on_ppseAdvertisesARealAidWithAValidLabelLength() {
        start(true);
        String r = send(SELECT_PPSE);
        assertTrue("must still carry the test card's own entry: " + r,
                r.contains("4F07AFFFFFFFFF1234"));
        assertTrue("must also offer a real, servable AID: " + r,
                r.contains("4F07A0000000041010"));
        // 50 0A "MASTERCARD" (10 ASCII bytes) - the length byte matches the text.
        assertTrue("the Mastercard entry's 50 label length must match its text: " + r,
                r.contains("500A4D415354455243415244"));
        assertTrue(r.endsWith("9000"));
    }

    /**
     * select() for the real fallback AID must bind AssetCardEngine as the
     * current card - via selectAs(), not its own select() which 6A82's
     * anything that isn't AFFFFFFFFF1234 - and hand back the profile's real
     * FCI (A5 untouched) with only the DF name in tag 84 rewritten to the
     * AID actually requested.
     *
     * Falling through to the ordinary profile select() instead (the old
     * behaviour) produced a structurally fine but synthetic FCI that never
     * flipped AssetCardEngine's own `selected` flag, so the GPO that
     * followed answered 6985 - see the next test.
     */
    @Test
    public void flag_on_selectA0000000041010_returnsTheProfileFci() {
        start(true);
        send(SELECT_PPSE);
        String r = send("00A4040007A0000000041010");
        assertTrue("fallback AID must get a real FCI, not AssetCardEngine's 6A82: " + r,
                r.startsWith("6F") && r.contains("8407A0000000041010"));
        assertTrue(r.endsWith("9000"));
    }

    /**
     * The GPO that follows a fallback-AID select must bind, not 6985: the
     * terminal gets the profile's real AIP/AFL (same values the test-AID
     * path serves) and the AFL's records are readable afterward.
     */
    @Test
    public void flag_on_selectA0000000041010_thenGpo_bindsAndRecordsAreReadable() {
        start(true);
        send(SELECT_PPSE);
        send("00A4040007A0000000041010");
        String gpoResp = send(GPO);
        assertEquals("GPO after the fallback select must return the profile's "
                        + "real AIP and AFL, not 6985",
                "7712" + "82021C00" + "940C080202001001020018010201" + "9000",
                gpoResp);
        String recResp = send("00B2020C00");
        assertTrue("the AFL's records must be readable once GPO has bound: " + recResp,
                recResp.endsWith("9000"));
    }

    /**
     * A terminal that gives up on AFFFFFFFFF1234 commonly falls back to a
     * well-known brand AID, including this 8-byte Amex one. It must not be
     * answered with 6A82.
     */
    @Test
    public void flag_on_selectA0000000250100_doesNotFail() {
        start(true);
        send(SELECT_PPSE);
        String r = send("00A4040007A0000000250100");
        assertFalse("fallback AID must not be rejected with 6A82: " + r, r.endsWith("6A82"));
        assertTrue(r.endsWith("9000"));
    }

    @Test
    public void flag_on_servesTheFullFlowWithAComputedCryptogram() {
        start(true);
        assertTrue(send(SELECT_PPSE).contains("4F07AFFFFFFFFF1234"));
        assertTrue(send(SELECT_AID).startsWith("6F398407AFFFFFFFFF1234"));
        assertEquals("7712" + "82021C00" + "940C080202001001020018010201" + "9000", send(GPO));
        assertTrue(send("00B2020C00").endsWith("9000"));
        assertEquals("771E9F2701809F360200F1" + "9F26084ED915D20AC28174" + "9F100706011203A4A0029000",
                send(GENAC));
    }

    @Test
    public void flag_on_atcSurvivesANewServiceInstance() {
        start(true);
        send(SELECT_AID);
        send(GPO);
        send(GENAC);

        // A second tap on a fresh service object, same preferences.
        svc = Robolectric.buildService(ShadowApduService.class).create().get();
        send(SELECT_AID);
        send(GPO);
        assertEquals("771E9F2701809F360200F2" + "9F260830E9D37ED4F1E27D" + "9F100706011203A4A0029000",
                send(GENAC));
    }

    @Test
    public void flag_on_secondAcThenThirdIsRefused() {
        start(true);
        send(SELECT_AID);
        send(GPO);
        send(GENAC);
        assertEquals("771E9F2701809F360200F1" + "9F2608463C0F076491C0E1" + "9F100706011203A4A0029000",
                send(GENAC2));
        assertEquals("6985", send(GENAC2));
    }

    /**
     * The asset card answers from its own engine, before the SELECT/GPO/
     * GENERATE AC counters that baseVerdict() reads were ever incremented -
     * every asset-card tap, including a complete one, used to report "terminal
     * read the directory and quit after one SELECT" regardless of how far the
     * terminal actually got. A tap that walks PPSE through GENERATE AC must not
     * be misdiagnosed as having died at the directory.
     */
    @Test
    public void flag_on_fullFlow_verdictDoesNotMisreportAFirstSelectDeath() {
        start(true);
        send(SELECT_PPSE);
        send(SELECT_AID);
        send(GPO);
        send("00B2020C00");
        send(GENAC);

        svc.onDeactivated(0);
        String verdict = Prefs.get(RuntimeEnvironment.getApplication())
                .getString("lastverdict", "");
        assertFalse("a tap that reached GENERATE AC must not be reported as having "
                        + "quit after the PPSE SELECT: " + verdict,
                verdict.contains("quit after one SELECT"));
    }

    /**
     * nGpos counts the attempt, not the outcome: a GPO the card refuses still
     * bumps it, and baseVerdict() used to read nGpos alone and then assume
     * success - so a refused GPO (the fallback-select bug served exactly
     * this: 6985, see the two fallback tests above) was reported as "the
     * terminal took the GPO response and read NO records", which blames the
     * terminal for something the card's own refusal caused. ATC exhaustion
     * is used here only because it is a public, reflection-free way to make
     * AssetCardEngine's own gpo() answer 6985.
     */
    @Test
    public void flag_on_gpoRefused_verdictNamesTheStatusWordNotNoRecords() {
        start(true);
        Prefs.get(RuntimeEnvironment.getApplication()).edit()
                .putString("asset_atc", "FFFF").commit();

        send(SELECT_PPSE);
        send(SELECT_AID);
        String gpoResp = send(GPO);
        assertEquals("6985", gpoResp);

        svc.onDeactivated(0);
        String verdict = Prefs.get(RuntimeEnvironment.getApplication())
                .getString("lastverdict", "");
        assertTrue("must name the real GPO status word: " + verdict, verdict.contains("6985"));
        assertFalse("must not claim records were read when the GPO itself was refused: "
                        + verdict,
                verdict.contains("read NO records"));
    }
}
