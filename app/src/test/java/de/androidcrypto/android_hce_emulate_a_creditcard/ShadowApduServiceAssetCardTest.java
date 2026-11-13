package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
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

    @Test
    public void flag_on_servesTheFullFlowWithAComputedCryptogram() {
        start(true);
        assertTrue(send(SELECT_PPSE).contains("4F07AFFFFFFFFF1234"));
        assertTrue(send(SELECT_AID).startsWith("6F398407AFFFFFFFFF1234"));
        assertEquals("800E3C00080202001001020018010201" + "9000", send(GPO));
        assertTrue(send("00B2020C00").endsWith("9000"));
        assertEquals("771E9F2701809F360200F1" + "9F2608FBE724C147ACDF75" + "9F100706011203A4A0029000",
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
        assertEquals("771E9F2701809F360200F2" + "9F26082D1F49E3E6EA0F85" + "9F100706011203A4A0029000",
                send(GENAC));
    }
}
