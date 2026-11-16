package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.robolectric.Shadows.shadowOf;

import android.os.Looper;
import android.widget.Spinner;
import android.widget.TextView;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

/**
 * The asset_scheme pref used to be exactly as unreachable as asset_profile
 * once was: nothing wrote it, so the Mastercard default could never be
 * changed from the app. The spinner next to the test-card toggle fixes
 * that - it has to be visible on the main screen, not behind showKeyTools().
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MainActivityAssetSchemeTest {

    @Before
    public void setUp() {
        Prefs.reset(RuntimeEnvironment.getApplication());
    }

    private MainActivity create() {
        MainActivity a = Robolectric.buildActivity(MainActivity.class).create().start().resume().get();
        shadowOf(Looper.getMainLooper()).idle();
        return a;
    }

    /**
     * Nothing has ever chosen a scheme yet, so the pref itself stays unset -
     * same as ShadowApduService.advertisedAssetScheme()'s own unset-pref
     * default. Only the spinner and its label show Mastercard.
     */
    @Test
    public void defaultsToMastercardWithNothingSet() {
        MainActivity a = create();
        Spinner spn = a.findViewById(R.id.spnAssetScheme);
        TextView lbl = a.findViewById(R.id.txtAssetScheme);

        assertEquals("MASTERCARD", spn.getSelectedItem());
        assertEquals("advertising: MASTERCARD", lbl.getText().toString());
    }

    @Test
    public void pickingVisa_writesThePrefAndUpdatesTheLabel() {
        MainActivity a = create();
        Spinner spn = a.findViewById(R.id.spnAssetScheme);
        TextView lbl = a.findViewById(R.id.txtAssetScheme);

        spn.setSelection(AssetSchemeProfile.VISA.ordinal());
        shadowOf(Looper.getMainLooper()).idle();

        assertEquals("VISA",
                Prefs.get(RuntimeEnvironment.getApplication()).getString("asset_scheme", ""));
        assertEquals("advertising: VISA", lbl.getText().toString());
    }

    @Test
    public void pickingAmex_survivesAReopen() {
        MainActivity first = create();
        Spinner spn1 = first.findViewById(R.id.spnAssetScheme);
        spn1.setSelection(AssetSchemeProfile.AMEX.ordinal());
        shadowOf(Looper.getMainLooper()).idle();

        MainActivity second = create();

        Spinner spn2 = second.findViewById(R.id.spnAssetScheme);
        TextView lbl2 = second.findViewById(R.id.txtAssetScheme);

        assertEquals("AMEX", spn2.getSelectedItem());
        assertEquals("advertising: AMEX", lbl2.getText().toString());
        assertEquals("AMEX",
                Prefs.get(RuntimeEnvironment.getApplication()).getString("asset_scheme", ""));
    }
}
