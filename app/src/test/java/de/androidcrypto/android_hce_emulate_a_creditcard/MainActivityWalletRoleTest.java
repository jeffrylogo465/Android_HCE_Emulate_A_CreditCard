package de.androidcrypto.android_hce_emulate_a_creditcard;

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
 * markWalletRoleAsked()'s ask-once gate, isolated from RoleManager and the
 * ActivityResultLauncher it feeds - see that method's own doc. The gate is
 * a plain prefs-flag read/write, so this calls it directly rather than
 * going through maybeRequestWalletRole()/RoleManager at all.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MainActivityWalletRoleTest {

    @Before
    public void setUp() {
        Prefs.reset(RuntimeEnvironment.getApplication());
    }

    @Test
    public void firstCallAsksAndMarksTheFlag_secondCallDoesNotAskAgain() {
        MainActivity activity = Robolectric.buildActivity(MainActivity.class).create().get();

        assertTrue("first call after a fresh install must ask", activity.markWalletRoleAsked());
        assertFalse("second call must not ask again", activity.markWalletRoleAsked());
        assertFalse("a third call still must not ask", activity.markWalletRoleAsked());
    }
}
