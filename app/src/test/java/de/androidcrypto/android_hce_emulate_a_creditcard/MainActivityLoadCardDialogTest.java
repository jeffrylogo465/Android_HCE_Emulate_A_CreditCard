package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.app.AlertDialog;
import android.os.Looper;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

/**
 * The "Load card" dialog - LoadedCard's only UI, deliberately kept off the
 * main screen (the asset-scheme spinner already earns that space). See
 * MainActivity.showLoadCardDialog()'s class doc.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MainActivityLoadCardDialogTest {

    // Same throwaway 1024-bit PKCS1 RSA key used by LoadedCardTest and
    // AssetCardEngineLoadedCardTest - a key that parses, not one tied to
    // the 9F46 bytes below.
    private static final String ICC_KEY_HEX =
            "3082025C02010002818100C29931DC752B8DE087F12EFCF99508635B590257A1548AE9E4DF3931C779554845"
            + "A6F2863E2442B6E47693E4F36714830B6F2A48A80EC15DF9C3C82BFF68BE235E966094DE12405709E90B2804"
            + "4B9B5D0C3257DFA717013D774AC8AB55407C9CE1C63B64A047F76D45EF2B7F4665C284079601D574FA16CE22F"
            + "7BB82090DAAEF020301000102818100BC063F8A2EE07D7E947B729656252CECAB87AE5EB37037A4D552E6357"
            + "5F28377886D4DEA6DC2A57F87F216E66254981A22832FCCF22D07A360C04DFA4D178C967A369820EBFCFE469B"
            + "3DC694F51FFE5B4013EE8FD4C53FC84F68377D2A61DF6C94BBEF3E80CD16FE736AF2216CCCCB679ACCA5C29F6"
            + "17D8B5CA0E163455B9E81024100EC65D28E93551D1B712FC4E754C5FD61F449FBEC23398D95EB2FF61CBB2F1"
            + "4833C917C8EC196AA467D61835658992F0D2C5D9A8E4E3ED16C6D75D08E686BF441024100D2BC11B837B4B0F"
            + "41B34DAB8628F5DC6D5B90A4291ECEACAE15A38B75655D9F784034A576556A8CC7D9A5954190B2F7D3804559B"
            + "1D6AA263DF0694BF475B132F0240743B3046D7DC0E7EB2AD391440D3445D483EA4361BAFAD94DBD96E19FC530"
            + "EB3E430E85C4C84E6DDD7C1FD509429654005E3541DCA0D0AED53F88C7DA88C03C1024002E26217B4637BBC8B"
            + "96C89B9775C0E1D4D1088BEAB5646D4C7250AE69B71919A32BEC5B8FDE84C6EFBD2A15D595EA9B7B25CC0A287"
            + "7EA2B15C56049D1EF342F02402A05A474247A801D314925437AA9CDFF6001A2144C3AAB15BE51CBFA89F681DA"
            + "24C904988C6FEAA0A9F874B609A93C53D7B77206424F495360660F9E8E614C45";

    private static final String GOOD_BLOCK =
            "5A=1234560012345608\n"
            + "5F24=291231\n"
            + "84=A0000000041010\n"
            + "8F=06\n"
            + "90=2008AABBCCDD\n"
            + "92=5FCEA152B4D9\n"
            + "9F46=18C47E974250014201\n"
            + "ICCKEY=" + ICC_KEY_HEX + "\n";

    private MainActivity activity;

    @Before
    public void setUp() {
        Prefs.reset(RuntimeEnvironment.getApplication());
        activity = Robolectric.buildActivity(MainActivity.class).create().start().resume().get();
        shadowOf(Looper.getMainLooper()).idle();
    }

    /** showLoadCardDialog() wires its buttons via setOnShowListener, which Robolectric posts. */
    private void openDialog() {
        activity.showLoadCardDialog();
        shadowOf(Looper.getMainLooper()).idle();
    }

    @Test
    public void badBlock_showsNamedMissingFieldsAndDoesNotPersist() {
        openDialog();
        activity.etLoadCardBlock.setText("8F=06\n"); // missing 90, 92, 9F46, ICCKEY

        activity.loadCardDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();

        String err = activity.tvLoadCardError.getText().toString();
        assertTrue("must name 90: " + err, err.contains("90"));
        assertTrue("must name 92: " + err, err.contains("92"));
        assertTrue("must name 9F46: " + err, err.contains("9F46"));
        assertTrue("must name ICCKEY: " + err, err.contains("ICCKEY"));

        assertNull("a refused block must not persist",
                LoadedCardStore.activeCard(RuntimeEnvironment.getApplication()));
    }

    @Test
    public void goodBlock_persistsAndSummaryShowsItsPan() {
        openDialog();
        activity.etLoadCardBlock.setText(GOOD_BLOCK);

        activity.loadCardDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();

        assertEquals("", activity.tvLoadCardError.getText().toString());

        LoadedCard stored = LoadedCardStore.activeCard(RuntimeEnvironment.getApplication());
        assertEquals("1234560012345608", stored.pan());

        String summary = activity.tvLoadCardSummary.getText().toString();
        assertTrue("summary must show the loaded PAN: " + summary, summary.contains("1234560012345608"));
        assertTrue("summary must show the loaded expiry: " + summary, summary.contains("291231"));
        assertTrue("summary must name the scheme (AID A0000000041010 is Mastercard): " + summary,
                summary.contains("MASTERCARD"));
    }

    @Test
    public void reopeningTheDialog_showsThePersistedSummary() throws Exception {
        LoadedCardStore.save(RuntimeEnvironment.getApplication(), GOOD_BLOCK);

        openDialog();

        String summary = activity.tvLoadCardSummary.getText().toString();
        assertTrue("reopening must show the already-loaded card: " + summary,
                summary.contains("1234560012345608"));
    }

    @Test
    public void clear_removesTheCardAndUpdatesTheSummary() throws Exception {
        LoadedCardStore.save(RuntimeEnvironment.getApplication(), GOOD_BLOCK);
        openDialog();

        activity.loadCardDialog.getButton(AlertDialog.BUTTON_NEUTRAL).performClick();

        assertNull(LoadedCardStore.activeCard(RuntimeEnvironment.getApplication()));
        assertTrue(activity.tvLoadCardSummary.getText().toString().contains("No card loaded"));
    }

    @Test
    public void noCardLoaded_dialogSaysSo() {
        openDialog();
        assertTrue(activity.tvLoadCardSummary.getText().toString().contains("No card loaded"));
    }
}
