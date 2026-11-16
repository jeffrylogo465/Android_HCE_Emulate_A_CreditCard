package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

/**
 * The internal file LoadedCardStore keeps a pasted card in, separate from
 * the encrypted Prefs store - see its class doc.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class LoadedCardStoreTest {

    private static final String GOOD =
            "8F=06\n90=AABB\n92=CCDD\n9F46=EEFF\n"
            + "ICCKEY=3082025C02010002818100C29931DC752B8DE087F12EFCF99508635B590257A1548AE9E4DF3931"
            + "C779554845A6F2863E2442B6E47693E4F36714830B6F2A48A80EC15DF9C3C82BFF68BE235E966094DE12405"
            + "709E90B28044B9B5D0C3257DFA717013D774AC8AB55407C9CE1C63B64A047F76D45EF2B7F4665C284079601"
            + "D574FA16CE22F7BB82090DAAEF020301000102818100BC063F8A2EE07D7E947B729656252CECAB87AE5EB3"
            + "7037A4D552E63575F28377886D4DEA6DC2A57F87F216E66254981A22832FCCF22D07A360C04DFA4D178C96"
            + "7A369820EBFCFE469B3DC694F51FFE5B4013EE8FD4C53FC84F68377D2A61DF6C94BBEF3E80CD16FE736AF22"
            + "16CCCCB679ACCA5C29F617D8B5CA0E163455B9E81024100EC65D28E93551D1B712FC4E754C5FD61F449FBE"
            + "C23398D95EB2FF61CBB2F14833C917C8EC196AA467D61835658992F0D2C5D9A8E4E3ED16C6D75D08E686BF"
            + "441024100D2BC11B837B4B0F41B34DAB8628F5DC6D5B90A4291ECEACAE15A38B75655D9F784034A576556A"
            + "8CC7D9A5954190B2F7D3804559B1D6AA263DF0694BF475B132F0240743B3046D7DC0E7EB2AD391440D3445"
            + "D483EA4361BAFAD94DBD96E19FC530EB3E430E85C4C84E6DDD7C1FD509429654005E3541DCA0D0AED53F88"
            + "C7DA88C03C1024002E26217B4637BBC8B96C89B9775C0E1D4D1088BEAB5646D4C7250AE69B71919A32BEC5"
            + "B8FDE84C6EFBD2A15D595EA9B7B25CC0A2877EA2B15C56049D1EF342F02402A05A474247A801D314925437"
            + "AA9CDFF6001A2144C3AAB15BE51CBFA89F681DA24C904988C6FEAA0A9F874B609A93C53D7B77206424F495"
            + "360660F9E8E614C45\n";

    @Test
    public void noCardStored_activeCardIsNull() {
        assertNull(LoadedCardStore.activeCard(RuntimeEnvironment.getApplication()));
    }

    @Test
    public void save_thenActiveCard_readsItBack() throws Exception {
        LoadedCardStore.save(RuntimeEnvironment.getApplication(), GOOD);
        LoadedCard c = LoadedCardStore.activeCard(RuntimeEnvironment.getApplication());
        assertEquals("06", c.tag("8F"));
        assertEquals("EEFF", c.tag("9F46"));
    }

    @Test
    public void badBlock_refusedAndNeverWritten() throws Exception {
        LoadedCardStore.save(RuntimeEnvironment.getApplication(), GOOD);

        try {
            LoadedCardStore.save(RuntimeEnvironment.getApplication(), "8F=06\n"); // missing 90/92/9F46/ICCKEY
            fail("a bad block must be refused");
        } catch (IllegalArgumentException expected) {
            // expected
        }

        LoadedCard still = LoadedCardStore.activeCard(RuntimeEnvironment.getApplication());
        assertTrue("the earlier good card must still be the one stored",
                "06".equals(still.tag("8F")) && "EEFF".equals(still.tag("9F46")));
    }

    @Test
    public void clear_removesTheStoredCard() throws Exception {
        LoadedCardStore.save(RuntimeEnvironment.getApplication(), GOOD);
        LoadedCardStore.clear(RuntimeEnvironment.getApplication());
        assertNull(LoadedCardStore.activeCard(RuntimeEnvironment.getApplication()));
    }
}
