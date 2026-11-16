package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.InputStream;

/**
 * A real card loaded on top of AssetCardEngineTest's own mrautio test card:
 * the loaded card's identity, chain and AFL/records win, and a chain tag it
 * does not declare never falls back to the shared profile.json chain once
 * any card is loaded. See AssetCardEngine's and LoadedCard's class docs.
 */
public class AssetCardEngineLoadedCardTest {

    private static final String PROFILE = AssetCardEngineTest.PROFILE;
    private static final String SELECT_AID = "00A4040007AFFFFFFFFF123400";
    private static final String GPO = "80A8000002830000";

    // Same throwaway 1024-bit PKCS1 RSA key as LoadedCardTest - a key that
    // parses, not one tied to the 9F46 bytes below; matching a real cert to
    // a real key is the operator's job pasting the block, not this test's.
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

    private AssetCardEngine eng;

    @Before
    public void setUp() throws Exception {
        try (InputStream in = new FileInputStream(PROFILE)) {
            eng = AssetCardEngine.load(in); // no ICC key - the loaded card supplies its own
        }
    }

    private String send(String apdu) {
        return Hex.toHex(eng.process(Hex.hex(apdu)));
    }

    @Test
    public void loadedCard_servesItsOwn8FCertsAndPan() {
        String block = "# a real card, pasted\n"
                + "5A=9999888877776666\n"
                + "5F24=291231\n"
                + "8F=07\n"
                + "90=AABBCCDD0011223344\n"
                + "92=1122334455\n"
                + "9F32=03\n"
                + "9F46=EEFF00112233445566\n"
                + "9F47=03\n"
                + "9F49=9F3704\n"
                + "82=1800\n"
                + "94=08010100\n"
                + "ICCKEY=" + ICC_KEY_HEX + "\n"
                + "REC 1:1=5A\n";
        eng.loadCard(LoadedCard.parse(block));

        // The shared profile's own identity/chain, still readable before
        // asking for anything the loaded card redeclared.
        assertEquals("0096", eng.tag("9F08"));

        send(SELECT_AID);
        assertEquals("770A82021800940408010100" + "9000", send(GPO));

        String rec = send("00B2010C00");
        assertTrue("record 1:1 must carry the loaded card's own PAN, not the test card's: " + rec,
                rec.contains("5A089999888877776666"));

        assertEquals("07", eng.tag("8F"));
        assertEquals("AABBCCDD0011223344", eng.tag("90"));
        assertEquals("1122334455", eng.tag("92"));
        assertEquals("EEFF00112233445566", eng.tag("9F46"));

        // Untouched by the loaded card: still the shared profile's own.
        assertEquals("0096", eng.tag("9F08"));
    }

    /**
     * 9F47 is a chain tag (LoadedCard.CHAIN_TAGS) but not one of the four
     * tags parse() hard-requires. A card that supplies the required four
     * and the ICC key, but not 9F47, must still not have 9F47 silently
     * served from the shared test chain - tag() must return null for it,
     * same as if it had never been asked for at all.
     */
    @Test
    public void loadedCard_missingAChainTag_neverFallsBackToTheSharedChain() {
        // Confirm the shared profile does have its own 9F47, so the
        // assertion below is about the override, not an absent tag.
        assertEquals("03", eng.tag("9F47"));

        String block = "# card missing 9F47\n"
                + "5A=9999888877776666\n"
                + "5F24=291231\n"
                + "8F=07\n"
                + "90=AABBCCDD0011223344\n"
                + "92=1122334455\n"
                + "9F46=EEFF00112233445566\n"
                + "ICCKEY=" + ICC_KEY_HEX + "\n";
        eng.loadCard(LoadedCard.parse(block));

        assertNull("9F47 must not fall back to the shared chain once a card is loaded",
                eng.tag("9F47"));
        // 9F08 is not a chain tag, so it is unaffected either way.
        assertEquals("0096", eng.tag("9F08"));
    }

    @Test
    public void clearLoadedCard_restoresTheSharedProfile() {
        String block = "5A=9999888877776666\n"
                + "5F24=291231\n"
                + "8F=07\n"
                + "90=AABBCCDD0011223344\n"
                + "92=1122334455\n"
                + "9F46=EEFF00112233445566\n"
                + "ICCKEY=" + ICC_KEY_HEX + "\n";
        eng.loadCard(LoadedCard.parse(block));
        assertEquals("07", eng.tag("8F"));

        eng.clearLoadedCard();
        assertEquals("92", eng.tag("8F"));
    }
}
