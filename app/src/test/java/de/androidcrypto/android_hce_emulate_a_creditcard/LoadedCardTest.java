package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.math.BigInteger;

/**
 * LoadedCard.parse(): the block format, validation, and the cascade
 * primitives (tag()/record()) AssetCardEngine builds the "never fall back
 * past a loaded card" rule on top of. See AssetCardEngine's and
 * LoadedCard's class docs for the format and the chain-tags rule.
 */
public class LoadedCardTest {

    // A throwaway 1024-bit RSA key, PKCS1 DER, not tied to any cert below -
    // LoadedCard.parse() only needs a key that PARSES, matching it to 9F46
    // is the asset-loading operator's job, not this parser's.
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

    private static final BigInteger ICC_MODULUS = new BigInteger(1, Hex.hex(
            "C29931DC752B8DE087F12EFCF99508635B590257A1548AE9E4DF3931C779554845A6F2863E2442B6E47693E4"
            + "F36714830B6F2A48A80EC15DF9C3C82BFF68BE235E966094DE12405709E90B28044B9B5D0C3257DFA717013D"
            + "774AC8AB55407C9CE1C63B64A047F76D45EF2B7F4665C284079601D574FA16CE22F7BB82090DAAEF"));

    private static String goodBlock() {
        return "# a synthetic real card\n"
                + "5A=1414141400001234\n"
                + "57=1414141400001234D29123011234567890120F\n"
                + "5F24=291231\n"
                + "5F34=01\n"
                + "84=A0000000041010\n"
                + "8F=06\n"
                + "90=2008AABBCCDDEEFF\n"
                + "92=5FCEA152B4D9EC97\n"
                + "9F32=03\n"
                + "9F46=18C47E9742500142A530DCC683431982\n"
                + "9F47=03\n"
                + "9F49=9F3704\n"
                + "94=08010100\n"
                + "82=5800\n"
                + "ICCKEY=" + ICC_KEY_HEX + "\n"
                + "ACKEY=0123456789ABCDEFFEDCBA9876543210\n"
                + "REC 1:1=5A,5F24,5F34\n"
                + "REC 3:1=90,92,9F32\n"
                + "REC 3:2=9F46,9F47,9F49\n";
    }

    @Test
    public void goodCard_servesItsOwnChainAndPan() {
        LoadedCard c = LoadedCard.parse(goodBlock());

        assertEquals("06", c.tag("8F"));
        assertEquals("06", c.tag("8f")); // tag lookup is case-insensitive
        assertEquals("18C47E9742500142A530DCC683431982", c.tag("9F46"));
        assertEquals("2008AABBCCDDEEFF", c.tag("90"));
        assertEquals("5FCEA152B4D9EC97", c.tag("92"));
        assertEquals("1414141400001234", c.tag("5A"));
        assertEquals("A0000000041010", c.tag("84"));

        assertArrayEquals(new String[]{"5A", "5F24", "5F34"}, c.record("1:1"));
        assertArrayEquals(new String[]{"9F46", "9F47", "9F49"}, c.record("3:2"));
        assertNull("a record this card never declared", c.record("2:1"));
        assertNull("a tag this card never declared", c.tag("9F08"));

        assertEquals(ICC_MODULUS, c.iccModulus());
        assertEquals("0123456789ABCDEFFEDCBA9876543210", c.acKey());
        assertTrue("a complete chain must carry no warnings: " + c.warnings(), c.warnings().isEmpty());
    }

    @Test
    public void acKeyIsOptional() {
        LoadedCard c = LoadedCard.parse(goodBlock().replace("ACKEY=0123456789ABCDEFFEDCBA9876543210\n", ""));
        assertNull(c.acKey());
    }

    /**
     * 9F46 (and 8F/90/92/ICCKEY) used to be refused outright. Split
     * validation downgrades these to warnings: PAN and expiry are present,
     * so this card still loads - it simply cannot answer INTERNAL
     * AUTHENTICATE or carry 9F46 in a record once bound, which already
     * fails loud elsewhere (AssetCardEngine.tag()'s chain-tag block), not
     * here.
     */
    @Test
    public void missing9F46_loadsWithAWarningNotARefusal() {
        String block = goodBlock().replace("9F46=18C47E9742500142A530DCC683431982\n", "");
        LoadedCard c = LoadedCard.parse(block);
        assertNull("no fallback to some other value - simply absent", c.tag("9F46"));
        assertTrue("must warn about 9F46: " + c.warnings(), c.warnings().contains("9F46"));
    }

    @Test
    public void missingIccKey_loadsWithAWarningAndNoIccKey() {
        String block = goodBlock().replaceAll("(?m)^ICCKEY=.*\\n", "");
        LoadedCard c = LoadedCard.parse(block);
        assertNull(c.iccModulus());
        assertNull(c.iccPrivateExponent());
        assertTrue("must warn about ICCKEY: " + c.warnings(), c.warnings().contains("ICCKEY"));
    }

    @Test
    public void multipleMissingChainFields_allWarnedTogether() {
        String block = goodBlock()
                .replace("8F=06\n", "")
                .replaceAll("(?m)^ICCKEY=.*\\n", "");
        LoadedCard c = LoadedCard.parse(block);
        assertTrue(c.warnings().toString(), c.warnings().contains("8F"));
        assertTrue(c.warnings().toString(), c.warnings().contains("ICCKEY"));
    }

    /**
     * The task's own test: a bare track 2 loads and yields the right
     * 5A/5F24/57/5F34. PAN 1234560012345608, expiry 2912 (YYMM), service
     * code 201, no discretionary data.
     */
    @Test
    public void bareTrack2_yieldsTheRightDerivedTags() {
        LoadedCard c = LoadedCard.parse("1234560012345608=2912201\n");

        assertEquals("1234560012345608", c.tag("5A"));
        assertEquals("1234560012345608", c.pan());
        assertEquals("291231", c.tag("5F24")); // YYMM + a defaulted day of 31
        assertEquals("291231", c.expiry());
        assertEquals("01", c.tag("5F34"));
        assertEquals("1234560012345608D2912201", c.tag("57")); // PAN, D, YYMM, SVC

        // No chain, no key - this is the common dump shape, so it is a
        // warning on an otherwise-loaded card, not a refusal.
        assertTrue(c.warnings().contains("8F"));
        assertTrue(c.warnings().contains("90"));
        assertTrue(c.warnings().contains("92"));
        assertTrue(c.warnings().contains("9F46"));
        assertTrue(c.warnings().contains("ICCKEY"));
    }

    /** A PAN with an odd digit count pads 5A with a trailing F, same as any other BCD field. */
    @Test
    public void bareTrack2_oddLengthPan_padsWithF() {
        LoadedCard c = LoadedCard.parse("123456001234560=2912311\n");
        assertEquals("123456001234560F", c.tag("5A"));
        assertEquals("123456001234560", c.pan());
    }

    /** A later explicit tag line overrides what the bare track 2 derived, simple top-to-bottom order. */
    @Test
    public void explicitTagAfterBareTrack2_overridesTheDerivedValue() {
        LoadedCard c = LoadedCard.parse(
                "1234560012345608=2912201\n"
                        + "5F24=301130\n");
        assertEquals("301130", c.tag("5F24"));
    }

    /** The task's own test: a block with no PAN is refused. */
    @Test
    public void noPan_refused() {
        try {
            LoadedCard.parse("8F=06\n90=AABB\n92=CCDD\n9F46=EEFF\n");
            fail("a card with no PAN must be refused");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("PAN"));
            assertTrue(e.getMessage(), e.getMessage().contains("5A"));
        }
    }

    @Test
    public void noExpiry_refused() {
        try {
            LoadedCard.parse("5A=1234560012345608\n");
            fail("a card with no expiry must be refused");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("expiry"));
            assertTrue(e.getMessage(), e.getMessage().contains("5F24"));
        }
    }

    @Test
    public void isChainTag_coversTheWholeChainAndNothingElse() {
        for (String t : new String[]{"8F", "90", "92", "9F32", "9F46", "9F47", "9F49"}) {
            assertTrue(t, LoadedCard.isChainTag(t));
            assertTrue(t + " lowercase", LoadedCard.isChainTag(t.toLowerCase(java.util.Locale.ROOT)));
        }
        for (String t : new String[]{"82", "94", "8E", "5A", "84"}) {
            assertTrue(t + " must not be a chain tag", !LoadedCard.isChainTag(t));
        }
    }

    @Test
    public void badHexValue_throwsRatherThanServingItLater() {
        String block = goodBlock().replace("5A=1414141400001234\n", "5A=NOTHEX\n");
        try {
            LoadedCard.parse(block);
            fail("bad hex must be refused at parse time");
        } catch (IllegalArgumentException e) {
            // expected - message content is not load-bearing here
        }
    }
}
