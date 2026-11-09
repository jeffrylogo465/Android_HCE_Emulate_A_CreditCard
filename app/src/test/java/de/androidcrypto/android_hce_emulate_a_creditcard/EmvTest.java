package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Emv tests that the old EmvTest.java never contained.
 *
 * That file was a verbatim copy of Emv.java: same class name, same package, no
 * @Test methods. It shadowed the shipped class on the test classpath while
 * contributing nothing, so the suite ran against a stale duplicate and the test
 * names cited in Emv.decideCid's javadoc had no implementation anywhere.
 *
 * Everything here runs in plain JUnit - Emv touches no Android type, which is
 * the whole reason it exists as a separate class.
 */
public class EmvTest {

    // ---------------------------------------------------------------- clearOda

    /**
     * Format 1: the payload is two raw AIP bytes then the AFL, not a TLV walk.
     *
     * 0x58 is Visa qVSDC + CV + TRM. 0x40 is simultaneously the SDA bit, so it
     * has to go: a clone has no certificate to authenticate against.
     */
    @Test
    public void clearOdaStripsFormat1Aip() {
        byte[] tpl = Emv.hex("8006580008010100");
        Emv.clearOda(tpl);
        assertEquals(0x18, tpl[2] & 0xFF);
        // The AFL behind it is untouched - this must not become a TLV walk.
        assertArrayEquals(Emv.hex("08010100"), Arrays.copyOfRange(tpl, 4, tpl.length));
    }

    /** Format 2: a real template, so the 82 is found and cleared in place. */
    @Test
    public void clearOdaStripsFormat2Aip() {
        byte[] tpl = Emv.hex("770A82025800940408010100");
        Emv.clearOda(tpl);
        byte[] aip = Emv.findTag(tpl, 0x82);
        assertNotNull(aip);
        assertEquals(0x18, aip[0] & 0xFF);
        assertEquals(0x00, aip[1] & 0xFF);
    }

    /**
     * Only 0x40, 0x20 and 0x01 go. Everything else in byte 1 survives.
     *
     * 0x9F is 0x80 RFU | 0x10 CV | 0x08 TRM | 0x04 issuer auth | 0x02 CVM |
     * 0x01 CDA | 0x20 DDA | 0x40 SDA. Expected 0x9E.
     */
    @Test
    public void clearOdaKeepsTheBitsACloneCanHonour() {
        byte[] tpl = Emv.hex("770A82029F00940408010100");
        Emv.clearOda(tpl);
        byte[] aip = Emv.findTag(tpl, 0x82);
        assertEquals(0x9E, aip[0] & 0xFF);
        assertEquals(0x80, aip[0] & 0x80);
        assertEquals(0x10, aip[0] & 0x10);
        assertEquals(0x08, aip[0] & 0x08);
    }

    /** An AIP already free of ODA bits is unchanged. */
    @Test
    public void clearOdaIsIdempotent() {
        byte[] tpl = Emv.hex("770A82021880940408010100");
        Emv.clearOda(tpl);
        assertEquals(0x18, Emv.findTag(tpl, 0x82)[0] & 0xFF);
    }

    // -------------------------------------------------------------- stripAcTags

    /** Format 1 has no inner TLVs, so it comes back as the same bytes. */
    @Test
    public void stripAcTagsLeavesFormat1Alone() {
        byte[] tpl = Emv.hex("8006188008010100");
        assertArrayEquals(tpl, Emv.stripAcTags(tpl));
    }

    /**
     * Format 2 loses every AC tag and keeps the rest.
     *
     * The outer length is 0x1E, the real byte count. It used to say 0x17, which
     * is under the content - stripAcTags clamps with Math.min(tpl.length,
     * pos[0] + olen), so the walk stopped early and the 9F36 was never even
     * reached. The assertions "passed" for the wrong reason.
     */
    @Test
    public void stripAcTagsRemovesAcTagsFromFormat2() {
        byte[] tpl = Emv.hex("771E" + "82021880" + "940408010100"
                + "9F2608" + "0000000000000000"
                + "9F270140" + "9F3602001B");
        byte[] out = Emv.stripAcTags(tpl);
        assertNull(Emv.findTag(out, 0x9F26));
        assertNull(Emv.findTag(out, 0x9F27));
        assertNull(Emv.findTag(out, 0x9F36));
        assertNotNull(Emv.findTag(out, 0x82));
        assertNotNull(Emv.findTag(out, 0x94));
    }

    // ---------------------------------------------------------------- cccBlock

    /** Exactly eight bytes, because the cipher is NoPadding. */
    @Test
    public void cccBlockIsEightBytes() {
        assertEquals(8, Emv.cccBlock(Emv.hex("1122"), Emv.hex("33445566"),
                Emv.hex("001B")).length);
    }

    // ------------------------------------------------------------------- decideCid

    private static final byte AAC = Emv.CID_AAC;
    private static final byte TC = Emv.CID_TC;
    private static final byte ARQC = Emv.CID_ARQC;

    /** A requested AAC wins even when an AC already went out in the GPO. */
    @Test
    public void decideHonoursAacEvenWhenTheAcWasAlreadySent() {
        assertEquals(AAC, Emv.decideCid(true, 0x00, true, true, TC, false, false, true));
    }

    /** A requested ARQC is echoed when the AC was already sent. */
    @Test
    public void decideEchoesTheRequestWhenTheAcWasAlreadySent() {
        assertEquals(ARQC, Emv.decideCid(true, 0x80, true, false, TC, false, false, true));
    }

    /** Nothing may approve a decline - the AAC check precedes the force box. */
    @Test
    public void decideHonoursAacOverEveryForce() {
        assertEquals(AAC, Emv.decideCid(false, 0x00, true, true, TC, true, true, true));
        assertEquals(AAC, Emv.decideCid(false, 0x00, true, true, ARQC, true, true, true));
    }

    /** A forced CID is obeyed when the card can back it. */
    @Test
    public void decideKeepsAForcedArqcWithAKey() {
        assertEquals(ARQC, Emv.decideCid(false, 0x40, true, true, ARQC, false, false, true));
    }

    /** A forced ARQC on a keyless card is unsatisfiable, so it downgrades. */
    @Test
    public void decideDowngradesAForcedArqcWithoutAKey() {
        assertEquals(TC, Emv.decideCid(false, 0x40, false, true, ARQC, false, false, false));
    }

    /** forceTc has to beat a terminal that asked for ARQC. */
    @Test
    public void decideForceTcBeatsARequestedArqc() {
        assertEquals(TC, Emv.decideCid(false, 0x80, true, false, TC, false, false, true));
    }

    /** With no force, a requested ARQC is answered when a key exists. */
    @Test
    public void decideAnswersARequestedArqcWhenTcIsNotForced() {
        assertEquals(ARQC, Emv.decideCid(false, 0x80, true, false, TC, false, false, false));
    }

    /** Eight zero bytes verify against nothing, so a keyless ARQC falls to TC. */
    @Test
    public void decideNeverAnswersArqcWithoutAKey() {
        assertEquals(TC, Emv.decideCid(false, 0x80, false, false, TC, false, false, false));
    }

    /**
     * KNOWN HOLE, pinned so it stays visible.
     *
     * The acInGpo branch never consults haveKey(). Once an AC is in the GPO a
     * zero ARQC goes on the wire regardless, which is why the keyless downgrade
     * for the GPO CID lives in ShadowApduService.gpoCidFor() instead.
     */
    @Test
    public void decideAcInGpoAnswersArqcWithoutAKeyKnownHole() {
        assertEquals(ARQC, Emv.decideCid(true, 0x80, false, false, TC, false, false, false));
    }

    // ------------------------------------------------------------------------ afl

    /**
     * Contiguous records collapse into ONE entry spanning first to last.
     *
     * The last byte is the run end, not the run start - 1 to 3 is 08 01 03 00.
     */
    @Test
    public void aflCollapsesContiguousRecords() {
        byte[] a = Emv.afl(Arrays.asList(new int[]{1, 1}, new int[]{1, 2}, new int[]{1, 3}));
        assertArrayEquals(Emv.hex("08010300"), a);
    }

    /** A gap starts a new entry, or the terminal reads a record that is absent. */
    @Test
    public void aflSplitsOnAGap() {
        byte[] a = Emv.afl(Arrays.asList(new int[]{1, 1}, new int[]{1, 3}));
        assertArrayEquals(Emv.hex("0801010008010300"), a);
    }

    /** Every entry is four bytes: SFI/rec-to-rec/none. */
    @Test
    public void aflEntriesAreFourBytes() {
        byte[] a = Emv.afl(Arrays.asList(new int[]{2, 5}, new int[]{3, 9}));
        assertEquals(0, a.length % 4);
    }

    // ------------------------------------------------------------ routing invariant

    /**
     * EVERY AID a profile can advertise must have an aid-filter in
     * apduservice.xml.
     *
     * The file states this as an INVARIANT in a comment and calls it invisible.
     * It is: an unfiltered AID means Android never routes the APDU to the
     * service, the tap dies with no log line and nothing to debug.
     */
    @Test
    public void everyAdvertisedAidHasAFilter() throws Exception {
        String xml = new String(Files.readAllBytes(
                Paths.get("src/main/res/xml/apduservice.xml")), StandardCharsets.UTF_8);

        Set<String> filters = new HashSet<>();
        Matcher f = Pattern.compile("aid-filter android:name=\"([0-9A-Fa-f]+)\"").matcher(xml);
        while (f.find()) filters.add(f.group(1).toUpperCase());
        assertFalse("no aid-filters parsed at all", filters.isEmpty());

        for (String name : Profiles.names()) {
            if (Profiles.AUTO.equals(name)) continue;
            CardProfile p = Profiles.byName(name);
            assertNotNull(name, p);

            Set<String> advertised = aidsIn(p.scriptConstants()[0]);
            assertFalse(name + " advertises no AID at all", advertised.isEmpty());
            for (String aid : advertised) {
                assertTrue(name + " advertises " + aid + " with no aid-filter",
                        filters.contains(aid));
            }
        }
    }

    /**
     * Every 4F value in a hex string, bounded by its own length byte.
     *
     * A plain regex over the whole hex cannot work - every character is a hex
     * digit, so a greedy group swallows the remainder of the string instead of
     * stopping at the declared length.
     */
    private static Set<String> aidsIn(String hex) {
        Set<String> out = new HashSet<>();
        int i = 0;
        while (i + 3 < hex.length()) {
            if (hex.charAt(i) == '4' && hex.charAt(i + 1) == 'F') {
                int len;
                try {
                    len = Integer.parseInt(hex.substring(i + 2, i + 4), 16);
                } catch (NumberFormatException e) {
                    i += 2;
                    continue;
                }
                int start = i + 4, end = start + len * 2;
                if (len > 0 && end <= hex.length()) {
                    out.add(hex.substring(start, end).toUpperCase());
                }
                i = end;
            } else {
                i += 2;
            }
        }
        return out;
    }

    // --------------------------------------------------------------- Visa CID

    /** A keyless Visa GPO still answers TC - the honest offline answer. */
    @Test
    public void gpoVisaAnswersTcWithoutAKey() {
        String line = Profiles.gpoVisa("06011200000000", "001B", "0000000000000000");
        assertTrue(line.contains("9F270140"));
    }

    /** A keyed Visa GPO answers ARQC, so the CTQ takes the tap online. */
    @Test
    public void gpoVisaAnswersArqcWithARealCryptogram() {
        String line = Profiles.gpoVisa("06011200000000", "001B", "A1B2C3D4E5F60718");
        assertTrue(line.contains("9F270180"));
    }
}
