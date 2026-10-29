package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * Fixtures for every byte-level bug that has actually cost a shop trip.
 *
 * These run on the JVM in milliseconds. Before this file, the only way to find
 * out whether stripAcTags corrupted a record was to drive to a terminal.
 *
 * FIXTURE RULE: every outer length byte must equal the actual content length.
 * Several of these were wrong on first writing and the parser cut early.
 */
public class EmvTest {

    private static byte[] h(String s) { return Emv.hex(s); }
    private static String x(byte[] b) { return Emv.toHex(b); }

    // ---- stripAcTags ----

    @Test
    public void stripKeepsFormat1AipVerbatim() {
        // 80 12 = 18 content: AIP 2 + 57 0A + 10 + 9F27 01 80
        byte[] tpl = h("8012" + "1900" + "570A" + "6011410636372356D280" + "9F270180");
        assertEquals("800E" + "1900" + "570A" + "6011410636372356D280",
                x(Emv.stripAcTags(tpl)));
    }

    @Test
    public void stripDropsAcTagsFromFormat2() {
        // 77 1A = 26 content: 82 02 + 2 + 94 10 + 16 + 9F27 01 80
        byte[] tpl = h("771A" + "8202" + "1900" + "9410"
                + "08010100100103002002030228040400" + "9F270180");
        assertEquals("7716" + "8202" + "1900" + "9410"
                        + "08010100100103002002030228040400",
                x(Emv.stripAcTags(tpl)));
    }

    @Test
    public void stripRewritesLengthAcrossLongFormBoundary() {
        // 4 + 10 * 13 = 134 content -> long form 81 86
        StringBuilder aip = new StringBuilder("8202" + "1900");
        for (int i = 0; i < 10; i++) {
            aip.append("9F10").append("0A").append("00112233445566778899");
        }
        byte[] tpl = h("778186" + aip);
        assertEquals("7704" + "8202" + "1900", x(Emv.stripAcTags(tpl)));
    }

    // ---- weakenAip ----

    @Test
    public void weakenClearsCdaInFormat1() {
        byte[] tpl = h("800E" + "1900" + "570A" + "6011410636372356D280");
        Emv.weakenAip(tpl);
        assertEquals("1800", x(new byte[]{tpl[2], tpl[3]}));
    }

    @Test
    public void weakenClearsCdaInFormat2() {
        byte[] tpl = h("770A" + "8202" + "1900" + "9404" + "08010100");
        Emv.weakenAip(tpl);
        assertEquals("1800", x(new byte[]{tpl[4], tpl[5]}));
    }

    // ---- forceCid ----

    @Test
    public void forceCidOverwrites() {
        // 77 0E = 14 content: 82 02 + 2 + 9F27 01 80 + 94 04 + 4
        byte[] tpl = h("770E" + "8202" + "1900" + "9F270180" + "9404" + "08010100");
        // layout: 77 0E | 82 02 19 00 | 9F 27 01 80 ... -> CID at byte 9
        assertEquals("40", x(new byte[]{Emv.forceCid(tpl, (byte) 0x40)[9]}));
    }

    @Test
    public void forceCidAppendsWhenAbsent() {
        byte[] tpl = h("770A" + "8202" + "1900" + "9404" + "08010100");
        assertEquals("770E" + "8202" + "1900" + "9404" + "08010100" + "9F270140",
                x(Emv.forceCid(tpl, (byte) 0x40)));
    }

    // ---- findTag ----

    @Test
    public void findTagReturnsNullForFormat1() {
        assertNull(Emv.findTag(h("800E" + "1900" + "570A" + "6011410636372356D280"), 0x9F10));
    }

    @Test
    public void findTagReadsValue() {
        // 77 17 = 23 content: 82 02 + 2 + 9F10 0A + 10 + 94 04 + 4
        byte[] tpl = h("7717" + "8202" + "1900" + "9F100A" + "011520100300FF01B000"
                + "9404" + "08010100");
        assertEquals("011520100300FF01B000", x(Emv.findTag(tpl, 0x9F10)));
    }

    // ---- lcOf / dataOff ----

    @Test
    public void lcOfReadsShortLength() {
        assertEquals(0x0E, Emv.lcOf(h("00A404000E325041592E5359532E444446303100")));
        assertEquals(5, Emv.dataOff(h("00A404000E325041592E5359532E444446303100")));
    }

    @Test
    public void lcOfReadsExtendedLength() {
        assertEquals(0x1234, Emv.lcOf(h("00A4040000123400000000000000")));
        assertEquals(7, Emv.dataOff(h("00A4040000123400000000000000")));
    }

    // ---- afl ----

    @Test
    public void aflCollapsesContiguousRecords() {
        List<int[]> r = new ArrayList<>();
        r.add(new int[]{1, 1});
        r.add(new int[]{1, 2});
        r.add(new int[]{1, 3});
        assertEquals("08010300", x(Emv.afl(r)));
    }

    @Test
    public void aflSplitsNonContiguousRuns() {
        List<int[]> r = new ArrayList<>();
        r.add(new int[]{1, 1});
        r.add(new int[]{1, 2});
        r.add(new int[]{1, 4});
        assertEquals("08010200" + "08040400", x(Emv.afl(r)));
    }

    @Test
    public void aflSeparatesSfis() {
        List<int[]> r = new ArrayList<>();
        r.add(new int[]{2, 3});
        r.add(new int[]{2, 4});
        r.add(new int[]{4, 5});
        assertEquals("10030400" + "20050500", x(Emv.afl(r)));
    }

    // ---- tlv ----

    @Test
    public void tlvUsesLongFormAbove127() {
        byte[] out = Emv.tlv(0x77, new byte[200]);
        assertEquals(0x81, out[1] & 0xFF);
        assertEquals(200, out[2] & 0xFF);
        assertEquals(203, out.length);
    }
}
