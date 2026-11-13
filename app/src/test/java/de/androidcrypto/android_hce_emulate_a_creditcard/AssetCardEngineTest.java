package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Full flow of the mrautio/emv-card-simulator test card (AID AFFFFFFFFF1234),
 * loaded from app/src/main/assets/profile.json.
 *
 * Expected record bytes were produced by an independent encoder over the
 * published profile, and the two cryptograms by an independent openssl 3DES/MAC
 * run (EMV Book 2 A1.3.1 session key, ISO 9797-1 Algorithm 3, padding method 2),
 * not by the code under test. The profile is the Zlib-licensed
 * card_setup_app_apdus.yaml.
 */
public class AssetCardEngineTest {

    static final String PROFILE = "src/main/assets/profile.json";

    private static final String SELECT_PPSE = "00A404000E325041592E5359532E444446303100";
    private static final String SELECT_AID = "00A4040007AFFFFFFFFF123400";
    private static final String GPO = "80A8000002830000";
    // CDOL1 data: 9F02 000000001000 | 9F03 0 | 9F1A 0840 | 95 0 | 5F2A 0840 | 9A 261112 | 9C 00 | 9F37 12345678
    private static final String CDOL1_DATA =
            "00000000100000000000000008400000000000084026111200" + "12345678";
    private static final String GENAC = "80AE80001D" + CDOL1_DATA + "00";

    private static final String FCI = "6F398407AFFFFFFFFF1234A52E500D5645534120454C454354524F4E5F2D02656E8701019F1210564553412020"
            + "202020202020202020209F1101019000";
    private static final String REC_1_2 = "704257131234560012345608D29122211229424900200F5F200F43415244484F4C4445522F544553549F1F1831"
            + "32323934303030303032303030303234393030303030309000";
    private static final String REC_2_1 = "7081BE9F4681B018C47E9742500142A530DCC6834319829E60204C3DAC1CA96861E40A0F2ACAEA7831411BFCC7"
            + "6DAFD527ECAA443372E28FC13DC20E478148AFC07342B2E1B4AFB4284F7141646C42F3420137FDD890B477A8A3"
            + "14E29EA589417A68A224821360FB0CA7C4D74280462FE7EADED581335C7A0080AE2BC47C2A21AF588DE719A000"
            + "A5187E65E098A5164E5C4F38A7CD5553DB98670E5C77282243CACD8EA9F9C3A12BC10770D55DC9154D19535A6C"
            + "DD074C9F4701039F49039F37049000";
    private static final String REC_2_2 = "7081E08F01929F32010392245FCEA152B4D9EC9791BF309672FA51AFA9562D1C0B333ED61A5A200040C3B50A46"
            + "023B899081B02008FB40DDA89999AF873A0D9BAB158D5ACE11344FE38F72053CC5ECCFE496BBA58B37D669BAB2"
            + "CEAF937F329735E02741E7122C832BE33CD1AA38D27CDACCED8B02F0EA231C7C6BCBF8239ECF2C11954B407D58"
            + "E9A689AB22DFC998022A179FAFC619ABC5AB237C68410239129395575E623F4F8BA8380A3907ACF42009B8C3D3"
            + "0FD10FBB91B13DC014B619BA584CE0B9AC6FB1D3A4A74503F690887F111313D010A3A7117E8C04448746D3AAF8"
            + "88EA9000";
    private static final String REC_3_1 = "70505F24032912315A0812345600123456085F3401019F0702FF808E1400000000000000000201440341031E03"
            + "02031F009F0D05B8483C98009F0E0500108000009F0F05B8483C98005F280202469F4A01829000";
    private static final String REC_3_2 = "703E9F420209789F4401029F080200968C159F02069F03069F1A0295055F2A029A039C019F37048D178A029F02"
            + "069F03069F1A0295055F2A029A039C019F37049000";

    private AssetCardEngine eng;

    @Before
    public void setUp() throws Exception {
        try (InputStream in = new FileInputStream(PROFILE)) {
            eng = AssetCardEngine.load(in);
        }
    }

    private String send(String apdu) {
        return Hex.toHex(eng.process(Hex.hex(apdu)));
    }

    @Test
    public void profile_carriesEveryRequiredField() {
        assertEquals("1234560012345608", eng.pan());
        assertEquals("291231", eng.expiry());
        assertEquals("221", eng.serviceCode());
        assertEquals("1234560012345608D29122211229424900200F", eng.track2());
        assertEquals("080202001001020018010201", eng.afl());
        assertEquals("3C00", eng.aip());
        assertEquals("9F02069F03069F1A0295055F2A029A039C019F3704", eng.cdol1());
        assertEquals("8A029F02069F03069F1A0295055F2A029A039C019F3704", eng.cdol2());
        assertEquals("06011203A4A002", eng.tag("9F10"));
        assertEquals("0123456789ABCDEFFEDCBA9876543210", eng.mkAc());
        assertEquals("03", eng.tag("9F32"));
        assertEquals("03", eng.tag("9F47"));
        assertEquals("92", eng.tag("8F"));
        assertTrue(eng.tag("90").startsWith("2008FB40"));
        assertTrue(eng.tag("92").startsWith("5FCEA152"));
        assertTrue(eng.tag("9F46").startsWith("18C47E97"));
    }

    @Test
    public void ppse_listsTheTestCardAid() {
        assertEquals("6F32840E325041592E5359532E4444463031A520BF0C1D611B4F07AFFFFFFFFF1234"
                + "500D5645534120454C454354524F4E8701019000", send(SELECT_PPSE));
    }

    @Test
    public void selectAid_returnsFciFromProfile() {
        assertEquals(FCI, send(SELECT_AID));
    }

    @Test
    public void gpo_isFormat1WithAipAndAflFromProfile() {
        send(SELECT_AID);
        assertEquals("800E3C00080202001001020018010201" + "9000", send(GPO));
    }

    @Test
    public void readRecord_walksTheAfl() {
        send(SELECT_AID);
        send(GPO);
        assertEquals(REC_1_2, send("00B2020C00"));
        assertEquals(REC_2_1, send("00B2011400"));
        assertEquals(REC_2_2, send("00B2021400"));
        assertEquals(REC_3_1, send("00B2011C00"));
        assertEquals(REC_3_2, send("00B2021C00"));
    }

    @Test
    public void readRecord_outsideAfl_returns6A83() {
        send(SELECT_AID);
        send(GPO);
        assertEquals("6A83", send("00B2010C00"));   // SFI 1 record 1: the AFL starts at record 2
        assertEquals("6A83", send("00B2032400"));   // SFI 4 is not in the AFL
    }

    @Test
    public void readRecord_beforeGpo_returns6985() {
        send(SELECT_AID);
        assertEquals("6985", send("00B2020C00"));
    }

    @Test
    public void fullFlow_ppseToGenerateAc_exactBytes() {
        assertTrue(send(SELECT_PPSE).endsWith("9000"));
        assertEquals(FCI, send(SELECT_AID));
        assertEquals("800E3C00080202001001020018010201" + "9000", send(GPO));
        assertEquals(REC_1_2, send("00B2020C00"));
        assertEquals(REC_2_1, send("00B2011400"));
        assertEquals(REC_2_2, send("00B2021400"));
        assertEquals(REC_3_1, send("00B2011C00"));
        assertEquals(REC_3_2, send("00B2021C00"));
        // ATC 00F0 in the profile, advanced to 00F1 by the GPO.
        assertEquals("771E" + "9F270180" + "9F360200F1"
                + "9F2608FBE724C147ACDF75" + "9F100706011203A4A002" + "9000", send(GENAC));
    }

    @Test
    public void generateAc_twoConsecutiveAcsDifferBecauseTheAtcAdvanced() {
        send(SELECT_AID);
        send(GPO);
        String first = send(GENAC);

        send(SELECT_AID);
        send(GPO);
        String second = send(GENAC);

        assertEquals("771E9F2701809F360200F1" + "9F2608FBE724C147ACDF75" + "9F100706011203A4A0029000", first);
        assertEquals("771E9F2701809F360200F2" + "9F26082D1F49E3E6EA0F85" + "9F100706011203A4A0029000", second);
        assertNotEquals(first, second);
        assertNotEquals(first.substring(22, 38), second.substring(22, 38));
    }

    @Test
    public void generateAc_cryptogramCoversTheTerminalData() {
        send(SELECT_AID);
        send(GPO);
        String a = send(GENAC);
        // Rewind the counter so only the CDOL data differs between the two.
        eng.setAtc(0xF0);
        send(SELECT_AID);
        send(GPO);
        String b = send(GENAC.replace("12345678", "87654321"));
        assertEquals(a.substring(0, 22), b.substring(0, 22));        // same CID and ATC
        assertNotEquals(a.substring(22, 38), b.substring(22, 38));   // different AC
    }

    @Test
    public void generateAc_wrongCdolLength_returns6700() {
        send(SELECT_AID);
        send(GPO);
        assertEquals("6700", send("80AE80001C" + CDOL1_DATA.substring(2) + "00"));
    }

    @Test
    public void generateAc_beforeGpo_returns6985() {
        send(SELECT_AID);
        assertEquals("6985", send(GENAC));
    }

    @Test
    public void generateAc_twiceInOneTransaction_secondIsRefused() {
        send(SELECT_AID);
        send(GPO);
        send(GENAC);
        assertEquals("6985", send(GENAC));
    }

    // ---- PDOL: parsed from the selected record, answered in list order ----

    private AssetCardEngine withPdol(String pdolHex) throws Exception {
        JsonObject o;
        try (InputStream in = new FileInputStream(PROFILE)) {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            o = JsonParser.parseString(new String(bo.toByteArray(), StandardCharsets.UTF_8))
                    .getAsJsonObject();
        }
        JsonObject tags = o.getAsJsonObject("tags");
        // The PDOL belongs to the A5 template of the selected application's FCI.
        tags.addProperty("A5", tags.get("A5").getAsString()
                + "9F38" + String.format("%02X", pdolHex.length() / 2) + pdolHex);
        return AssetCardEngine.load(new ByteArrayInputStream(
                o.toString().getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void pdol_isParsedFromTheSelectedRecord_andAnsweredInOrder() throws Exception {
        // 9F66 (4), 9F02 (6), 9F37 (4): 14 bytes of terminal data
        AssetCardEngine e = withPdol("9F66049F02069F3704");
        String fci = Hex.toHex(e.process(Hex.hex(SELECT_AID)));
        assertTrue(fci, fci.contains("9F38099F66049F02069F3704"));
        assertEquals("800E3C00080202001001020018010201" + "9000",
                Hex.toHex(e.process(Hex.hex("80A8000010" + "830E"
                        + "F6204000" + "000000001000" + "AABBCCDD" + "00"))));
        assertEquals("F6204000", e.terminalData("9F66"));
        assertEquals("000000001000", e.terminalData("9F02"));
        assertEquals("AABBCCDD", e.terminalData("9F37"));
    }

    @Test
    public void pdol_dataOfTheWrongLength_returns6700() throws Exception {
        AssetCardEngine e = withPdol("9F66049F02069F3704");
        e.process(Hex.hex(SELECT_AID));
        assertEquals("6700", Hex.toHex(e.process(Hex.hex("80A800000283000000"))));
    }

    @Test
    public void dolParse_returnsTagLengthPairsInOrder() {
        assertArrayEquals(new int[]{0x9F66, 4, 0x9F02, 6, 0x95, 5},
                AssetCardEngine.parseDol(Hex.hex("9F66049F0206" + "9505")));
    }

    @Test(expected = IllegalArgumentException.class)
    public void dolParse_truncatedList_throws() {
        AssetCardEngine.parseDol(Hex.hex("9F66049F02"));
    }
}
