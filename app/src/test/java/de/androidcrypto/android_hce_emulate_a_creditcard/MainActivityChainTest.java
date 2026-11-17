package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.os.Looper;
import android.widget.EditText;
import android.widget.TextView;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The new chain path: AssetCardHolder's process-wide AssetCardEngine, and
 * MainActivity's TRACK 2 RAW HEX box telling a captured chain from a bare
 * track 2 before picking applyChain() over applyDump().
 *
 * The chain blob here reuses profile.json's own real 8F/90/9F32/82/94 plus
 * its AFL-named records - DumpChain.parse()'s five required tags - but
 * carries no SSAD, so lastDumpVerify() fails (expected: this proves the
 * LOAD, not a verified chain; AssetCardEngineDumpTest already owns the
 * signed-SSAD, verifies-ok case).
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MainActivityChainTest {

    private static final String PROFILE = "src/main/assets/profile.json";

    private static Map<String, String> tags;
    private static Map<String, String[]> records;
    private static String afl, aip;

    private MainActivity activity;
    private EditText etTrack2;
    private TextView txtStatus;

    @BeforeClass
    public static void loadFixture() throws IOException {
        JsonObject o = JsonParser.parseString(readAll(PROFILE)).getAsJsonObject();
        afl = o.get("afl").getAsString();
        aip = o.get("aip").getAsString();
        tags = new LinkedHashMap<>();
        for (Map.Entry<String, com.google.gson.JsonElement> e : o.getAsJsonObject("tags").entrySet()) {
            tags.put(e.getKey().toUpperCase(), e.getValue().getAsString());
        }
        records = new LinkedHashMap<>();
        for (Map.Entry<String, com.google.gson.JsonElement> e : o.getAsJsonObject("records").entrySet()) {
            JsonArray a = e.getValue().getAsJsonArray();
            String[] list = new String[a.size()];
            for (int i = 0; i < list.length; i++) list[i] = a.get(i).getAsString();
            records.put(e.getKey(), list);
        }
    }

    private static String readAll(String path) throws IOException {
        try (InputStream in = new FileInputStream(path)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return new String(bo.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    @Before
    public void setUp() {
        Prefs.reset(RuntimeEnvironment.getApplication());
        AssetCardHolder.reset();
        activity = Robolectric.buildActivity(MainActivity.class).create().start().resume().get();
        shadowOf(Looper.getMainLooper()).idle();

        etTrack2 = activity.findViewById(R.id.etTrack2);
        txtStatus = activity.findViewById(R.id.txtStatus);
    }

    private void type(String text) {
        etTrack2.setText(text);
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300));
    }

    private static byte[] record(String key) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (String t : records.get(key)) {
            byte[] enc = Tlv.t(Integer.parseInt(t, 16), Hex.hex(tags.get(t)));
            body.write(enc, 0, enc.length);
        }
        return Tlv.t(0x70, body.toByteArray());
    }

    /**
     * DumpChain.parse()'s five required tags, no SSAD - this proves the
     * LOAD, not a verified chain. Leads with record("1:2") - a 0x70
     * template, a real constructed/template tag - not the bare 0x84, which
     * is primitive and would fail looksLikeChain()'s own "opens with a
     * template tag" check before this blob ever reached DumpChain at all.
     *
     * profile.json's own chain carries no 9F4B (no DDA signature - this
     * card proves itself by SDA/no-ODA, not DDA, and 9F4B is only ever
     * generated dynamically by a real INTERNAL AUTHENTICATE, never stored),
     * so looksLikeChain()'s own "carries 90/9F4B" check would otherwise
     * fail on this blob. A 77{9F4B} appended here is exactly the shape a
     * real terminal log would add if it also captured an INTERNAL
     * AUTHENTICATE in the same session - not fabricating what the card is,
     * just completing the capture's own shape for the detection heuristic.
     */
    private static String validChainHex() {
        byte[] blob = Tlv.cat(
                record("1:2"), record("2:1"), record("2:2"), record("3:1"), record("3:2"),
                Tlv.t(0x84, Hex.hex(tags.get("84"))),
                Tlv.t(0x77, Tlv.cat(Tlv.t(0x82, Hex.hex(aip)), Tlv.t(0x94, Hex.hex(afl)))),
                Tlv.t(0x77, Tlv.t(0x9F4B, Hex.hex("00"))));
        return Hex.toHex(blob);
    }

    // ----------------------------------------------------------------- tests

    @Test
    public void assetCardHolder_isOneInstanceAcrossTheProcess() throws IOException {
        AssetCardEngine a = AssetCardHolder.get(RuntimeEnvironment.getApplication());
        AssetCardEngine b = AssetCardHolder.get(RuntimeEnvironment.getApplication());
        assertSame("process-wide means one instance, not a new one per caller", a, b);
    }

    @Test
    public void validChain_loadsIntoTheSharedEngine_aFreshServiceSeesIt() throws IOException {
        type(validChainHex());

        assertTrue("status must say the chain loaded: " + txtStatus.getText(),
                txtStatus.getText().toString().contains("chain loaded"));

        // Not through MainActivity at all - a freshly built ShadowApduService
        // (the OTHER component, in the OTHER half of the pair this task asked
        // for) must see the exact same loaded dump, because it is the exact
        // same AssetCardEngine instance, not a copy.
        AssetCardEngine fromService = AssetCardHolder.get(RuntimeEnvironment.getApplication());
        assertTrue("the instance MainActivity loaded into must carry the dump", fromService.hasDump());
    }

    @Test
    public void malformedChain_failsLoudly_doesNotLoad() throws IOException {
        // Satisfies looksLikeChain()'s cheap shape check (opens with a
        // constructed tag, contains "90" and "9F4B") without being anything
        // DumpChain.parse() can actually use - no 8F, no real structure.
        type("77049000" + "9F4B00");

        assertTrue("status must name the chain refusal: " + txtStatus.getText(),
                txtStatus.getText().toString().startsWith("chain:"));
        assertFalse("a rejected parse must not leave a dump loaded",
                AssetCardHolder.get(RuntimeEnvironment.getApplication()).hasDump());
    }

    @Test
    public void ambiguousInput_failsClosed_neitherPathRuns() throws IOException {
        // "70" opens with a constructed tag (bit 0x20 set) - satisfying
        // looksLikeChain() - but as plain text it is ALSO the digit '7',
        // and this string's 'D' lands at index 12 with enough tail after
        // it, satisfying looksLikeFullDump() too (verified against both
        // methods' actual logic before writing this, not assumed). Neither
        // applyChain() nor applyDump() may run.
        String ambiguous = "709000000000" + "D9F4B000000000";
        type(ambiguous);

        assertTrue("status must name the ambiguity: " + txtStatus.getText(),
                txtStatus.getText().toString().contains("both a chain and a track 2"));
        assertFalse(AssetCardHolder.get(RuntimeEnvironment.getApplication()).hasDump());
    }
}
