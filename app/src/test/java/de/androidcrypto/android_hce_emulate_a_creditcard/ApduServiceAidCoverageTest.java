package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Guard: every AID a profile actually declares (its defaultAid(), and every
 * 4F/84 value embedded in its own scriptConstants() - the directory entries
 * and FCIs it can serve) must have a matching <aid-filter> in
 * apduservice.xml, full length, inside an aid-group whose category is
 * "payment" (see that file's own rule 2 and 3). If a profile ever grows a
 * new AID without the manifest resource following it, Android never routes
 * that AID here at all and the tap dies with no log line - this is the test
 * that catches that before a device does.
 *
 * The TLV reader here is independent of TlvValidator and of production
 * code, same reasoning as ShadowApduServicePpseTest's own reader: a bug
 * shared with the code under test would prove nothing.
 */
public class ApduServiceAidCoverageTest {

    private static final String APDUSERVICE_XML = "src/main/res/xml/apduservice.xml";

    private static String readAll(String path) throws IOException {
        try (InputStream in = new FileInputStream(path)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return new String(bo.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    /** Every value under tag 0x4F or 0x84, at any depth, short-form length only (every constant here is small). */
    private static List<String> extractAids(String hex) {
        byte[] b = fromHex(hex);
        List<String> out = new ArrayList<>();
        walk(b, 0, b.length, out);
        return out;
    }

    private static void walk(byte[] b, int from, int to, List<String> out) {
        int i = from;
        while (i < to) {
            int tag = b[i++] & 0xFF;
            boolean constructed = (tag & 0x20) != 0;
            if ((tag & 0x1F) == 0x1F) {
                int bb;
                do { bb = b[i++] & 0xFF; } while ((bb & 0x80) != 0);
            }
            int len = b[i++] & 0xFF;
            if (len == 0x81) len = b[i++] & 0xFF;
            else if (len == 0x82) { len = ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF); i += 2; }
            if (tag == 0x4F || tag == 0x84) out.add(toHex(b, i, i + len));
            if (constructed) walk(b, i, i + len, out);
            i += len;
        }
    }

    private static byte[] fromHex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    private static String toHex(byte[] b, int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to; i++) sb.append(String.format("%02X", b[i] & 0xFF));
        return sb.toString();
    }

    private static List<String> declaredAids(CardProfile p) {
        List<String> aids = new ArrayList<>();
        aids.add(p.defaultAid().toUpperCase());
        for (String constant : p.scriptConstants()) aids.addAll(extractAids(constant));
        return aids;
    }

    @Test
    public void everyProfileAid_hasAnAidFilterInApduServiceXml() throws IOException {
        String xml = readAll(APDUSERVICE_XML).toUpperCase();
        CardProfile[] profiles = {new ProfileMastercard(), new ProfileVisa(), new ProfileAmex()};

        for (CardProfile p : profiles) {
            for (String aid : declaredAids(p)) {
                assertTrue(p.name() + "'s AID " + aid + " has no <aid-filter> in " + APDUSERVICE_XML,
                        xml.contains("ANDROID:NAME=\"" + aid + "\""));
            }
        }
    }

    @Test
    public void aidGroup_categoryIsPayment() throws IOException {
        String xml = readAll(APDUSERVICE_XML);
        Pattern groupOpen = Pattern.compile("<aid-group\\b[^>]*>", Pattern.DOTALL);
        Matcher m = groupOpen.matcher(xml);
        assertTrue("no <aid-group> element found in " + APDUSERVICE_XML, m.find());
        String tag = m.group();
        assertTrue("aid-group has no android:category attribute: " + tag,
                tag.contains("android:category="));
        assertTrue("aid-group's category is not \"payment\": " + tag,
                tag.contains("android:category=\"payment\""));
        assertFalse("more than one <aid-group> found - this test only checked the first",
                m.find());
    }
}
