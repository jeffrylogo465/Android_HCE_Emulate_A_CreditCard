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

    /**
     * Fallback AIP when the card has no captured GPO.
     *
     * The EMV Contactless AIP byte 1 is:
     *   0x40 SDA supported        0x10 cardholder verification supported
     *   0x20 DDA supported        0x08 terminal risk management to be performed
     *   0x01 CDA supported        0x04 issuer authentication supported
     * 0x80 and 0x02 are RFU.
     *
     * 0x10 = CV only. No ODA of any kind, no TRM, no issuer auth - nothing for
     * the terminal to check and fail.
     */
    private static final String DEFAULT_AIP = "1080";

    /**
     * Keep-mask applied to byte 1 of whatever AIP is in force. Clears the three
     * ODA bits (SDA 0x40, DDA 0x20, CDA 0x01) and issuer auth (0x04), which a
     * clone can never satisfy, and keeps CV (0x10) and TRM (0x08) so the editor
     * can still choose them. A field of 3080 becomes 1080; a field of 1800 stays
     * 1800.
     */
    private static final byte AIP_ODA_MASK = (byte) 0x18;

    /**
     * AIP byte 2 bit 8. Only meaningful with EMV framing - a magstripe response
     * must not claim EMV mode.
     *
     * Note: real cards hand back byte 2 = 0x00 here, so this is the app's own
     * convention rather than a spec bit. It is kept because it makes byte 2 agree
     * with the framing we send, which is the part that actually matters. If a
     * terminal ever objects, set this to 0x00 and rebuild.
     */
    private static final byte AIP_EMV_MODE = (byte) 0x80;

    private static final byte CID_AAC  = (byte) 0x00;
    private static final byte CID_TC   = (byte) 0x40;
    private static final byte CID_ARQC = (byte) 0x80;

    private static final boolean ALWAYS_ONLINE_FOR_RECEIPT = false;
    private static final boolean FORCE_ONLINE_ARQC = true;
    private static final boolean FORCE_OFFLINE_TC = true;

    private static final String PDOL    = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL1   = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL2   = "9F02069F03069F1A0295055F2A029A039C019F37049F3403";

    private static final String CVMLIST = "00000000000000001F00";

    /**
     * Used when the selected card has no script of its own. One per line:
     *   <match>=<response>
     *   match    - hex PREFIX of the command APDU. 80A80000 catches every GPO.
     *   response - sent verbatim, so paste the '<<' line out of the tap log.
     * '#' starts a comment, spaces are ignored, longest match wins.
     *
     * INCLUDE THE 9000 ON THE SAME LINE. It is part of the response. Putting it
     * on the next line means it has no '=' and is ignored - the terminal then
     * reads the last two payload bytes as the status word. A 77 template must
     * also declare its content length exactly: 82 02 xxxx is 4 bytes and
     * 94 04 + 4 is 6, so the content is 10 = 0x0A and the header reads 770A.
     */
    private static final String DEFAULT_SCRIPT =
            "# match=response, hex only. Longest match wins.\n"
          + "# 80A80000=770A82021000940408010100 9000\n"
          + "# 00B2010C=70265A0860114994320077045F24033112318C149F02069F03069F1A0295055F2A029A039C019F3704 9000\n";

    private final StringBuilder tapLog = new StringBuilder();
    private final Random rnd = new Random();

    private byte[] txnAip;
    private String txnAtc;
    private boolean cryptogramSent;
    private int scriptHits;

    private void tap(String s) {
        tapLog.append(s).append('\n');
        if (tapLog.length() > 6000) tapLog.delete(0, 3000);
    }

    private void popup(final String s) {
        if (s == null || s.isEmpty()) return;
        try {
            new android.os.Handler(android.os.Looper.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(HceCcEmulationServiceVisa.this, s, Toast.LENGTH_SHORT).show();
                }
            });
        } catch (Exception ignored) { }
    }

    static byte[] hex(String s) { return Hex.hex(s); }
    static byte[] tlv(int tag, byte[] v) { return Tlv.t(tag, v); }
    static byte[] cat(byte[]... arrs) { return Tlv.cat(arrs); }
    private static String bytesToHex(byte[] d) { return Hex.toHex(d); }

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

    /**
     * Lc of an incoming APDU, extended length included.
     *
     * FIX: reading apdu[4] as a plain Lc gives 0 for an extended APDU. The
     * reader emits extended when a PDOL or CDOL1 is over 255 bytes, and the two
     * consequences were both silent: a long SELECT took the empty-name path and
     * selected the card's own AID, and a long GENERATE AC MACed over an empty
     * CDOL. Neither raised anything.
     */
    private static int lcOf(byte[] apdu) {
        if (apdu.length < 5) return 0;
        int lc = apdu[4] & 0xFF;
        if (lc != 0x00) return lc;
        if (apdu.length < 7) return 0;
        return ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
    }

    /** Offset of the data field, past an extended length if there is one. */
    private static int dataOff(byte[] apdu) {
        return (apdu.length >= 7 && (apdu[4] & 0xFF) == 0x00) ? 7 : 5;
    }

    private static byte[] hexOrNull(String s) {
        return (s == null || s.isEmpty()) ? null : hex(s);
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("hce_card", Context.MODE_PRIVATE);
    }

    private String sel() {
        return "card" + prefs().getInt("selected", 0) + "_";
    }

    private String p(String k, String d) {
        String v = prefs().getString(sel() + k, d);
        return (v == null || v.isEmpty()) ? d : v;
    }

    private void put(String k, String v) {
        prefs().edit().putString(sel() + k, v).apply();
    }

    private boolean isMsd() {
        return prefs().getInt(sel() + "msd", 0) == 1;
    }

    // ---------- card fields, normalised once ----------

    /**
     * FIX: PAN and PSN were being read with two different defaults in two
     * different places - the record said PSN 01 while the ARQC was MACed over
     * PSN 00. One helper each, used by every caller, so the record and the
     * cryptogram can never disagree.
     *
     * PSN is zero padded, not F padded: hex("1") gives 1F, which is the wrong
     * byte for a one-digit sequence number.
     */
    private String pan() {
        String s = p("pan", "4111111111111111").replaceAll("[^0-9]", "");
        return s.isEmpty() ? "4111111111111111" : s;
    }

    private String psn() {
        String s = p("psn", "01").replaceAll("[^0-9]", "");
        if (s.isEmpty()) return "01";
        if (s.length() > 2) s = s.substring(0, 2);
        if (s.length() == 1) s = "0" + s;
        return s;
    }

    /** Directory label: the editor field wins, then whatever the reader saw. */
    private String labelText() {
        String s = p("label", p("cap_label", "CARD"));
        return s.length() > 16 ? s.substring(0, 16) : s;
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

    private String txnAtc() {
        if (txnAtc == null) txnAtc = nextAtc();
        return txnAtc;
    }

    private void resetTransaction() {
        txnAip = null;
        txnAtc = null;
        cryptogramSent = false;
        scriptHits = 0;
    }

    /**
     * FIX: this used to hand back the raw field when gpo() had not run - which
     * happens whenever a script line serves the GPO. The ARQC was then MACed
     * over an AIP that was never sent. The mask is applied here too, so the MAC
     * input matches the wire either way.
     */
    private byte[] aipForMac() {
        byte[] a = txnAip;
        if (a == null) {
            a = hex(p("aip", DEFAULT_AIP));
            if (a.length >= 2) a = new byte[]{(byte) (a[0] & AIP_ODA_MASK), a[1]};
        }
        if (a.length < 2) a = hex(DEFAULT_AIP);
        return a;
    }

    private boolean haveKey() {
        return p("mkac", "").replaceAll("[^0-9A-Fa-f]", "").length() >= 32;
    }

    private byte[] cap(String key) {
        return hexOrNull(p("cap_" + key, ""));
    }

    private byte[] rawFci()  { return cap("rawfci"); }
    private byte[] rawGpo()  { return cap("rawgpo"); }

    private byte[] rawRec(int sfi, int rec) {
        return cap("rec" + sfi + "_" + rec);
    }

    private String holderName() {
        return p("name", p("cap_holder", ""));
    }

    private String nameLine() {
        String h = holderName();
        String pan = p("pan", "");
        String tail = pan.length() >= 4 ? "  \u2022\u2022" + pan.substring(pan.length() - 4) : "";
        if (h.isEmpty()) return pan.isEmpty() ? "Tapping - card is empty" : "Tapping" + tail;
        return h + tail;
    }

    private byte[] holder() {
        String h = holderName().toUpperCase()
                .replaceAll("[^A-Z0-9 ./'-]", "")
                .replaceAll("\\s+", " ")
                .trim();
        if (h.length() < 2) return null;
        if (h.length() > 26) h = h.substring(0, 26);
        return h.getBytes(StandardCharsets.ISO_8859_1);
    }

    // ---------- script overrides ----------

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

    /** A status word always starts 0x90 or in the 0x61-0x6F range. */
    private static boolean looksLikeSw(int cls) {
        return cls == 0x90 || (cls >= 0x61 && cls <= 0x6F);
    }

    private static int kernelFor(String aidHex) {
        String a = aidHex == null ? "" : aidHex.toUpperCase();
        if (a.startsWith("A000000152")) return 6;
        if (a.startsWith("A000000015")) return 6;
        if (a.startsWith("A000000004")) return 2;
        if (a.startsWith("A000000065")) return 5;
        if (a.startsWith("A000000025")) return 4;
        if (a.startsWith("A000000333")) return 7;
        return 3;
    }

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

        String lbl = labelText();

        ByteArrayOutputStream dir = new ByteArrayOutputStream();

        byte[] e0 = tlv(0x61, appEntry(realAid, lbl, 1));
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
                v = patchA5(v, aid);
            }

            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        return tlv(outer, out.toByteArray());
    }

    /**
     * FIX: this used to only rewrite 9F2A when it was already there. A captured
     * FCI that carried no kernel identifier stayed without one, while the
     * generated FCI has it - so the two paths disagreed about the same card.
     * It is now added when missing.
     */
    private byte[] patchA5(byte[] a5, byte[] aid) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        boolean sawKernel = false;
        int i = 0;
        while (i < a5.length) {
            int[] q = new int[]{i};
            int t = readTag(a5, q);
            int l = readLen(a5, q);
            if (q[0] + l > a5.length) break;
            byte[] v = Arrays.copyOfRange(a5, q[0], q[0] + l);
            i = q[0] + l;

            if (t == 0x9F2A && v.length >= 1) {
                sawKernel = true;
                v = new byte[]{(byte) kernelFor(bytesToHex(aid))};
            }
            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        if (!sawKernel) {
            byte[] one = tlv(0x9F2A, new byte[]{(byte) kernelFor(bytesToHex(aid))});
            out.write(one, 0, one.length);
        }
        return out.toByteArray();
    }

    private byte[] afl() {
        String typed = p("afl", "").replaceAll("[^0-9A-Fa-f]", "");
        if (typed.length() >= 8 && typed.length() % 8 == 0) {
            tap("-- afl source: typed");
            return hex(typed);
        }

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
            tap("-- afl source: no records - defaulting to SFI 1 rec 1");
            TreeSet<Integer> one = new TreeSet<>();
            one.add(1);
            map.put(1, one);
        } else {
            tap("-- afl source: derived from " + map.size() + " SFI(s)");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, TreeSet<Integer>> e : map.entrySet()) {
            int sfi = e.getKey();
            int runStart = -1, prev = -1;
            for (int rec : e.getValue()) {
                if (runStart < 0) {
                    runStart = rec;
                } else if (rec != prev + 1) {
                    aflEntry(out, sfi, runStart, prev);
                    runStart = rec;
                }
                prev = rec;
            }
            if (runStart >= 0) aflEntry(out, sfi, runStart, prev);
        }
        return out.toByteArray();
    }

    private static void aflEntry(ByteArrayOutputStream out, int sfi, int first, int last) {
        out.write((sfi << 3) & 0xFF);
        out.write(first & 0xFF);
        out.write(last & 0xFF);
        out.write(0x00);
    }

    /**
     * FIX: a five digit value used to fall through every branch and land on the
     * hardcoded 311201. Anything at least four long is now treated as YYMM with
     * a day appended.
     */
    private String expiry6() {
        String d = p("expiry", "3112").replaceAll("[^0-9]", "");
        if (d.length() >= 6) return d.substring(0, 6);
        if (d.length() == 5) return d.substring(0, 4) + "01";
        if (d.length() == 4) return d + "01";
        if (d.length() == 2) return "27" + d + "01";
        return "311201";
    }

    private byte[] track2() {
        String t = p("track2", "").toUpperCase().replace('=', 'D');
        t = t.replaceAll("[^0-9A-F]", "");

        if (t.isEmpty()) {
            String exp = expiry6();
            String svc = p("service", "201").replaceAll("[^0-9]", "");
            while (svc.length() < 3) svc = "0" + svc;
            t = pan()
                    + "D"
                    + exp.substring(0, 4)
                    + svc.substring(0, 3)
                    + p("discretionary", "").replaceAll("[^0-9]", "");
        }

        if (t.length() % 2 != 0) t += "F";
        return hex(t);
    }

    private byte[] syntheticRecord() {
        String pan = pan();
        String exp = expiry6();
        String psn = psn();
        if (pan.length() % 2 != 0) pan += "F";

        byte[] h = holder();

        return tlv(0x70, cat(
                tlv(0x5A, hex(pan)),
                tlv(0x5F34, hex(psn)),
                tlv(0x5F24, hex(exp)),
                h == null ? new byte[0] : tlv(0x5F20, h),
                tlv(0x57, track2()),
                tlv(0x8C, hex(CDOL1)),
                tlv(0x8D, hex(CDOL2)),
                tlv(0x8E, hex(CVMLIST))));
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        try {
            if (apdu == null || apdu.length < 4) return SW_BAD;

            int ins = apdu[1] & 0xFF;
            int p1  = apdu[2] & 0xFF;
            int p2  = apdu[3] & 0xFF;

            // FIX: any P1 now counts. A SELECT with P1 02 used to fall through
            // every branch and get 6A82.
            boolean isSelect = (ins == 0xA4);

            if (isSelect && apdu.length >= 5) {
                int lc0 = lcOf(apdu);
                int off0 = dataOff(apdu);
                if (apdu.length >= off0 + lc0) {
                    byte[] nm = new byte[lc0];
                    System.arraycopy(apdu, off0, nm, 0, lc0);
                    if (Arrays.equals(nm, PPSE)) {
                        tapLog.setLength(0);
                        resetTransaction();
                        int n = scriptLines();
                        if (n > 0) tap("-- script armed: " + n + " line(s)");
                        popup(nameLine());
                    }
                }
            }

            tap(">> " + bytesToHex(apdu));

            String hit = scriptMatch(apdu);
            if (hit != null) {
                byte[] out = hex(hit);
                scriptHits++;

                if (out.length >= 2 && !looksLikeSw(out[out.length - 2] & 0xFF)) {
                    tap("-- script response had no status word - appended 9000");
                    out = cat(out, SW_OK);
                } else if (out.length < 2) {
                    out = cat(out, SW_OK);
                }

                if (ins == 0xA8) {
                    tap("-- script served the GPO - MSD/AIP/AFL come from the script, not the card");
                }
                tap("-- script hit " + out.length + " bytes");
                tap("<< " + bytesToHex(out));
                return out;
            }

            byte[] out;
            if (isSelect) {
                if (apdu.length < dataOff(apdu)) return SW_BAD;
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
                out = SW_OK;
            } else if (ins == 0x84) {
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
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (apdu.length < off + lc) return SW_BAD;
        byte[] name = new byte[lc];
        System.arraycopy(apdu, off, name, 0, lc);

        if (Arrays.equals(name, PPSE)) {
            return cat(buildPpse(), SW_OK);
        }

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
        tap("-- fci source: " + (captured == null ? "generated" : "captured " + captured.length + "B"));
        if (captured != null) {
            return cat(patchFci(captured, name), SW_OK);
        }

        String label = labelText();
        byte[] prop = cat(
                tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{0x01}),
                tlv(0x9F11, new byte[]{0x01}),
                tlv(0x9F12, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x9F2A, new byte[]{(byte) kernelFor(bytesToHex(name))}),
                tlv(0x9F38, hex(PDOL)));
        byte[] inner = cat(tlv(0x84, name), tlv(0xA5, prop));
        return cat(tlv(0x6F, inner), SW_OK);
    }

    /**
     * Magstripe branch, back to the author's original shape: 80 <len> <AIP 2>
     * <57 track 2>, no AFL.
     *
     * FIX: the MSD field now WINS over the captured framing instead of the other
     * way round, so MSD is actually selectable on a clone. The old behaviour made
     * the editor switch decorative - a clone of an EMV card could never be put
     * into the no-crypto lane. A disagreement is logged.
     */
    private byte[] gpo() {
        byte[] raw = rawGpo();

        boolean msd = isMsd();
        if (raw != null && raw.length > 0) {
            int[] q = new int[1];
            int outer = readTag(raw, q);
            boolean capMsd = (outer == 0x80);
            if (capMsd != msd) {
                tap("-- msd field=" + msd + " wins over captured framing=" + capMsd);
            } else {
                tap("-- msd " + msd + " agrees with the capture");
            }
        }

        byte[] aip = capturedAip(raw);
        if (aip == null || aip.length < 2) aip = hex(p("aip", DEFAULT_AIP));
        if (aip.length < 2) aip = hex(DEFAULT_AIP);

        byte[] masked = new byte[]{(byte) (aip[0] & AIP_ODA_MASK), aip[1]};
        if (msd) masked[1] &= (byte) ~AIP_EMV_MODE;
        else     masked[1] |= AIP_EMV_MODE;
        txnAip = masked;

        byte[] a = afl();
        tap("-- gpo msd=" + msd + " aip=" + bytesToHex(masked) + " afl=" + bytesToHex(a));

        if (msd) {
            byte[] payload = cat(masked, tlv(0x57, track2()));
            tap("-- msd payload: 80" + String.format("%02X", payload.length) + bytesToHex(payload));
            return cat(tlv(0x80, payload), SW_OK);
        }
        return cat(tlv(0x77, cat(tlv(0x82, masked), tlv(0x94, a))), SW_OK);
    }

    /**
     * FIX: the format 1 branch used raw[2] and raw[3], which is only right for a
     * short-form length. A long-form payload (0x81 xx) put the AIP two bytes
     * further along, so the AIP came out as the length byte plus the real AIP[0].
     */
    private byte[] capturedAip(byte[] raw) {
        if (raw == null || raw.length < 4) return null;
        int[] pos = new int[1];
        int outer = readTag(raw, pos);
        if (outer == 0x80) {
            int l = readLen(raw, pos);
            if (l >= 2 && pos[0] + 2 <= raw.length) {
                return Arrays.copyOfRange(raw, pos[0], pos[0] + 2);
            }
            return null;
        }
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

        byte cid;
        if (ALWAYS_ONLINE_FOR_RECEIPT && !cryptogramSent) {
            cid = CID_ARQC;
        } else if (cryptogramSent) {
            cid = CID_TC;
        } else if (haveKey() && FORCE_ONLINE_ARQC) {
            cid = CID_ARQC;
        } else if (FORCE_OFFLINE_TC) {
            cid = CID_TC;
        } else if (requested == 0x80) {
            cid = CID_ARQC;
        } else if (requested == 0x40) {
            cid = CID_TC;
        } else if (requested == 0x00) {
            cid = CID_AAC;
        } else {
            cid = CID_TC;
        }

        String atc = txnAtc();

        byte[] cdol = new byte[0];
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (lc > 0 && apdu.length >= off + lc) {
            cdol = Arrays.copyOfRange(apdu, off, off + lc);
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
            return EmvCrypto.arqc(mk, pan(), psn(), atc, macIn, variant & 1);
        } catch (Exception e) {
            tap("!! ARQC failed: " + e);
            return new byte[8];
        }
    }

    private byte[] getData(byte[] apdu) {
        int tag = ((apdu[2] & 0xFF) << 8) | (apdu[3] & 0xFF);

        if (tag == 0x9F36)      return cat(tlv(0x9F36, hex(txnAtc())), SW_OK);
        else if (tag == 0x9F13) return cat(tlv(0x9F13, hex("00")), SW_OK);
        else if (tag == 0x9F17) return cat(tlv(0x9F17, hex("00")), SW_OK);
        return SW_BAD;
    }

    private static int countOf(String hay, String needle) {
        int n = 0, i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) { n++; i += needle.length(); }
        return n;
    }

    private String baseVerdict() {
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

        if (isMsd()) {
            if (gens == 0)              return "TAP: MSD mode - terminal took the track 2 and decided on its own";
            if (gens >= 2)              return "TAP: MSD mode - terminal WENT ONLINE";
            if (l.contains("9F270140")) return "TAP: MSD mode - we answered TC, terminal should APPROVE";
            if (l.contains("9F270180")) return "TAP: MSD mode - we answered ARQC, terminal must go online";
            if (l.contains("9F270100")) return "TAP: MSD mode - we answered AAC, terminal read it as a decline";
            return "TAP: MSD mode - terminal asked for a cryptogram and we did not answer TC";
        }

        if (recs == 0)    return "TAP: terminal started a transaction but read no records - check the logged AFL";
        if (gens == 0)    return "TAP: terminal read " + recs
                + " records then quit before the cryptogram - its own ODA or CVM check failed";
        if (gens >= 2)    return "TAP: terminal WENT ONLINE - the issuer judged our ARQC";
        if (l.contains("9F270140")) return "TAP: we answered TC - terminal should have APPROVED offline";
        if (l.contains("9F270180")) return "TAP: we answered ARQC - terminal must go online";
        if (l.contains("9F270100")) return "TAP: we answered AAC - terminal treated it as an offline decline";
        return "TAP: terminal asked for a cryptogram and we did not answer TC";
    }

    private String verdict() {
        String v = baseVerdict();
        int armed = scriptLines();
        if (scriptHits > 0) return v + " | script hit " + scriptHits + "x";
        if (armed > 0) return v + " | script armed " + armed + " line(s) but never matched";
        return v;
    }

    /**
     * FIX: verdict() was computed AFTER resetTransaction(), which zeroes
     * scriptHits - so the "script hit Nx" suffix could never appear. The verdict
     * is now taken while the tap counters are still live.
     */
    @Override
    public void onDeactivated(int reason) {
        final String t = tapLog.toString();
        final String v = verdict();
        resetTransaction();

        if (!t.isEmpty()) {
            try {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("tap log", t));
            } catch (Exception ignored) { }
            try {
                prefs().edit().putString("taplog", t).putString("lastverdict", v).apply();
            } catch (Exception ignored) { }
            popup(v);
        }
        Log.d(TAG, "onDeactivated reason=" + reason + " | " + v);
    }
}
