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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;

public class HceCcEmulationServiceVisa extends HostApduService {

    private static final String TAG = "HCE";

    private static final byte[] SW_OK          = hex("9000");
    private static final byte[] SW_BAD         = hex("6A82");
    private static final byte[] SW_UNSUPPORTED = hex("6D00");
    private static final byte[] SW_MALFORMED   = hex("6700");
    private static final byte[] SW_NO_RECORD   = hex("6A83");
    private static final byte[] SW_NOT_FOUND   = hex("6A88");
    private static final byte[] SW_ERR         = hex("6F00");
    private static final byte[] PPSE           = hex("325041592E5359532E4444463031");

    /**
     * Placeholder written to 9F26 when no MK-AC is set and no ARQC was computed.
     *
     * Eight zeros read as a plausible MAC. Eight FF bytes read as "absent" -
     * they are what a card that cannot do crypto would look like, and they are
     * visible at a glance in a log.
     */
    private static final String AC_FILLER = "FFFFFFFFFFFFFFFF";

    /** 0x40 SDA  0x20 DDA  0x01 CDA  0x10 CV  0x08 TRM  0x04 issuer auth */
    private static final String DEFAULT_AIP = "1080";

    /** Keep-mask for aipForMac()'s no-GPO fallback only. */
    private static final byte AIP_KEEP_MASK = (byte) 0x18;

    /** AIP byte 1 bit 1 - CDA. A clone cannot honour it, so gpo() clears it. */
    private static final byte AIP_CDA = (byte) 0x01;

    /** AIP byte 1 bit 5 - CV. Parked; clearing it made the terminal bail. */
    private static final byte AIP_CVM = (byte) 0x10;

    /**
     * false - keep the card's own AC tags. This terminal takes the AC from the
     * GPO and never sends GENERATE AC, so stripping leaves it nothing.
     */
    private static final boolean STRIP_AC = false;

    private static final int[] GPO_AC_TAGS = {0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F71};

    /** Only affects the generated directory; a capture is replayed verbatim. */
    private static final boolean EXTRA_AIDS = false;

    private static final byte CID_AAC  = (byte) 0x00;
    private static final byte CID_TC   = (byte) 0x40;
    private static final byte CID_ARQC = (byte) 0x80;

    /** CID written into a captured GPO. 40 = TC, approve offline. */
    private static final byte GPO_CID = CID_TC;

    private static final boolean ALWAYS_ONLINE_FOR_RECEIPT = false;
    private static final boolean FORCE_ONLINE_ARQC = true;
    private static final boolean FORCE_OFFLINE_TC = true;

    private static final String PDOL    = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL1   = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL2   = "9F02069F03069F1A0295055F2A029A039C019F37049F3403";

    private static final String CVMLIST = "00000000000000001F00";

    private static final String DEFAULT_SCRIPT =
            "# match=response, hex only. Longest match wins.\n"
          + "# 80A80000=770A82021080940408010100 9000\n"
          + "# 00B2010C=70265A0860114994320077045F24033112318C149F02069F03069F1A0295055F2A029A039C019F3704 9000\n";

    private final StringBuilder tapLog = new StringBuilder();
    private final Random rnd = new Random();

    /** Serialises the two APDU entry points - two taps can overlap. */
    private final Object txnLock = new Object();

    private byte[] txnAip;
    private String txnAtc;
    private boolean cryptogramSent;
    private int scriptHits;

    private byte[] capturedIad;
    private String gpoCid = "";

    private boolean sawPpse;
    private int nSelects, nGpos, nRecs, nGens;
    private String lastCid = "";

    private boolean sawError;

    /**
     * NEW. Whether 9F26 holds a real MAC or AC_FILLER. Nothing else in the app
     * distinguishes "computed" from "absent", and the difference decides whether
     * going online can possibly succeed.
     */
    private boolean acComputed;

    private String lastSelAid = "";
    private int nSelMiss;
    private int nApps;
    private int aflEntries;
    private int reqGenP1 = -1;

    private static final String TERM_LOG = "term_log.txt";

    /** One worker for all file logging - see termLog(). */
    private static final java.util.concurrent.ExecutorService LOGQ =
            java.util.concurrent.Executors.newSingleThreadExecutor();

    /**
     * Appends a line to the on-device terminal log, off the APDU thread.
     *
     * This used to open, write and close a FileWriter inline on every APDU, and
     * one APDU in sixty also read 30 KB, truncated and rewrote the file. The
     * per-APDU budget is a few hundred milliseconds before the terminal gives
     * up, and the trim path alone can spend all of it - the symptom looks like a
     * bad antenna.
     */
    private void termLog(final String s) {
        LOGQ.execute(() -> {
            try {
                java.io.File f = new java.io.File(getExternalFilesDir(null), TERM_LOG);
                java.io.FileWriter w = new java.io.FileWriter(f, true);
                w.write(s + "\n");
                w.close();

                if (f.length() > 60000) {
                    long keep = 30000;
                    byte[] buf = new byte[(int) keep];
                    java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "rw");
                    raf.seek(f.length() - keep);
                    raf.readFully(buf);
                    raf.setLength(0);
                    raf.write(buf);
                    raf.close();
                }
            } catch (Throwable ignored) { }
        });
    }

    private void tap(String s) {
        tapLog.append(s).append('\n');
        if (tapLog.length() > 32000) tapLog.delete(0, 16000);
        termLog(s);
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
    static byte[] cat(byte[]... arrs) { return Tlv.cat(arrs); }
    private static String bytesToHex(byte[] d) { return Hex.toHex(d); }

    /** Local TLV writer with proper long-form lengths. See patchFci(). */
    static byte[] tlv(int tag, byte[] v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if ((tag & 0xFF00) != 0) {
            o.write((tag >> 8) & 0xFF);
            o.write(tag & 0xFF);
        } else {
            o.write(tag & 0xFF);
        }
        int n = v.length;
        if (n < 0x80) {
            o.write(n);
        } else if (n <= 0xFF) {
            o.write(0x81);
            o.write(n);
        } else if (n <= 0xFFFF) {
            o.write(0x82);
            o.write((n >> 8) & 0xFF);
            o.write(n & 0xFF);
        } else {
            o.write(0x83);
            o.write((n >> 16) & 0xFF);
            o.write((n >> 8) & 0xFF);
            o.write(n & 0xFF);
        }
        o.write(v, 0, n);
        return o.toByteArray();
    }

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

    /** Lc of an incoming APDU, extended length included. */
    private static int lcOf(byte[] apdu) {
        if (apdu.length < 5) return 0;
        int lc = apdu[4] & 0xFF;
        if (lc != 0x00) return lc;
        if (apdu.length < 7) return 0;
        return ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
    }

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

    private String labelText() {
        String s = p("label", p("cap_label", "CARD"));
        return s.length() > 16 ? s.substring(0, 16) : s;
    }

    /** The card's own AID, capture first - one helper, so nothing disagrees. */
    private String cardAid() {
        String a = p("cap_aid", "");
        if (a.isEmpty()) a = p("aid", "");
        return a;
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
        sawPpse = false;
        nSelects = nGpos = nRecs = nGens = 0;
        lastCid = "";
        sawError = false;
        capturedIad = null;
        gpoCid = "";

        acComputed = false;
        lastSelAid = "";
        nSelMiss = 0;
        nApps = 0;
        aflEntries = 0;
        reqGenP1 = -1;
    }

    private byte[] aipForMac() {
        byte[] a = txnAip;
        if (a == null) {
            a = hex(p("aip", DEFAULT_AIP));
            if (a.length >= 2) a = new byte[]{(byte) (a[0] & AIP_KEEP_MASK), a[1]};
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

    private byte[] rawPpse() { return cap("rawppse"); }
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

    /** 'usescript' is written with putInt but read here as an Object. */
    private boolean useScript() {
        Object o = prefs().getAll().get(sel() + "usescript");
        if (o instanceof Number) return ((Number) o).intValue() != 0;
        if (o == null) return false;
        String v = o.toString().trim();
        return v.equals("1") || v.equalsIgnoreCase("true") || v.equalsIgnoreCase("on");
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
        String realAid = cardAid();
        if (realAid.isEmpty()) realAid = "A0000000031010";

        String lbl = labelText();

        ByteArrayOutputStream dir = new ByteArrayOutputStream();

        byte[] e0 = tlv(0x61, appEntry(realAid, lbl, 1));
        dir.write(e0, 0, e0.length);

        if (EXTRA_AIDS) {
            if (!realAid.equalsIgnoreCase("A0000000031010")) {
                byte[] e = tlv(0x61, appEntry("A0000000031010", "VISA", 2));
                dir.write(e, 0, e.length);
            }
            if (!realAid.equalsIgnoreCase("A0000000041010")) {
                byte[] e = tlv(0x61, appEntry("A0000000041010", "MASTERCARD", 3));
                dir.write(e, 0, e.length);
            }
        }

        byte[] fci = tlv(0xBF0C, dir.toByteArray());
        byte[] inner = cat(tlv(0x84, PPSE), tlv(0xA5, fci));
        return tlv(0x6F, inner);
    }

    /** Replay a captured directory, correcting only the 84 to the PPSE name. */
    private byte[] patchPpse(byte[] ppse) {
        int[] pos = new int[1];
        int outer = readTag(ppse, pos);
        int olen = readLen(ppse, pos);
        int end = Math.min(ppse.length, pos[0] + olen);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        boolean saw84 = false;
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(ppse, q);
            int l = readLen(ppse, q);
            if (q[0] + l > ppse.length) break;
            byte[] v = Arrays.copyOfRange(ppse, q[0], q[0] + l);
            i = q[0] + l;
            if (t == 0x84) { v = PPSE; saw84 = true; }
            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }

        byte[] inner = out.toByteArray();
        if (!saw84) inner = cat(tlv(0x84, PPSE), inner);
        return tlv(outer == 0 ? 0x6F : outer, inner);
    }

    /** 61 entries in a directory FCI - how many applets the terminal is offered. */
    private static int countApps(byte[] fci) {
        if (fci == null) return 0;
        int n = 0;
        int[] pos = new int[1];
        int outer = readTag(fci, pos);
        int olen = readLen(fci, pos);
        int end = Math.min(fci.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(fci, q);
            int l = readLen(fci, q);
            if (q[0] + l > fci.length) break;
            if (t == 0xA5) {
                int j = q[0], e2 = Math.min(fci.length, q[0] + l);
                while (j < e2) {
                    int[] r = new int[]{j};
                    int t2 = readTag(fci, r);
                    int l2 = readLen(fci, r);
                    if (r[0] + l2 > fci.length) break;
                    if (t2 == 0xBF0C) {
                        int k = r[0], e3 = Math.min(fci.length, r[0] + l2);
                        while (k < e3) {
                            int[] s = new int[]{k};
                            int t3 = readTag(fci, s);
                            int l3 = readLen(fci, s);
                            if (s[0] + l3 > fci.length) break;
                            if (t3 == 0x61) n++;
                            k = s[0] + l3;
                        }
                    }
                    j = r[0] + l2;
                }
            }
            i = q[0] + l;
        }
        return n;
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

    /** Rebuilds the proprietary template in tag order, keeping duplicates. */
    private byte[] patchA5(byte[] a5, byte[] aid) {
        TreeMap<Integer, List<byte[]>> tags = new TreeMap<>();
        int i = 0;
        while (i < a5.length) {
            int[] q = new int[]{i};
            int t = readTag(a5, q);
            int l = readLen(a5, q);
            if (q[0] + l > a5.length) break;
            List<byte[]> list = tags.get(t);
            if (list == null) { list = new ArrayList<>(); tags.put(t, list); }
            list.add(Arrays.copyOfRange(a5, q[0], q[0] + l));
            i = q[0] + l;
        }

        List<byte[]> k = tags.get(0x9F2A);
        if (k == null) { k = new ArrayList<>(); tags.put(0x9F2A, k); }
        if (k.isEmpty()) k.add(new byte[]{(byte) kernelFor(bytesToHex(aid))});

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, List<byte[]>> e : tags.entrySet())
            for (byte[] v : e.getValue()) {
                byte[] one = tlv(e.getKey(), v);
                out.write(one, 0, one.length);
            }
        return out.toByteArray();
    }

    private byte[] afl() {
        String typed = p("afl", "").replaceAll("[^0-9A-Fa-f]", "");
        if (typed.length() >= 8 && typed.length() % 8 == 0) {
            tap("-- afl source: typed");
            aflEntries = typed.length() / 8;
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
        aflEntries = out.size() / 4;
        return out.toByteArray();
    }

    private static void aflEntry(ByteArrayOutputStream out, int sfi, int first, int last) {
        out.write((sfi << 3) & 0xFF);
        out.write(first & 0xFF);
        out.write(last & 0xFF);
        out.write(0x00);
    }

    private String expiry6() {
        String d = p("expiry", "3112").replaceAll("[^0-9]", "");
        if (d.length() >= 6) return d.substring(0, 6);
        if (d.length() == 5) return d.substring(0, 4) + "01";
        if (d.length() == 4) return d + "01";
        if (d.length() == 2) {
            String yy = String.format("%02d", Calendar.getInstance().get(Calendar.YEAR) % 100);
            int v = Integer.parseInt(d);
            if (v >= 1 && v <= 12) return yy + d + "01";
            return d + "0101";
        }
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
        String panS = pan();
        String expS = expiry6();
        String psnS = psn();
        if (panS.length() % 2 != 0) panS += "F";

        byte[] h = holder();

        return tlv(0x70, cat(
                tlv(0x5A, hex(panS)),
                tlv(0x5F34, hex(psnS)),
                tlv(0x5F24, hex(expS)),
                h == null ? new byte[0] : tlv(0x5F20, h),
                tlv(0x57, track2()),
                tlv(0x8C, hex(CDOL1)),
                tlv(0x8D, hex(CDOL2)),
                tlv(0x8E, hex(CVMLIST))));
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        synchronized (txnLock) {
            try {
                if (apdu == null || apdu.length < 4) return SW_MALFORMED;

                int ins = apdu[1] & 0xFF;
                int p1  = apdu[2] & 0xFF;
                int p2  = apdu[3] & 0xFF;

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
                            sawPpse = true;
                            termLog("=== tap "
                                    + new java.text.SimpleDateFormat("HH:mm:ss",
                                            java.util.Locale.US).format(new java.util.Date())
                                    + " ===");
                            int n = scriptLines();
                            if (n > 0) {
                                tap("-- script armed: " + n + " line(s), gate="
                                        + (useScript() ? "ON" : "OFF"));
                            }
                            popup(nameLine());
                        }
                    }
                }

                tap(">> " + bytesToHex(apdu));

                if (isSelect)         nSelects++;
                else if (ins == 0xA8) nGpos++;
                else if (ins == 0xB2) nRecs++;
                else if (ins == 0xAE) nGens++;

                String hit = useScript() ? scriptMatch(apdu) : null;
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
                        byte[] sa = capturedAip(out);
                        if (sa != null && sa.length >= 2) {
                            txnAip = sa;
                            tap("-- script GPO AIP parked for the MAC: " + bytesToHex(sa));
                        }
                        tap("-- script served the GPO - MSD/AIP/AFL come from the script, not the card");
                    }
                    tap("-- script hit " + out.length + " bytes");
                    tap("<< " + bytesToHex(out));
                    return out;
                }

                byte[] out;
                if (isSelect) {
                    if (apdu.length < dataOff(apdu)) return SW_MALFORMED;
                    out = select(apdu);
                } else if (ins == 0xA8) {
                    out = gpo();
                } else if (ins == 0xB2) {
                    out = readRecord(p1, p2);
                } else if (ins == 0xAE) {
                    reqGenP1 = p1;
                    out = genac(apdu);
                } else if (ins == 0xCA) {
                    out = getData(apdu);
                } else if (ins == 0x20) {
                    out = SW_OK;
                } else if (ins == 0x84) {
                    byte[] ch = new byte[8];
                    rnd.nextBytes(ch);
                    out = cat(ch, SW_OK);
                } else {
                    out = SW_UNSUPPORTED;
                }

                tap("<< " + bytesToHex(out));
                return out;
            } catch (Exception e) {
                sawError = true;
                tap("!! " + e);
                return SW_ERR;
            }
        }
    }

    private byte[] select(byte[] apdu) {
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (apdu.length < off + lc) return SW_MALFORMED;
        byte[] name = new byte[lc];
        System.arraycopy(apdu, off, name, 0, lc);

        if (Arrays.equals(name, PPSE)) {
            byte[] capPpse = rawPpse();
            byte[] fci;
            if (capPpse != null && capPpse.length > 8) {
                tap("-- ppse source: captured " + capPpse.length + "B");
                fci = patchPpse(capPpse);
            } else {
                tap("-- ppse source: generated");
                fci = buildPpse();
            }
            nApps = countApps(fci);
            tap("-- directory offers " + nApps + " applet(s)");
            return cat(fci, SW_OK);
        }

        if (name.length == 0) {
            String a = cardAid();
            if (a.isEmpty()) a = "A0000000031010";
            name = hex(a);
        }

        String real = cardAid();
        String picked = bytesToHex(name);
        lastSelAid = picked;

        tap("-- selected " + picked + " | card is " + (real.isEmpty() ? "?" : real));

        boolean match = real.length() > 0 && picked.equalsIgnoreCase(real);
        if (!match && real.length() > 0) {
            nSelMiss++;
            tap("-- AID MISMATCH: terminal picked an AID the card is not");
        }

        byte[] captured = rawFci();
        if (captured != null && match) {
            tap("-- fci source: captured " + captured.length + "B");
            return cat(patchFci(captured, name), SW_OK);
        }
        if (captured != null) {
            tap("-- fci source: generated (capture is for " + real + ")");
        } else {
            tap("-- fci source: generated");
        }

        String label = labelText();
        byte[] prop = cat(
                tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{0x01}),
                tlv(0x9F11, new byte[]{0x01}),
                tlv(0x9F12, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x9F2A, new byte[]{(byte) kernelFor(picked)}),
                tlv(0x9F38, hex(PDOL)));
        byte[] inner = cat(tlv(0x84, name), tlv(0xA5, prop));
        return cat(tlv(0x6F, inner), SW_OK);
    }

    /**
     * Replay the captured GPO with the CDA bit cleared and the CID rewritten to
     * TC. This terminal takes the AC from the GPO and never sends GENERATE AC,
     * and the captured ARQC was computed over someone else's unpredictable
     * number - so it would go online and be judged on a MAC the host never
     * issued.
     */
    private byte[] gpo() {
        byte[] raw = rawGpo();
        boolean msd = isMsd();

        if (raw != null && raw.length >= 4) {
            int[] q = new int[1];
            int outer = readTag(raw, q);
            int olen  = readLen(raw, q);

            if (q[0] + olen + 2 == raw.length
                    && (raw[raw.length - 2] & 0xFF) == 0x90
                    && (raw[raw.length - 1] & 0xFF) == 0x00) {
                raw = Arrays.copyOf(raw, raw.length - 2);
            }

            boolean capMsd = (outer == 0x80);

            if (capMsd == msd) {
                byte[] aip = capturedAip(raw);
                if (aip != null && aip.length >= 2) {
                    capturedIad = findTag(raw, 0x9F10);

                    weakenAip(raw);

                    boolean cidForced = false;
                    if (STRIP_AC) {
                        raw = stripAcTags(raw);
                        gpoCid = "(stripped)";
                    } else {
                        byte[] forced = forceCid(raw, GPO_CID);
                        if (forced != null) {
                            raw = forced;
                            cidForced = true;
                            gpoCid = String.format("%02X", GPO_CID & 0xFF);
                        } else {
                            gpoCid = "";
                        }
                    }

                    txnAip = capturedAip(raw);
                    tap("-- gpo replay aip=" + bytesToHex(txnAip)
                            + " (CDA dropped, "
                            + (STRIP_AC ? "AC tags stripped"
                               : cidForced ? "cid forced to " + gpoCid
                               : "no cid in capture - left as-is")
                            + ") len=" + raw.length
                            + (capturedIad == null ? "" : " iadKept=" + bytesToHex(capturedIad)));
                } else {
                    tap("-- gpo replay verbatim len=" + raw.length);
                }
                return cat(raw, SW_OK);
            }
            tap("-- msd field=" + msd + " wins over captured framing=" + capMsd);
        }

        byte[] aip = capturedAip(raw);
        if (aip == null || aip.length < 2) aip = hex(p("aip", DEFAULT_AIP));
        if (aip.length < 2) aip = hex(DEFAULT_AIP);

        byte[] used = new byte[]{aip[0], aip[1]};
        used[0] &= (byte) ~AIP_CDA;
        txnAip = used;

        byte[] a = afl();
        tap("-- gpo msd=" + msd + " aip=" + bytesToHex(used) + " afl=" + bytesToHex(a)
                + " entries=" + aflEntries);

        if (msd) {
            byte[] payload = cat(used, tlv(0x57, track2()));
            tap("-- msd payload: 80" + String.format("%02X", payload.length) + bytesToHex(payload));
            return cat(tlv(0x80, payload), SW_OK);
        }
        return cat(tlv(0x77, cat(tlv(0x82, used), tlv(0x94, a))), SW_OK);
    }

    private static void weakenAip(byte[] tpl) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        readLen(tpl, pos);

        if (outer == 0x80) {
            if (pos[0] + 2 <= tpl.length) tpl[pos[0]] &= (byte) ~AIP_CDA;
            return;
        }

        int i = pos[0];
        while (i < tpl.length) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) return;
            if (t == 0x82 && l >= 1) {
                tpl[q[0]] &= (byte) ~AIP_CDA;
                return;
            }
            i = q[0] + l;
        }
    }

    /** Returns null when the template carries no 9F27 - caller leaves it alone. */
    private static byte[] forceCid(byte[] tpl, byte cid) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        int olen  = readLen(tpl, pos);
        int end   = Math.min(tpl.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == 0x9F27 && l >= 1) {
                tpl[q[0]] = cid;
                return tpl;
            }
            i = q[0] + l;
        }
        return null;
    }

    private static byte[] stripAcTags(byte[] tpl) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        int olen  = readLen(tpl, pos);
        int end   = Math.min(tpl.length, pos[0] + olen);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        if (outer == 0x80) {
            if (end - pos[0] < 2) return tpl;
            out.write(tpl, pos[0], 2);
            pos[0] += 2;
        }

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            i = q[0] + l;

            boolean drop = false;
            for (int d : GPO_AC_TAGS) if (d == t) { drop = true; break; }
            if (drop) continue;

            byte[] one = tlv(t, Arrays.copyOfRange(tpl, q[0], q[0] + l));
            out.write(one, 0, one.length);
        }
        return tlv(outer, out.toByteArray());
    }

    private static byte[] findTag(byte[] tpl, int want) {
        if (tpl == null || tpl.length < 4) return null;
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        if (outer == 0x80) return null;
        int olen = readLen(tpl, pos);
        int end  = Math.min(tpl.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == want) return Arrays.copyOfRange(tpl, q[0], q[0] + l);
            i = q[0] + l;
        }
        return null;
    }

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

    /**
     * The CID box wins only when it can back the value up.
     *
     * CHANGED. It used to win whenever it held two hex digits, so a leftover
     * "80" from an earlier card pinned every tap to ARQC - the terminal went
     * online, and with no MK-AC the host judged eight zeros and declined. The
     * card looked broken for an EMV reason when it was a stale pref.
     *
     *   00  AAC - honest in every state, always honoured
     *   40  TC  - honest in every state, always honoured
     *   80  ARQC - only honoured when there is a key to compute with, otherwise
     *              the flags decide and the log says the box was ignored
     */
    private byte[] genac(byte[] apdu) {
        int p1 = apdu[2] & 0xFF;
        int requested = p1 & 0xC0;

        String forced = p("cid", "").replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        boolean forcedOk = false;
        byte forcedCid = 0;

        if (forced.length() == 2) {
            byte f = (byte) Integer.parseInt(forced, 16);
            if (f == CID_AAC || f == CID_TC) {
                forcedOk = true;
                forcedCid = f;
            } else if (f == CID_ARQC && haveKey()) {
                forcedOk = true;
                forcedCid = f;
            } else {
                tap("-- cid box says " + forced
                        + " but there is no MK-AC to compute with - ignored, logic decides");
            }
        }

        byte cid;
        if (cryptogramSent) {
            cid = (requested == 0x00) ? CID_AAC : CID_TC;
        } else if (requested == 0x00) {
            cid = CID_AAC;
        } else if (forcedOk) {
            cid = forcedCid;
        } else if (ALWAYS_ONLINE_FOR_RECEIPT) {
            cid = CID_ARQC;
        } else if (haveKey() && FORCE_ONLINE_ARQC) {
            cid = CID_ARQC;
        } else if (FORCE_OFFLINE_TC) {
            cid = CID_TC;
        } else if (requested == 0x80) {
            cid = CID_ARQC;
        } else if (requested == 0x40) {
            cid = CID_TC;
        } else {
            cid = CID_TC;
        }

        lastCid = String.format("%02X", cid);
        String atc = txnAtc();

        byte[] cdol = new byte[0];
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (lc > 0 && apdu.length >= off + lc) {
            cdol = Arrays.copyOfRange(apdu, off, off + lc);
        }

        byte[] ac = computeAc(atc, cdol);
        cryptogramSent = true;

        String iad = (capturedIad == null)
                ? p("iad", "06010A03A0B800")
                : bytesToHex(capturedIad);

        tap("-- genac requested=" + String.format("%02X", requested)
                + " cid=" + lastCid
                + (forcedOk ? " (forced from the CID box)" : "")
                + " atc=" + atc + " arqc=" + bytesToHex(ac)
                + (acComputed ? "" : " FILLER"));

        return cat(tlv(0x77, cat(
                tlv(0x9F27, new byte[]{cid}),
                tlv(0x9F36, hex(atc)),
                tlv(0x9F26, ac),
                tlv(0x9F10, hex(iad)))), SW_OK);
    }

    /**
     * ARQC, or AC_FILLER when there is no key.
     *
     * CHANGED. It returned eight zeros, which read as a plausible MAC. Eight FF
     * bytes read as absent, and the flag lets the verdict say so.
     */
    private byte[] computeAc(String atc, byte[] cdol) {
        String mk = p("mkac", "").replaceAll("[^0-9A-Fa-f]", "");
        if (mk.length() < 32) {
            acComputed = false;
            tap("!! no MK-AC set - 9F26 is FILLER (" + AC_FILLER + "), not a real ARQC");
            return hex(AC_FILLER);
        }
        int variant = 0;
        try {
            String kv = p("keyvar", "0").replaceAll("[^0-9A-Fa-f]", "");
            if (!kv.isEmpty()) {
                variant = kv.matches("[0-9]+")
                        ? Integer.parseInt(kv)
                        : Integer.parseInt(kv, 16);
            }
        } catch (Exception ignored) { }
        variant &= 0x03;

        try {
            byte[] macIn = ((variant & 2) != 0)
                    ? cat(aipForMac(), hex(atc), cdol)
                    : cat(cdol, aipForMac(), hex(atc));
            byte[] ac = EmvCrypto.arqc(mk, pan(), psn(), atc, macIn, variant & 1);
            acComputed = true;
            return ac;
        } catch (Exception e) {
            acComputed = false;
            tap("!! ARQC failed (" + e + ") - 9F26 is FILLER");
            return hex(AC_FILLER);
        }
    }

    private byte[] getData(byte[] apdu) {
        int tag = ((apdu[2] & 0xFF) << 8) | (apdu[3] & 0xFF);

        if (tag == 0x9F36)      return cat(tlv(0x9F36, hex(txnAtc())), SW_OK);
        else if (tag == 0x9F13) return cat(tlv(0x9F13, hex("00")), SW_OK);
        else if (tag == 0x9F17) return cat(tlv(0x9F17, hex("00")), SW_OK);
        else if (tag == 0x9F4F) return cat(tlv(0x9F4F, hex("9F4D020B0A")), SW_OK);
        return SW_NOT_FOUND;
    }

    /**
     * Built from counters, not from searching the log text. Order: did it read
     * us at all, did it pick anything, did it pick US, did it get past the FCI,
     * did it read the records it was pointed at.
     */
    private String baseVerdict() {
        if (sawError)     return "TAP: an APDU threw - read the !! line above, not the AID list";
        if (tapLog.length() == 0) return "TAP: nothing recorded - the phone was never read";

        if (!sawPpse)     return "TAP: terminal never asked for the directory - it never read the phone";

        if (nSelects <= 1) {
            return "TAP: terminal read the directory and picked NOTHING - "
                    + (nApps > 0
                        ? nApps + " applet(s) offered, it supports none of them"
                        : "the directory came back empty");
        }

        if (nGpos == 0) {
            String picked = lastSelAid.isEmpty() ? "?" : lastSelAid;
            if (nSelMiss > 0) {
                return "TAP: terminal selected " + picked + ", which is NOT the card ("
                        + (cardAid().isEmpty() ? "?" : cardAid())
                        + ") - it read the FCI for an applet we do not hold and stopped";
            }
            return "TAP: terminal selected " + picked + " then stopped before the GPO -"
                    + " it rejected the FCI";
        }

        if (isMsd()) {
            if (nGens == 0)          return "TAP: MSD mode - terminal took the track 2 and decided on its own";
            if (nGens >= 2)          return "TAP: MSD mode - terminal WENT ONLINE"
                    + (acComputed ? "" : " with a FILLER cryptogram - the host will decline it");
            if ("40".equals(lastCid)) return "TAP: MSD mode - we answered TC, terminal should APPROVE";
            if ("80".equals(lastCid)) return "TAP: MSD mode - we answered ARQC, terminal must go online";
            if ("00".equals(lastCid)) return "TAP: MSD mode - we answered AAC, terminal read it as a decline";
            return "TAP: MSD mode - terminal asked for a cryptogram and we did not answer TC";
        }

        if (nRecs == 0) {
            return "TAP: terminal took the GPO response and read NO records - "
                    + (gpoCid.isEmpty()
                        ? "check the logged AFL"
                        : "the AC in the GPO (cid " + gpoCid + ") did not satisfy it");
        }

        if (aflEntries > 0 && nRecs < aflEntries) {
            return "TAP: AFL pointed at " + aflEntries + " record(s) and only " + nRecs
                    + " were read - it gave up mid-read, so one of the records it did read"
                    + " was wrong";
        }

        if (nGens == 0 && !gpoCid.isEmpty()) {
            return "TAP: terminal read " + nRecs + " records and never sent GENERATE AC -"
                    + " the AC came out of the GPO response (cid " + gpoCid
                    + ") so it went online with it rather than asking us";
        }

        if (nGens == 0)   return "TAP: terminal read " + nRecs + " records then quit before the cryptogram";

        if (nGens >= 2) {
            return "TAP: terminal WENT ONLINE - the issuer judged our ARQC"
                    + (acComputed ? " (a real one)" : " (FILLER, no MK-AC - will decline)");
        }

        String p1s = reqGenP1 < 0 ? "?" : String.format("%02X", reqGenP1 & 0xC0);
        if ("40".equals(lastCid)) return "TAP: we answered TC to a " + p1s + " request - terminal should have APPROVED offline";
        if ("80".equals(lastCid)) return "TAP: we answered ARQC - terminal must go online";
        if ("00".equals(lastCid)) return "TAP: we answered AAC - terminal treated it as an offline decline";
        return "TAP: terminal asked for a cryptogram and we did not answer TC";
    }

    private String verdict() {
        String v = baseVerdict();
        int armed = scriptLines();
        if (armed == 0) return v;
        if (!useScript()) return v + " | script armed " + armed + " line(s) but OFF";
        if (scriptHits > 0) return v + " | script hit " + scriptHits + "x";
        return v + " | script armed " + armed + " line(s) but never matched";
    }

    @Override
    public void onDeactivated(int reason) {
        synchronized (txnLock) {
            final String t = tapLog.toString();

            String v;
            try {
                v = verdict();
            } catch (Exception e) {
                v = "TAP: verdict failed - " + e;
            }
            resetTransaction();

            if (!t.isEmpty()) termLog("!! verdict: " + v);

            if (!t.isEmpty()) {
                try {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("tap log", t));
                } catch (Exception ignored) { }
                try {
                    prefs().edit()
                            .putString("taplog", t)
                            .putString("lastverdict", v)
                            .putLong("lastverdict_at", System.currentTimeMillis())
                            .apply();
                } catch (Exception ignored) { }
                popup(v);
            }
            Log.d(TAG, "onDeactivated reason=" + reason + " | " + v);
        }
    }
}
