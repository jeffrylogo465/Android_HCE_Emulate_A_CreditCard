package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Pulls the offline-data-authentication chain out of a captured TLV blob: the
 * concatenation of a SELECT FCI, a GPO response and the READ RECORD responses,
 * in whatever order a terminal log holds them. Pure Java, no Android types.
 *
 * Every tag it reports is read straight out of the blob; nothing here supplies
 * a default or treats one tag as a stand-in for another (8F missing is an
 * error, never a fallback to 92 or anywhere else).
 *
 * Record attribution: a 70-tagged template found anywhere in the blob is
 * treated as one READ RECORD response and consumed, in encounter order, to
 * fill the (SFI, record) slots the AFL names, in AFL order. This assumes the
 * dump holds the records in that order, which is how a real terminal log
 * reads them; it is not re-derived from any marker inside the template, since
 * none exists in the wire bytes themselves.
 */
public final class DumpChain {

    public static final class Result {
        public final boolean ok;
        public final String error;
        public final DumpChain chain;

        private Result(boolean ok, String error, DumpChain chain) {
            this.ok = ok;
            this.error = error;
            this.chain = chain;
        }

        static Result fail(String msg) { return new Result(false, msg, null); }
        static Result ok(DumpChain c) { return new Result(true, null, c); }

        @Override
        public String toString() { return ok ? "OK" : "error: " + error; }
    }

    public final int caIndex;              // 8F
    public final byte[] issuerCert;        // 90
    public final byte[] issuerRemainder;   // 92, empty when absent
    public final byte[] issuerExponent;    // 9F32
    public final byte[] iccCert;           // 9F46, null when absent
    public final byte[] iccExponent;       // 9F47, null when absent
    public final byte[] iccRemainder;      // 9F48, empty when absent
    public final byte[] aip;               // 82
    public final byte[] afl;               // 94
    public final byte[] sdaTagList;        // 9F4A, null when absent
    public final byte[] ssad;              // 93, null when absent
    /** DF Name (tag 84), null when the blob carried none. */
    public final byte[] aid;

    private final Map<String, byte[]> records; // "sfi:rec" -> raw 70 template
    private final Map<Integer, byte[]> flat;   // every tag the walk found, first occurrence

    private DumpChain(int caIndex, byte[] issuerCert, byte[] issuerRemainder, byte[] issuerExponent,
                       byte[] iccCert, byte[] iccExponent, byte[] iccRemainder, byte[] aip, byte[] afl,
                       byte[] sdaTagList, byte[] ssad, byte[] aid, Map<String, byte[]> records,
                       Map<Integer, byte[]> flat) {
        this.caIndex = caIndex;
        this.issuerCert = issuerCert;
        this.issuerRemainder = issuerRemainder;
        this.issuerExponent = issuerExponent;
        this.iccCert = iccCert;
        this.iccExponent = iccExponent;
        this.iccRemainder = iccRemainder;
        this.aip = aip;
        this.afl = afl;
        this.sdaTagList = sdaTagList;
        this.ssad = ssad;
        this.aid = aid;
        this.records = records;
        this.flat = flat;
    }

    /** Any tag the walk found anywhere in the blob, or null. Not limited to the chain tags above. */
    public byte[] tag(int t) { return flat.get(t); }

    /** First 5 bytes of the AID (tag 84), i.e. the RID, or null when no AID was found. */
    public byte[] rid() {
        if (aid == null || aid.length < 5) return null;
        byte[] r = new byte[5];
        System.arraycopy(aid, 0, r, 0, 5);
        return r;
    }

    public OdaVerifier.RecordSource recordSource() {
        return new OdaVerifier.RecordSource() {
            @Override
            public byte[] read(int sfi, int record) {
                return records.get(sfi + ":" + record);
            }
        };
    }

    // ------------------------------------------------------------------ parse

    private static final int[] REQUIRED = {0x8F, 0x90, 0x9F32, 0x82, 0x94};

    public static Result parse(byte[] blob) {
        Map<Integer, byte[]> flat = new HashMap<>();
        List<byte[]> templates70 = new ArrayList<>();
        try {
            walk(blob, 0, blob.length, flat, templates70);
        } catch (IllegalArgumentException ex) {
            return Result.fail("malformed TLV: " + ex.getMessage());
        }

        for (int t : REQUIRED) {
            if (!flat.containsKey(t)) return Result.fail("missing tag " + tagName(t));
        }

        byte[] afl = flat.get(0x94);
        if (afl.length % 4 != 0) return Result.fail("AFL length is not a multiple of 4");

        Map<String, byte[]> records = new HashMap<>();
        int next = 0;
        for (int i = 0; i < afl.length; i += 4) {
            int sfi = (afl[i] & 0xFF) >> 3;
            int first = afl[i + 1] & 0xFF;
            int last = afl[i + 2] & 0xFF;
            if (last < first) return Result.fail("AFL entry has last < first record");
            for (int rec = first; rec <= last; rec++) {
                if (next >= templates70.size()) {
                    return Result.fail("AFL names " + countAflRecords(afl)
                            + " record(s) but only " + templates70.size() + " record template(s) in the dump");
                }
                records.put(sfi + ":" + rec, templates70.get(next++));
            }
        }

        byte[] issuerRem = flat.get(0x92);
        byte[] iccRem = flat.get(0x9F48);
        DumpChain c = new DumpChain(
                flat.get(0x8F)[0] & 0xFF,
                flat.get(0x90),
                issuerRem == null ? new byte[0] : issuerRem,
                flat.get(0x9F32),
                flat.get(0x9F46),
                flat.get(0x9F47),
                iccRem == null ? new byte[0] : iccRem,
                flat.get(0x82),
                afl,
                flat.get(0x9F4A),
                flat.get(0x93),
                flat.get(0x84),
                records,
                flat);
        return Result.ok(c);
    }

    private static int countAflRecords(byte[] afl) {
        int n = 0;
        for (int i = 0; i < afl.length; i += 4) n += (afl[i + 2] & 0xFF) - (afl[i + 1] & 0xFF) + 1;
        return n;
    }

    private static String tagName(int t) { return String.format("%02X", t); }

    // ------------------------------------------------------------- BER walker

    /**
     * Recurses into every constructed TLV (tag's bit 0x20 set), collecting the
     * first occurrence of each primitive tag into {@code flat} and every 0x70
     * template encountered, at any depth, into {@code templates70} in
     * encounter order.
     */
    private static void walk(byte[] b, int from, int to, Map<Integer, byte[]> flat, List<byte[]> templates70) {
        int i = from;
        while (i < to) {
            int tagStart = i;
            int tag = b[i++] & 0xFF;
            boolean constructed = (tag & 0x20) != 0;
            if ((tag & 0x1F) == 0x1F) {
                int bb;
                do {
                    if (i >= to) throw new IllegalArgumentException("tag runs past end at " + tagStart);
                    bb = b[i++] & 0xFF;
                    tag = (tag << 8) | bb;
                } while ((bb & 0x80) != 0);
            }
            if (i >= to) throw new IllegalArgumentException("no length byte after tag at " + tagStart);
            int len = b[i++] & 0xFF;
            if (len == 0x81) {
                if (i >= to) throw new IllegalArgumentException("truncated 0x81 length at " + tagStart);
                len = b[i++] & 0xFF;
            } else if (len == 0x82) {
                if (i + 1 >= to) throw new IllegalArgumentException("truncated 0x82 length at " + tagStart);
                len = ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
                i += 2;
            } else if (len > 0x82) {
                throw new IllegalArgumentException("unsupported length form at " + tagStart);
            }
            if (i + len > to) throw new IllegalArgumentException("value runs past end at " + tagStart);

            if (tag == 0x70) {
                templates70.add(java.util.Arrays.copyOfRange(b, tagStart, i + len));
            }
            if (!flat.containsKey(tag)) {
                flat.put(tag, java.util.Arrays.copyOfRange(b, i, i + len));
            }
            if (constructed) {
                walk(b, i, i + len, flat, templates70);
            }
            i += len;
        }
    }
}
