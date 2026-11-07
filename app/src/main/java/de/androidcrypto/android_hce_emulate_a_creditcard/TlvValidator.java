package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Static BER-TLV length validator.
 *
 * Walks a hex-encoded TLV constant and verifies that every length field equals
 * the real byte count of the value that follows it, recursing into constructed
 * (nested) tags. Throws on the first mismatch, naming the tag path and the
 * declared versus available lengths.
 *
 * The directory and FCI are the only places in this app where a length is
 * written by hand instead of computed by tlv(), which makes them the only
 * places that can go wrong without a compiler complaint. ProfileAmex had every
 * one of them wrong.
 */
final class TlvValidator {

    private TlvValidator() { }

    /** Null when balanced, otherwise the first problem found. */
    static String firstProblem(String hex) {
        try {
            validate(hex);
            return null;
        } catch (RuntimeException e) {
            return e.getMessage();
        }
    }

    static void validate(String hex) {
        byte[] data = fromHex(hex);
        int consumed = walk(data, 0, data.length, "");
        if (consumed != data.length) {
            throw new IllegalStateException(
                    "Trailing bytes: parsed " + consumed + " of " + data.length);
        }
    }

    /** Parses TLVs in data[off, end) and returns the index just past the last. */
    private static int walk(byte[] data, int off, int end, String path) {
        int p = off;
        while (p < end) {
            int tagStart = p;

            int first = data[p++] & 0xFF;
            boolean constructed = (first & 0x20) != 0;
            if ((first & 0x1F) == 0x1F) {
                int guard = 0;
                while (p < end && (data[p++] & 0x80) != 0) {
                    if (++guard > 4) throw new IllegalStateException(path + ": tag too long");
                }
            }
            String tag  = toHex(data, tagStart, p);
            String here = path.isEmpty() ? tag : path + "/" + tag;

            if (p >= end) throw new IllegalStateException(here + ": truncated length");
            int lenByte = data[p++] & 0xFF;
            int declared;
            if ((lenByte & 0x80) == 0) {
                declared = lenByte;
            } else {
                int n = lenByte & 0x7F;
                if (n == 0 || n > 4)
                    throw new IllegalStateException(here + ": bad length form 0x"
                            + Integer.toHexString(lenByte));
                declared = 0;
                for (int i = 0; i < n; i++) {
                    if (p >= end)
                        throw new IllegalStateException(here + ": truncated long length");
                    declared = (declared << 8) | (data[p++] & 0xFF);
                }
            }

            int valStart = p;
            int valEnd   = valStart + declared;
            if (valEnd > end) {
                throw new IllegalStateException(here + ": length 0x"
                        + Integer.toHexString(declared) + " (" + declared
                        + ") exceeds available " + (end - valStart) + " byte(s)");
            }

            if (constructed) {
                int childEnd = walk(data, valStart, valEnd, here);
                if (childEnd != valEnd) {
                    throw new IllegalStateException(here + ": children consumed "
                            + (childEnd - valStart) + " but length declares " + declared);
                }
            }

            p = valEnd;
        }
        return p;
    }

    private static byte[] fromHex(String s) {
        String h = s.replaceAll("\\s", "");
        if ((h.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] data, int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to; i++) sb.append(String.format("%02X", data[i] & 0xFF));
        return sb.toString();
    }
}
