package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.regex.Pattern;

/**
 * Hex and BCD. The plain name is the strict one.
 *
 * Every entry point validates its charset BEFORE stripping, so a typo throws
 * instead of silently shifting a nibble. Only whitespace and colon are tolerated
 * as separators; everything else is a rejection.
 *
 * hex() throws on odd length. hexLenient() pads a trailing F and is named for
 * it. hexOrNull()/bcdOrNull() are the null-returning siblings of the STRICT
 * parse, not of the lenient one.
 *
 * Messages carry an index and a length but never the input: these throws land in
 * the service log and the input may be a PAN.
 */
final class Hex {

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    private static final Pattern HEX_ALLOWED = Pattern.compile("[0-9A-Fa-f\\s:]*");
    private static final Pattern DEC_ALLOWED = Pattern.compile("[0-9\\s:]*");
    private static final Pattern SEPARATORS  = Pattern.compile("[\\s:]+");
    private static final Pattern NON_DIGITS  = Pattern.compile("[^0-9]");

    private static String normalize(String s, Pattern allowed) {
        if (s == null) return "";
        if (!allowed.matcher(s).matches())
            throw new IllegalArgumentException("invalid character at index " + firstBad(s, allowed));
        return SEPARATORS.matcher(s).replaceAll("");
    }

    private static int firstBad(String s, Pattern allowed) {
        for (int i = 0; i < s.length(); i++)
            if (!allowed.matcher(s.substring(i, i + 1)).matches()) return i;
        return -1;
    }

    private static byte[] strict(String t) {
        if ((t.length() & 1) != 0)
            throw new IllegalArgumentException("odd hex length: " + t.length());
        return decode(t);
    }

    private static byte[] lenient(String t) {
        if ((t.length() & 1) != 0) t = t + "F";
        return decode(t);
    }

    /**
     * Lossy by contract: pulls decimal digits out of arbitrary text. Extraction,
     * not a validating parse. Punctuated input goes through here first if you
     * then want bcd()/hex() to accept it.
     */
    static String digits(String s) {
        return s == null ? "" : NON_DIGITS.matcher(s).replaceAll("");
    }

    static int u8(byte b) { return b & 0xFF; }

    static byte[] hex(String s) { return strict(normalize(s, HEX_ALLOWED)); }

    static byte[] hexLenient(String s) { return lenient(normalize(s, HEX_ALLOWED)); }

    static byte[] hexOrNull(String s) {
        String t = normalize(s, HEX_ALLOWED);
        return t.isEmpty() ? null : strict(t);
    }

    static byte[] bcd(String s) { return strict(normalize(s, DEC_ALLOWED)); }

    static byte[] bcdLenient(String s) { return lenient(normalize(s, DEC_ALLOWED)); }

    static byte[] bcdOrNull(String s) {
        String t = normalize(s, DEC_ALLOWED);
        return t.isEmpty() ? null : strict(t);
    }

    /** Reachable now that callers feed validated, even-length input. */
    private static byte[] decode(String even) {
        byte[] b = new byte[even.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(even.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    static String toHex(byte[] b) {
        if (b == null) return "";
        char[] out = new char[b.length * 2];
        int j = 0;
        for (byte x : b) {
            int v = x & 0xFF;
            out[j++] = HEX_DIGITS[v >>> 4];
            out[j++] = HEX_DIGITS[v & 0x0F];
        }
        return new String(out);
    }

    static String toHexSpaced(byte[] b) {
        if (b == null) return "null";
        if (b.length == 0) return "";
        char[] out = new char[b.length * 3 - 1];
        int j = 0;
        for (int i = 0; i < b.length; i++) {
            if (i > 0) out[j++] = ' ';
            int v = b[i] & 0xFF;
            out[j++] = HEX_DIGITS[v >>> 4];
            out[j++] = HEX_DIGITS[v & 0x0F];
        }
        return new String(out);
    }

    static boolean same(byte[] a, byte[] b) {
        // Short-circuits on first mismatch: fine for structural compares, but a
        // MAC/cryptogram compare wants MessageDigest.isEqual (constant time).
        if (a == null || b == null) return a == b;
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    static boolean isPrefix(byte[] hay, byte[] needle) {
        if (hay == null || needle == null || hay.length < needle.length) return false;
        for (int i = 0; i < needle.length; i++) if (hay[i] != needle[i]) return false;
        return true;
    }

    private Hex() { }
}
