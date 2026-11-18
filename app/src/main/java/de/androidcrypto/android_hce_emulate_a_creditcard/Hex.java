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
 * it.
 *
 * Messages carry an index and a length but never the input: these throws land in
 * the service log and the input may be a PAN.
 */
final class Hex {

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    private static final Pattern HEX_ALLOWED = Pattern.compile("[0-9A-Fa-f\\s:]*");
    private static final Pattern DEC_ALLOWED = Pattern.compile("[0-9\\s:]*");
    private static final Pattern SEPARATORS  = Pattern.compile("[\\s:]+");

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

    static byte[] hex(String s) { return strict(normalize(s, HEX_ALLOWED)); }

    static byte[] hexLenient(String s) { return lenient(normalize(s, HEX_ALLOWED)); }

    static byte[] bcd(String s) { return strict(normalize(s, DEC_ALLOWED)); }

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

    private Hex() { }
}
