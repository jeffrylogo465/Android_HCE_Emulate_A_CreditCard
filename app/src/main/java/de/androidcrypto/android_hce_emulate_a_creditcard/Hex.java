package de.androidcrypto.android_hce_emulate_a_creditcard;

final class Hex {

    static String digits(String s) {
        return s == null ? "" : s.replaceAll("[^0-9]", "");
    }

    static int u8(byte b) {
        return b & 0xFF;
    }

    static byte[] hex(String s) {
        if (s == null) return new byte[0];
        String t = s.replaceAll("[^0-9A-Fa-f]", "");
        if (t.length() % 2 != 0) t = t + "F";
        return decode(t);
    }

    static byte[] hexStrict(String s) {
        if (s == null) return new byte[0];
        String t = s.replaceAll("[^0-9A-Fa-f]", "");
        if (t.length() % 2 != 0)
            throw new IllegalArgumentException("odd hex length: " + t.length() + " in \"" + s + "\"");
        return decode(t);
    }

    static byte[] hexOrNull(String s) {
        String t = (s == null) ? "" : s.replaceAll("[^0-9A-Fa-f]", "");
        return t.isEmpty() ? null : hex(t);
    }

    static byte[] bcd(String in) {
        String s = digits(in);
        if (s.isEmpty()) return new byte[0];
        if (s.length() % 2 != 0) s = s + "F";
        return decode(s);
    }

    static byte[] bcdOrNull(String s) {
        String d = digits(s);
        return d.isEmpty() ? null : bcd(d);
    }

    private static byte[] decode(String even) {
        byte[] b = new byte[even.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(even.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    static String toHex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    static String toHexSpaced(byte[] b) {
        if (b == null) return "null";
        if (b.length == 0) return "";
        StringBuilder sb = new StringBuilder(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02X", b[i]));
        }
        return sb.toString();
    }

    static boolean same(byte[] a, byte[] b) {
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

    private Hex() {}
}
