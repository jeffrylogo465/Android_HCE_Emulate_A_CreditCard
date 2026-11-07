package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Single source of truth for the Luhn (mod 10) check digit test.
 *
 * The rightmost digit is the check digit and is NEVER doubled. The toggle
 * therefore starts false and flips AFTER the digit is added to the sum.
 * Getting that one line wrong flips the parity and rejects roughly 9 valid
 * card numbers out of 10, which is exactly how this class came to exist.
 */
public final class Luhn {

    private Luhn() { }

    /** True if raw holds a well-formed card number with a valid check digit. */
    public static boolean valid(String raw) {
        return valid(raw, 12, 19);
    }

    public static boolean valid(String raw, int minLen, int maxLen) {
        String d = digits(raw);
        if (d.length() < minLen || d.length() > maxLen) return false;
        return sum(d) % 10 == 0;
    }

    /** The check digit that would make payload valid. -1 if payload is empty. */
    public static int checkDigit(String payload) {
        String d = digits(payload);
        if (d.isEmpty()) return -1;
        return (10 - (sum(d + "0") % 10)) % 10;
    }

    /** payload with its correct check digit appended. */
    public static String complete(String payload) {
        String d = digits(payload);
        return d.isEmpty() ? "" : d + checkDigit(d);
    }

    private static int sum(String digits) {
        int total = 0;
        boolean doubleIt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int c = digits.charAt(i) - '0';
            if (doubleIt) {
                c *= 2;
                if (c > 9) c -= 9;
            }
            total += c;
            doubleIt = !doubleIt;
        }
        return total;
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("\\D", "");
    }
}
