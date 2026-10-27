package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Candidate issuer master keys for the ARQC scan.
 *
 * A 16-byte IMK is 2^128, so this is a dictionary attack, not a brute force.
 * The only thing that matters is how good the dictionary is. A real issuer key
 * is rarely random: it is a published test vector, a repeated byte, a counting
 * pattern, or something derived from the BIN.
 *
 * Everything here is cheap, so widen this list before touching anything else -
 * each extra family is thousands more chances at essentially zero cost.
 */
public final class KeyFinder {

    private KeyFinder() { }

    /** 66k candidates x 4 variants is a few seconds on a phone. */
    private static final int MAX_CANDIDATES = 200000;

    public static List<String> candidates(String pan, String userList) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        String p = digits(pan);
        String bin8 = p.length() >= 8 ? p.substring(0, 8) : "";
        String bin6 = p.length() >= 6 ? p.substring(0, 6) : "";

        addTestVectors(out);
        addRepeats(out);
        addSequences(out);
        addAscii(out);
        addBinDerived(out, bin8, bin6);
        addFromUserList(out, userList);

        List<String> list = new ArrayList<>(out);
        if (list.size() > MAX_CANDIDATES) list = new ArrayList<>(list.subList(0, MAX_CANDIDATES));
        return list;
    }

    // ---------------------------------------------------------------- families

    /** Published test vectors and the defaults processors ship with. */
    private static void addTestVectors(LinkedHashSet<String> out) {
        String[] keys = {
                "0123456789ABCDEF0123456789ABCDEF",
                "FEDCBA9876543210FEDCBA9876543210",
                "0123456789ABCDEFFEDCBA9876543210",
                "FEDCBA98765432100123456789ABCDEF",
                "00000000000000000000000000000000",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "11111111111111111111111111111111",
                "22222222222222222222222222222222",
                "33333333333333333333333333333333",
                "44444444444444444444444444444444",
                "55555555555555555555555555555555",
                "66666666666666666666666666666666",
                "77777777777777777777777777777777",
                "88888888888888888888888888888888",
                "99999999999999999999999999999999",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
                "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
                "00112233445566778899AABBCCDDEEFF",
                "00112233445566770011223344556677",
                "404142434445464748494A4B4C4D4E4F",
                "ABCDEF0123456789ABCDEF0123456789",
                "12345678901234561234567890123456",
                "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
                "CAFEBABECAFEBABECAFEBABECAFEBABE",
                "FEEDFACEFEEDFACEFEEDFACEFEEDFACE",
                "0102030405060708090A0B0C0D0E0F10",
                "00000000000000000000000000000001",
                "10000000000000000000000000000000",
        };
        for (String k : keys) out.add(k);
    }

    /** Every repeated byte, then every repeated 2-byte pattern. ~65k. */
    private static void addRepeats(LinkedHashSet<String> out) {
        for (int b = 0; b < 256; b++) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++) sb.append(hex2(b));
            out.add(sb.toString());
        }
        for (int a = 0; a < 256; a++) {
            for (int b = 0; b < 256; b++) {
                String pair = hex2(a) + hex2(b);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++) sb.append(pair);
                out.add(sb.toString());
            }
        }
    }

    /** Counting ramps, forwards and backwards. */
    private static void addSequences(LinkedHashSet<String> out) {
        String[] ramps = {
                "0123456789ABCDEF",
                "FEDCBA9876543210",
                "0001020304050607",
                "08090A0B0C0D0E0F",
                "0011223344556677",
                "8899AABBCCDDEEFF",
                "1020304050607080",
                "F0E0D0C0B0A09080",
                "0102030405060708",
                "1112131415161718",
                "3132333435363738",
                "0000000100020003",
                "0001000200030004",
                "FFFEFFFDFFFCFFFB",
                "AAAAAAAA55555555",
                "55555555AAAAAAAA",
        };
        for (String r : ramps) {
            out.add(r + r);
            out.add(reverse(r) + reverse(r));
        }
    }

    /** ASCII words - some issuers set a key by typing one in. */
    private static void addAscii(LinkedHashSet<String> out) {
        String[] words = {
                "MASTERCARD", "VISA", "AMERICANEXPRESS", "AMEX", "DISCOVER",
                "CITADEL", "SCHOOLSFIRST", "SUTTON", "BANKOFAMERICA",
                "EMVTESTKEY", "TESTKEY", "SHADOWS", "WALLET", "CREDITCARD",
                "0123456789", "ABCDEFGHIJKLMNOP",
        };
        for (String w : words) {
            out.add(asciiPadded(w, '0'));
            out.add(asciiPadded(w, '\0'));
        }
    }

    /** Keys built out of the BIN - common when a bank wants one key per range. */
    private static void addBinDerived(LinkedHashSet<String> out, String bin8, String bin6) {
        if (bin6.isEmpty()) return;
        out.add(padRight(bin6, 32, '0'));
        out.add(padRight(bin6, 32, 'F'));
        out.add(repeatTo(bin6, 32));
        out.add(asciiPadded(bin6, '0'));
        if (!bin8.isEmpty()) {
            out.add(padRight(bin8, 32, '0'));
            out.add(padRight(bin8, 32, 'F'));
            out.add(repeatTo(bin8, 32));
            out.add(asciiPadded(bin8, '0'));
        }
    }

    /** Whatever the user typed into the key editor. */
    private static void addFromUserList(LinkedHashSet<String> out, String userList) {
        if (userList == null) return;
        for (String k : userList.split("[^0-9A-Fa-f]+")) {
            String h = k.toUpperCase(Locale.US);
            if (h.length() == 32) out.add(h);
        }
    }

    // ---------------------------------------------------------------- helpers

    private static String hex2(int v) {
        return String.format(Locale.US, "%02X", v & 0xFF);
    }

    private static String padRight(String s, int len, char pad) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < len) sb.append(pad);
        return sb.substring(0, len);
    }

    private static String repeatTo(String s, int len) {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < len) sb.append(s);
        return sb.substring(0, len);
    }

    private static String reverse(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    private static String asciiPadded(String s, char pad) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(hex2(i < s.length() ? s.charAt(i) : pad));
        }
        return sb.toString();
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("[^0-9]", "");
    }
}
