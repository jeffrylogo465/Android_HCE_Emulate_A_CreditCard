package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Locale;

/**
 * Parses a raw track 2 dump into the fields the MSD path needs.
 * Everything is validated before any field is handed back, so a bad dump
 * cannot half-populate the profile.
 */
public final class Track2Dump {

    public final String pan;
    public final String expiry;       // YYMM
    public final String serviceCode;  // 3 digits
    public final String dd;           // discretionary data from the dump, may be empty
    public final String vectorTrack;  // PAN '=' YYMM SC  -- CVC3 input, no DD

    private Track2Dump(String pan, String expiry, String serviceCode, String dd) {
        this.pan = pan;
        this.expiry = expiry;
        this.serviceCode = serviceCode;
        this.dd = dd;
        this.vectorTrack = pan + "=" + expiry + serviceCode;
    }

    public static Track2Dump parse(String raw) {
        if (raw == null) throw new IllegalArgumentException("empty");
        String s = raw.trim().toUpperCase(Locale.US);
        s = s.replace(";", "").replace("?", "").replace(" ", "")
             .replace("\n", "").replace("\r", "");
        if (s.startsWith("B")) s = s.substring(1);

        int eq = s.indexOf('=');
        if (eq < 0) {
            int dsep = s.indexOf('D');                 // some dumps use D as the separator
            if (dsep < 0) throw new IllegalArgumentException("no separator");
            s = s.substring(0, dsep) + "=" + s.substring(dsep + 1);
            eq = dsep;
        }
        if (s.indexOf('=', eq + 1) >= 0) throw new IllegalArgumentException("two separators");

        String pan = s.substring(0, eq);
        String rest = s.substring(eq + 1);

        if (pan.length() < 13 || pan.length() > 19) throw new IllegalArgumentException("PAN length");
        if (!isDigits(pan)) throw new IllegalArgumentException("PAN not digits");
        if (!luhn(pan)) throw new IllegalArgumentException("PAN Luhn");

        if (rest.length() < 7) throw new IllegalArgumentException("truncated");
        String expiry = rest.substring(0, 4);
        String sc = rest.substring(4, 7);
        String dd = rest.substring(7);

        if (!isDigits(expiry)) throw new IllegalArgumentException("expiry not digits");
        int mm = Integer.parseInt(expiry.substring(2, 4));
        if (mm < 1 || mm > 12) throw new IllegalArgumentException("expiry month");

        if (!isDigits(sc)) throw new IllegalArgumentException("service code not digits");
        char a = sc.charAt(0);
        if (a != '1' && a != '2' && a != '5' && a != '6')
            throw new IllegalArgumentException("service code");

        if (dd.length() > 12) throw new IllegalArgumentException("DD too long");
        if (!isHex(dd)) throw new IllegalArgumentException("DD not hex");

        return new Track2Dump(pan, expiry, sc, dd);
    }

    /** 57 payload: vector track plus the computed CVC3, padded with F to even length. */
    public String recordTrack(String cvc3) {
        if (cvc3 == null || cvc3.length() != 5 || !isDigits(cvc3))
            throw new IllegalArgumentException("CVC3 must be 5 digits");
        String t = padEven(vectorTrack + cvc3);
        if (t.length() > 37) throw new IllegalArgumentException("57 exceeds 37 bytes");
        return t;
    }

    private static String padEven(String s) {
        return (s.length() % 2 == 0) ? s : s + "F";
    }

    private static boolean isDigits(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    private static boolean luhn(String pan) {
        int sum = 0;
        boolean dbl = false;
        for (int i = pan.length() - 1; i >= 0; i--) {
            int d = pan.charAt(i) - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}
