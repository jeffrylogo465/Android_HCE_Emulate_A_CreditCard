package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A real EMV card, pasted as one text block (or a bare track 2 line) and
 * parsed into a tag map plus the two secrets no EMV tag carries (the ICC
 * private key and MK_AC).
 *
 * This is a library, not a feature of its own: MainActivity's per-slot card
 * editor is the one place a loaded card lives (the same fields, prefs and
 * tile every hand-typed or dump-pasted card uses - see
 * MainActivity.applyLoadedCard()), not a separate store. Parsing a block
 * that carries more than the editor has fields for - the certificate chain,
 * the ICC key - is not an error; it is simply not kept, and warnings()
 * exists so the editor can say so on the tile rather than silently drop it.
 *
 * Validation is split in two. PAN and expiry are the only things a card
 * cannot be served without at all, so a block with neither an explicit 5A/
 * 5F24 nor a bare track 2 line is REFUSED, naming both. The certificate
 * chain (8F/90/92/9F46) and the ICC key are a WARNING, not a refusal - a
 * dump is usually just a bare track 2, which has none of them, and it is
 * still a usable card.
 *
 * Pure Java, no Android types - same discipline as AssetCardEngine and
 * AssetSchemeProfile, so parsing and validation run as plain unit tests.
 */
final class LoadedCard {

    /** Missing here is a WARNING (warnings()), not a refusal - see the class doc. */
    private static final String[] WARN_TAGS = {"8F", "90", "92", "9F46"};

    /**
     * PAN D YYMMSVC[discretionary], no tag= prefix - the common bare track 2
     * dump shape, in its canonical D-separated form (ISO 7813's own field
     * separator sentinel, the same character applyBareTrack2() and tag 57
     * already store it as). The tail allows hex, not just decimal, digits -
     * an odd-length discretionary field BCD-pads with a trailing F, same
     * convention as every other field here (5A, track2 itself). A line is
     * normalised to this shape - see normaliseTrack2Candidate() - before
     * being tested here; this pattern
     * itself never sees a raw '=' line.
     */
    private static final Pattern BARE_TRACK2 = Pattern.compile("(\\d{12,19})D([0-9A-F]{7,})");

    private final Map<String, String> tags = new HashMap<>();
    private final Map<String, String[]> records = new HashMap<>();
    private final BigInteger iccModulus;
    private final BigInteger iccPrivateExponent;
    private final String acKey;
    private final List<String> warnings;

    private LoadedCard(Map<String, String> tags, Map<String, String[]> records,
                        BigInteger iccModulus, BigInteger iccPrivateExponent, String acKey,
                        List<String> warnings) {
        this.tags.putAll(tags);
        this.records.putAll(records);
        this.iccModulus = iccModulus;
        this.iccPrivateExponent = iccPrivateExponent;
        this.acKey = acKey;
        this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
    }

    /**
     * Parses and validates one pasted block. Throws IllegalArgumentException
     * naming every missing required field (PAN and/or expiry) in one
     * message when neither can be determined at all. Everything else that
     * is merely incomplete - the certificate chain, the ICC key - is
     * reported through warnings() on the card this still returns.
     */
    static LoadedCard parse(String block) {
        if (block == null) block = "";

        Map<String, String> tags = new HashMap<>();
        Map<String, String[]> records = new HashMap<>();
        String iccKeyHex = null;
        String acKeyHex = null;

        int lineNo = 0;
        for (String raw : block.split("\n", -1)) {
            lineNo++;
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            if (line.toUpperCase(Locale.ROOT).startsWith("REC ")) {
                int eq = line.indexOf('=');
                if (eq < 0) throw new IllegalArgumentException(
                        "line " + lineNo + ": a REC line needs '=': " + raw);
                String key = line.substring(4, eq).trim();
                if (!key.matches("\\d+:\\d+")) throw new IllegalArgumentException(
                        "line " + lineNo + ": a REC line's key must be SFI:RECORD, got '" + key + "'");
                String[] list = line.substring(eq + 1).trim().split(",");
                for (int i = 0; i < list.length; i++) list[i] = list[i].trim().toUpperCase(Locale.ROOT);
                records.put(key, list);
                continue;
            }

            // Choke point: every bare-track2 candidate is normalised here,
            // in LoadedCard.parse, not at a call site - a leading ';' and
            // trailing '?' (the ISO reader frame a typed or re-pasted dump
            // often still carries), upper-cased, and '=' folded to the
            // canonical 'D' separator (real readers emit both forms). Only
            // this candidate is tested/used; `line` itself is untouched, so
            // a genuine TAG=HEX or REC line's own '=' is never touched by
            // this - it only ever applies to a line that ends up matching
            // the bare-track2 shape in the first place.
            String track2Candidate = normaliseTrack2Candidate(line);
            if (BARE_TRACK2.matcher(track2Candidate).matches()) {
                applyBareTrack2(track2Candidate, tags);
                continue;
            }

            int eq = line.indexOf('=');
            if (eq < 0) throw new IllegalArgumentException(
                    "line " + lineNo + ": expected TAG=HEX, REC sfi:rec=TAG,TAG, "
                            + "or a bare track 2 (PAN=YYMMSVC...): " + raw);
            String key = line.substring(0, eq).trim().toUpperCase(Locale.ROOT);
            String value = line.substring(eq + 1).trim().toUpperCase(Locale.ROOT);
            if (value.isEmpty()) continue;

            if (key.equals("ICCKEY")) { iccKeyHex = value; continue; }
            if (key.equals("ACKEY")) { acKeyHex = value; continue; }

            Hex.hex(value); // validates even-length hex now rather than at serve time
            tags.put(key, value);
        }

        List<String> missing = new ArrayList<>();
        if (!tags.containsKey("5A")) missing.add("PAN (5A, or a bare track 2 line)");
        if (!tags.containsKey("5F24")) missing.add("expiry (5F24, or a bare track 2 line)");
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException(
                    "card is missing required field(s): " + String.join(", ", missing));
        }

        List<String> warnings = new ArrayList<>();
        for (String t : WARN_TAGS) if (!tags.containsKey(t)) warnings.add(t);
        if (iccKeyHex == null) warnings.add("ICCKEY");

        BigInteger modulus = null;
        BigInteger privateExponent = null;
        if (iccKeyHex != null) {
            try {
                byte[] der = Hex.hex(iccKeyHex);
                RSAPrivateKey k;
                try {
                    k = RSAPrivateKey.getInstance(ASN1Primitive.fromByteArray(der));
                } catch (RuntimeException e1) {
                    k = RSAPrivateKey.getInstance(
                            PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der)).parsePrivateKey());
                }
                modulus = k.getModulus();
                privateExponent = k.getPrivateExponent();
            } catch (Exception e) {
                throw new IllegalArgumentException("ICCKEY is not a PKCS1 or PKCS8 DER RSA private key: "
                        + e.getMessage(), e);
            }
        }

        if (acKeyHex != null && Hex.hex(acKeyHex).length != 16) {
            throw new IllegalArgumentException("ACKEY must be a double-length 3DES key (16 bytes)");
        }

        return new LoadedCard(tags, records, modulus, privateExponent, acKeyHex, warnings);
    }

    /**
     * Strips a single leading ';' and a single trailing '?' (the ISO reader
     * frame), upper-cases, and folds '=' to 'D' - the two separator
     * conventions real readers actually emit collapse to one before the
     * bare-track2 pattern (or applyBareTrack2()) ever sees the line.
     */
    private static String normaliseTrack2Candidate(String line) {
        String s = line;
        if (s.startsWith(";")) s = s.substring(1);
        if (s.endsWith("?")) s = s.substring(0, s.length() - 1);
        s = s.toUpperCase(Locale.ROOT);
        return s.replace('=', 'D');
    }

    /**
     * A bare track 2 line - PAN D YYMMSVC[discretionary], no tag= prefix -
     * derives exactly the fields a real dump hands over and nothing it
     * does not: 5A (PAN, BCD-padded), 5F24 (YYMM plus the real last day of
     * that month - track 2 carries no day, and a real card's own 5F24
     * always does hold the actual expiry date, which issuers set to the
     * last day of the month), 57 (the full track 2 equivalent data: PAN,
     * field separator D, YYMM, service code, discretionary, BCD-padded)
     * and 5F34 (01, since track 2 carries no PAN sequence number).
     *
     * Applied directly into the tag map, same as any other line - a later
     * explicit 5A/5F24/57/5F34 line further down the block overwrites it,
     * simple top-to-bottom precedence, no special-casing which one "wins".
     */
    private static void applyBareTrack2(String line, Map<String, String> tags) {
        // `line` is always normaliseTrack2Candidate()'s output by the time
        // this runs, so the separator is always 'D' - a PAN is all digits,
        // so the first 'D' can only be this one.
        int eq = line.indexOf('D');
        String pan = line.substring(0, eq);
        String tail = line.substring(eq + 1);
        String yymm = tail.substring(0, 4);
        String serviceCode = tail.substring(4, 7);
        String discretionary = tail.substring(7);

        tags.put("5A", pan.length() % 2 == 0 ? pan : pan + "F");
        tags.put("5F24", yymm + lastDayOfMonth(yymm));
        tags.put("5F34", "01");

        String t2 = pan + "D" + yymm + serviceCode + discretionary;
        if (t2.length() % 2 != 0) t2 = t2 + "F";
        tags.put("57", t2);
    }

    /**
     * The real last day of yymm's month - "31", "30", or "28"/"29" for
     * February with the Gregorian leap rule on 2000+YY (every card year
     * this app will ever see a bare track 2 for falls in that one century,
     * so the divisible-by-100-except-divisible-by-400 exception never
     * actually matters here - divisible-by-4 alone is exact across the
     * whole 2000-2099 range, 2000 itself included). A month outside 01-12
     * falls through to "31" rather than throwing - applyBareTrack2()'s own
     * caller (the BARE_TRACK2 regex) does not itself bound-check the month,
     * and a day digit at all beats refusing an otherwise-parseable card
     * over a field track 2 never carried in the first place.
     */
    private static String lastDayOfMonth(String yymm) {
        int mm;
        try {
            mm = Integer.parseInt(yymm.substring(2, 4));
        } catch (NumberFormatException notDigits) {
            return "31";
        }
        switch (mm) {
            case 4: case 6: case 9: case 11:
                return "30";
            case 2:
                int yy = Integer.parseInt(yymm.substring(0, 2));
                boolean leap = (2000 + yy) % 4 == 0;
                return leap ? "29" : "28";
            default:
                return "31";
        }
    }

    /** This card's own value for an EMV tag, or null - never the shared profile's. */
    String tag(String t) { return tags.get(t.toUpperCase(Locale.ROOT)); }

    /**
     * The PAN out of tag 5A, with BCD's single trailing 'F' pad nibble
     * stripped for an odd-length PAN, or null if this card has no 5A.
     */
    String pan() {
        String v = tag("5A");
        if (v == null) return null;
        return v.endsWith("F") ? v.substring(0, v.length() - 1) : v;
    }

    /** Expiry out of tag 5F24 (YYMMDD, already the exact digits), or null. */
    String expiry() { return tag("5F24"); }

    /** This card's own AID (tag 84), or null. */
    String aid() { return tag("84"); }

    /**
     * Service code and discretionary data, read out of tag 57 (PAN, D,
     * YYMM, SVC, discretionary) rather than kept as separate fields - one
     * source of truth whether 57 came from an explicit line or was derived
     * from a bare track 2. Null/empty when this card has no 57.
     */
    String serviceCode() {
        String rest = track2Rest(); // YYMM + SVC + discretionary
        return rest == null || rest.length() < 7 ? null : rest.substring(4, 7);
    }

    String discretionary() {
        String rest = track2Rest();
        if (rest == null || rest.length() <= 7) return "";
        String dd = rest.substring(7);
        return dd.endsWith("F") ? dd.substring(0, dd.length() - 1) : dd;
    }

    /** Tag 57 after the PAN and its D separator (YYMM+SVC+discretionary), or null. */
    private String track2Rest() {
        String t2 = tag("57");
        if (t2 == null) return null;
        int d = t2.indexOf('D');
        return d < 0 ? null : t2.substring(d + 1);
    }

    /** This card's own tag list for one SFI:record, or null. */
    String[] record(String sfiColonRecord) { return records.get(sfiColonRecord); }

    BigInteger iccModulus() { return iccModulus; }

    BigInteger iccPrivateExponent() { return iccPrivateExponent; }

    /** MK_AC, or null to keep the shared profile's. */
    String acKey() { return acKey; }

    /**
     * The WARN_TAGS (and ICCKEY) this card did not supply, empty when it
     * carries the full chain. Never thrown over - see the class doc - so a
     * caller that cares shows these, it does not catch them.
     */
    List<String> warnings() { return warnings; }
}
