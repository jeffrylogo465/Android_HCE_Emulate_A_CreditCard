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
 * A real EMV card, pasted as one text block and parsed into exactly the
 * shape AssetCardEngine already knows how to serve: a tag map and a records
 * map, plus the two secrets no EMV tag carries (the ICC private key and
 * MK_AC).
 *
 * See AssetCardEngine's class doc for the block format and for how this
 * cascades under a loaded card: loaded card, then scheme profile, then
 * profile.json, with the certificate-chain tags never falling back past
 * "loaded card" once one exists.
 *
 * Validation is split in two. PAN and expiry are the only things a card
 * cannot be served without at all, so a block with neither an explicit 5A/
 * 5F24 nor a bare track 2 line is REFUSED, naming both. The certificate
 * chain (8F/90/92/9F46) and the ICC key are a WARNING, not a refusal - a
 * dump is usually just a bare track 2, which has none of them, and it is
 * still a usable card: it loads and serves PAN/track2/expiry (MSD), it
 * simply cannot answer INTERNAL AUTHENTICATE or carry the cert chain in a
 * record, both of which already fail loud (need() throws) rather than
 * silently borrowing the shared test chain - see warnings() and
 * AssetCardEngine's tag().
 *
 * Pure Java, no Android types - same discipline as AssetCardEngine and
 * AssetSchemeProfile, so parsing and validation run as plain unit tests.
 */
final class LoadedCard {

    /**
     * The certificate-chain tags AssetCardEngine must never let fall back to
     * the shared test chain once a card is loaded, even for a tag this
     * particular card did not bother to redeclare. 8F is the CA index; the
     * rest is the chain and the DDOL it is read against.
     */
    static final String[] CHAIN_TAGS = {"8F", "90", "92", "9F32", "9F46", "9F47", "9F49"};

    /** Missing here is a WARNING (warnings()), not a refusal - see the class doc. */
    private static final String[] WARN_TAGS = {"8F", "90", "92", "9F46"};

    /** PAN=YYMMSVC[discretionary], no tag= prefix - the common bare track 2 dump shape. */
    private static final Pattern BARE_TRACK2 = Pattern.compile("(\\d{12,19})=(\\d{7,})");

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

            if (BARE_TRACK2.matcher(line).matches()) {
                applyBareTrack2(line, tags);
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
     * A bare track 2 line - PAN=YYMMSVC[discretionary], no tag= prefix -
     * derives exactly the fields a real dump hands over and nothing it
     * does not: 5A (PAN, BCD-padded), 5F24 (YYMM plus a defaulted day of
     * 31 - track 2 carries no day), 57 (the full track 2 equivalent data:
     * PAN, field separator D, YYMM, service code, discretionary, BCD-
     * padded) and 5F34 (01, since track 2 carries no PAN sequence number).
     *
     * Applied directly into the tag map, same as any other line - a later
     * explicit 5A/5F24/57/5F34 line further down the block overwrites it,
     * simple top-to-bottom precedence, no special-casing which one "wins".
     */
    private static void applyBareTrack2(String line, Map<String, String> tags) {
        int eq = line.indexOf('=');
        String pan = line.substring(0, eq);
        String tail = line.substring(eq + 1);
        String yymm = tail.substring(0, 4);
        String serviceCode = tail.substring(4, 7);
        String discretionary = tail.substring(7);

        tags.put("5A", pan.length() % 2 == 0 ? pan : pan + "F");
        tags.put("5F24", yymm + "31");
        tags.put("5F34", "01");

        String t2 = pan + "D" + yymm + serviceCode + discretionary;
        if (t2.length() % 2 != 0) t2 = t2 + "F";
        tags.put("57", t2);
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

    static boolean isChainTag(String t) {
        String up = t.toUpperCase(Locale.ROOT);
        for (String c : CHAIN_TAGS) if (c.equals(up)) return true;
        return false;
    }
}
