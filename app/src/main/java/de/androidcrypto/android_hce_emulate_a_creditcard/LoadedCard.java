package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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

    /** Refused outright if any of these - or the ICC key - is missing. */
    private static final String[] REQUIRED_TAGS = {"8F", "90", "92", "9F46"};

    private final Map<String, String> tags = new HashMap<>();
    private final Map<String, String[]> records = new HashMap<>();
    private final BigInteger iccModulus;
    private final BigInteger iccPrivateExponent;
    private final String acKey;

    private LoadedCard(Map<String, String> tags, Map<String, String[]> records,
                        BigInteger iccModulus, BigInteger iccPrivateExponent, String acKey) {
        this.tags.putAll(tags);
        this.records.putAll(records);
        this.iccModulus = iccModulus;
        this.iccPrivateExponent = iccPrivateExponent;
        this.acKey = acKey;
    }

    /**
     * Parses and validates one pasted block. Throws IllegalArgumentException
     * naming every missing required tag (and the ICC key) in one message,
     * not just the first one found, so a card is not rejected one field at a
     * time across repeated pastes.
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

            int eq = line.indexOf('=');
            if (eq < 0) throw new IllegalArgumentException(
                    "line " + lineNo + ": expected TAG=HEX or REC sfi:rec=TAG,TAG: " + raw);
            String key = line.substring(0, eq).trim().toUpperCase(Locale.ROOT);
            String value = line.substring(eq + 1).trim().toUpperCase(Locale.ROOT);
            if (value.isEmpty()) continue;

            if (key.equals("ICCKEY")) { iccKeyHex = value; continue; }
            if (key.equals("ACKEY")) { acKeyHex = value; continue; }

            Hex.hex(value); // validates even-length hex now rather than at serve time
            tags.put(key, value);
        }

        List<String> missing = new ArrayList<>();
        for (String t : REQUIRED_TAGS) if (!tags.containsKey(t)) missing.add(t);
        if (iccKeyHex == null) missing.add("ICCKEY");
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException(
                    "card is missing required field(s): " + String.join(", ", missing));
        }

        BigInteger modulus;
        BigInteger privateExponent;
        try {
            byte[] der = Hex.hex(iccKeyHex);
            boolean pkcs1;
            RSAPrivateKey k;
            try {
                k = RSAPrivateKey.getInstance(ASN1Primitive.fromByteArray(der));
                pkcs1 = true;
            } catch (RuntimeException e1) {
                k = RSAPrivateKey.getInstance(
                        PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der)).parsePrivateKey());
                pkcs1 = false;
            }
            modulus = k.getModulus();
            privateExponent = k.getPrivateExponent();
        } catch (Exception e) {
            throw new IllegalArgumentException("ICCKEY is not a PKCS1 or PKCS8 DER RSA private key: "
                    + e.getMessage(), e);
        }

        if (acKeyHex != null && Hex.hex(acKeyHex).length != 16) {
            throw new IllegalArgumentException("ACKEY must be a double-length 3DES key (16 bytes)");
        }

        return new LoadedCard(tags, records, modulus, privateExponent, acKeyHex);
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

    static boolean isChainTag(String t) {
        String up = t.toUpperCase(Locale.ROOT);
        for (String c : CHAIN_TAGS) if (c.equals(up)) return true;
        return false;
    }
}
