package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * The scheme-specific byte shape a real brand AID gets when a terminal falls
 * back off AssetCardEngine's own fictional AID (AFFFFFFFFF1234) onto one it
 * actually recognises.
 *
 * Before this existed, AssetCardEngine.selectAs() rewrote only the DF name
 * (tag 84) and left every other byte Mastercard-shaped - AIP, label, 9F12,
 * the CA index in the ICC's own record data - no matter which AID a terminal
 * selected. A Visa or Amex kernel reading those bytes under its own AID was
 * being handed another scheme's card.
 *
 * What is deliberately SHARED and not split per scheme: the certificate
 * chain (90, 92, 9F32, 9F46, 9F47, 9F49) and the ICC private key behind
 * INTERNAL AUTHENTICATE. The CA Public Key Index (8F) is a terminal-side
 * lookup pointer, never bytes embedded inside the certificate itself, so
 * three brands pointing at the same issuer/ICC key pair under three
 * different (fictional) indices is exactly how a real co-badged card would
 * look, and it costs nothing - no terminal that would ever recognise the
 * cert's own hash exists anyway, see .claude/todo.md.
 *
 * Also deliberately unchanged: the wire mechanism. GPO still answers AIP+AFL
 * in a format-2 77 template, READ RECORD still walks the AFL, GENERATE AC
 * still computes the cryptogram from CDOL1/CDOL2. Only the presentation
 * bytes below vary; this is not qVSDC's GPO-carries-the-cryptogram shape.
 */
enum AssetSchemeProfile {

    // 9F2A kernel ids for these AIDs come from ShadowApduService.kernelFor(),
    // the same prefix table buildAssetPpse()'s directory entries already use
    // for every other scheme (2 Mastercard, 3 Visa, 4 ExpressPay/Amex) - not
    // repeated here, so there is one table, not two that can drift apart.
    MASTERCARD("A0000000041010", "EF", "MASTERCARD", null, null),
    VISA("A0000000031010", "94", "VISA", "9F6604", null),
    AMEX("A0000000250101", "05", "AMEX",
            null,
            // Amex's own CVM list (8E): zero amount thresholds, "No CVM
            // Required" if the terminal supports it and as the final
            // fallback rule - deliberately NOT the shared list's bytes.
            "00000000000000001F031F00");

    final String aid;
    final String caIndex;
    final String label;
    final String preferredName;
    private final String pdolBrandTag;
    private final String cvmListOverride;

    AssetSchemeProfile(String aid, String caIndex, String label,
                        String pdolBrandTag, String cvmListOverride) {
        this.aid = aid;
        this.caIndex = caIndex;
        this.label = label;
        this.pdolBrandTag = pdolBrandTag;
        this.cvmListOverride = cvmListOverride;
        StringBuilder sb = new StringBuilder(label);
        while (sb.length() < 16) sb.append(' ');
        this.preferredName = Hex.toHex(sb.toString().getBytes(StandardCharsets.US_ASCII));
    }

    /** MC/Visa/Amex AIP: same bit layout, same DDA capability as the shared ICC key. */
    String aip() { return "3C00"; }

    /** The PDOL (raw DOL bytes for tag 9F38): this scheme's brand tag, if any, then the base set. */
    String pdol(String base) { return pdolBrandTag == null ? base : pdolBrandTag + base; }

    /** The 8E this scheme serves, or null to use the shared/default list. */
    String cvmListOverride() { return cvmListOverride; }

    /** The scheme whose AID this is, or null when it matches none of the three. */
    static AssetSchemeProfile byAid(byte[] aidBytes) {
        if (aidBytes == null) return null;
        String hex = Hex.toHex(aidBytes).toUpperCase(Locale.ROOT);
        for (AssetSchemeProfile s : values()) if (s.aid.equalsIgnoreCase(hex)) return s;
        return null;
    }
}
