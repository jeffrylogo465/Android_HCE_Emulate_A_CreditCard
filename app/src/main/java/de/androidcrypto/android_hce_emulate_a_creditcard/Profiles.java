package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The profile registry, and the byte builders every profile shares.
 *
 * forPan() is the automatic path - it reads the network off the PAN prefix.
 * byName() is the manual override from the selector. AUTO means "ask the PAN",
 * and an unrecognised prefix falls through to Mastercard.
 */
public final class Profiles {

    public static final String AUTO = "AUTO";

    private static final String PPSE = "325041592E5359532E4444463031";

    /**
     * AIP for the Mastercard profile: 18 80.
     *
     * BYTE 1 - classic EMV, not the Visa meaning:
     *   0x80 RFU  0x40 SDA  0x20 DDA  0x10 CV
     *   0x08 TRM  0x04 issuer auth  0x02 on-device CVM  0x01 CDA
     *
     * 0x18 = CV + TRM. Every ODA bit is clear - a clone cannot sign static data
     * and has no 9F4A or certificates, so claiming them invites a failed check.
     *
     * BYTE 2 b8 is "EMV mode supported". It stays on here; the MSD path is
     * entered from the other side, by the service masking this byte.
     */
    private static final String AIP_MC = "1880";

    /** Visa: 58 00. b8 is mag-stripe, b7 is qVSDC. 0x58 = qVSDC + CV + TRM. */
    private static final String AIP_VISA = "5800";

    /** One AFL entry, TLV-wrapped: SFI 1, rec 1 to 1, none for offline auth. */
    private static final String AFL_ONE = "940408010100";

    /**
     * The same AFL entry RAW, for format 1.
     *
     * A tag 80 body is AIP || AFL with no inner TLVs - the 94 wrapper is
     * format 2 shape and belongs only inside a 77. SFI 1, rec 1 to 1, none for
     * offline auth.
     */
    private static final String AFL_RAW = "08010100";

    /**
     * Visa CTQ (9F6C): 30 = go online and switch interface if ODA fails.
     * VISA ONLY - in Kernel 2 the same tag is the mag-stripe app version.
     */
    private static final String CTQ_VISA = "9F6C023080";

    private static final CardProfile[] ALL = {
            new ProfileMastercard(),
            new ProfileVisa(),
            new ProfileAmex(),
    };

    private Profiles() { }

    /** Selector entries, AUTOMATICO first like the reference app. */
    public static String[] names() {
        String[] out = new String[ALL.length + 1];
        out[0] = AUTO;
        for (int i = 0; i < ALL.length; i++) out[i + 1] = ALL[i].name();
        return out;
    }

    public static CardProfile byName(String name) {
        if (name == null) return null;
        for (CardProfile p : ALL) if (p.name().equalsIgnoreCase(name.trim())) return p;
        return null;
    }

    /** The profile a PAN belongs to, or null when no prefix matches. */
    public static CardProfile forPan(String pan) {
        if (pan == null || pan.isEmpty()) return null;
        for (CardProfile p : ALL) if (p.matches(pan)) return p;
        return null;
    }

    /** The profile
