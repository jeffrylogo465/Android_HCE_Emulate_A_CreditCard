package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * American Express, mag-stripe mode with CVC3.
 *
 * Kernel 4 reuses the Kernel 2 application structure - an FCI carrying 84 and
 * A5, a GPO carrying 82 and 94 - so the framing is shared with ProfileMastercard
 * and only the AID, the directory, the FCI and the AIP differ.
 *
 * WHY MAG-STRIPE AND NOT EMV MODE: CVC3 is the one offline decision a card can
 * make without the issuer's key. It is a 3DES checksum over a static track, so
 * a clone holding IMKCVC3 produces a value the terminal verifies on the spot.
 * EMV mode would instead ask for an ARQC, which needs IMK-AC. So the AIP keeps
 * the EMV-mode bit clear and msd() returns true.
 *
 * THE AIP IS 1C00. Classic EMV numbering, as Mastercard uses: 0x10 CV, 0x08
 * TRM, 0x04 issuer auth, and every ODA bit clear - SDA 0x40, DDA 0x20, CDA
 * 0x01. Byte 2 is 00. The value is not lifted off a real Amex card; nothing in
 * the dump provided one. If a terminal takes the FCI and then misbehaves, vary
 * the AIP before suspecting anything else.
 *
 * 9F2A 04 is advertised in both the directory entry and the FCI so the terminal
 * picks Kernel 4 by identifier rather than guessing from the AID prefix.
 *
 * NO IAD. Amex has no M/Chip style CVN block and cvn() would misread one, so
 * defaultIad() is empty rather than null.
 *
 * LENGTHS: the AID is 9 bytes, so every length is computed against that. PPSE
 * closes at 6F36 / A524 / BF0C22 / 6120 - 54, 36, 34 and 32 bytes of content.
 * The FCI closes at 6F22 / A515 - 34 and 21.
 */
public final class ProfileAmex implements CardProfile {

    private static final String LABEL = "414D45582042617365203031";   // "AMEX Base 01"

    private static final String PPSE =
            "6F36840E325041592E5359532E4444463031A524BF0C226120"
          + "4F09A00000002501500C" + LABEL + "8701019F2A0104";

    private static final String FCI =
            "6F228409A00000002501A515500C" + LABEL + "8701019F2A0104";

    /** See the class comment. ODA bits clear, byte 2 00. */
    private static final String AIP = "1C00";

    @Override public String name() { return "AMEX"; }

    @Override public String defaultAid() { return "A00000002501"; }

    @Override public boolean matches(String pan) {
        return pan != null && (pan.startsWith("34") || pan.startsWith("37"));
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null && aid.startsWith("A000000025");
    }

    /** Amex is mag-stripe by nature - see the class comment. */
    @Override public boolean msd() { return true; }

    /** Empty, not null: Amex has no CVN-bearing IAD to fall back to. */
    @Override public String defaultIad() { return ""; }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(PPSE);
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{
                "00A4040009A000000
