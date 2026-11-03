package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * American Express, modelled on ProfileMastercard.
 *
 * Kernel 4 uses the same application structure as Kernel 2 - an FCI carrying
 * 84 and A5, a GPO carrying 82 and 94, and the AC in GENERATE AC - so the
 * builders and the shape are reused verbatim. Only the AID, the directory and
 * the FCI differ.
 *
 * THE AIP IS THE GUESS. 1880 mirrors the Mastercard profile: CV and TRM set,
 * every ODA bit clear, EMV mode in byte 2. Amex numbers its AIP bits by the
 * classic table as Mastercard does, but the value itself is not lifted from a
 * real Amex card - nothing in the dump provided one. If a terminal takes the
 * FCI and then misbehaves, vary the AIP before suspecting anything else.
 *
 * No 9F38 in the FCI, so the terminal sends a PDOL-free GPO, same as Mastercard.
 *
 * LENGTHS: the AID is 9 bytes, so every outer length is computed against that.
 * PPSE closes at 6F32 / A520 / BF0C1E / 611C - 50, 34, 32 and 30 bytes of
 * content. The FCI closes at 6F1E / A511 - 30 and 17.
 */
public final class ProfileAmex implements CardProfile {

    private static final String PPSE =
            "6F32840E325041592E5359532E4444463031A520BF0C1E611C4F09A0000000250150"
          + "0C414D45582042617365203031" + "870101";

    private static final String FCI =
            "6F1E8409A00000002501A511500C414D45582042617365203031" + "870101";

    /** Mirrors the Mastercard AIP. See the class comment - this is the guess. */
    private static final String AIP = "1880";

    @Override public String name() { return "AMEX"; }

    @Override public String defaultAid() { return "A00000002501"; }

    @Override public boolean matches(String pan) {
        return pan != null && (pan.startsWith("34") || pan.startsWith("37"));
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null && aid.startsWith("A000000025");
    }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(PPSE);
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{
                "00A4040009A0000000250100=" + FCI + "9000",
        };
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoMastercard(atc, arqc);
    }
}
