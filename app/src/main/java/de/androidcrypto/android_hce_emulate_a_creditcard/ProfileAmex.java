package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * American Express, mag-stripe mode with CVC3.
 *
 * CVC3 is the one offline decision a card makes without the issuer's key: a
 * 3DES checksum over a static track. EMV mode would need an ARQC, which needs
 * IMK-AC. So AIP byte 2 is 00 (no EMV-mode bit) and msd() is true.
 *
 * AIP 1C00 is classic numbering: CV + TRM + issuer auth, every ODA bit clear.
 * The value is a guess - nothing in the dump provided one.
 *
 * 9F2A 04 goes in both the directory and the FCI so the kernel is picked by
 * identifier. No IAD: Amex has no CVN block, so defaultIad() is empty.
 */
public final class ProfileAmex implements CardProfile {

    private static final String PPSE = "6F36840E325041592E5359532E4444463031A524BF0C2261204F09A00000002501500C414D455820426173652030318701019F2A0104";

    private static final String FCI = "6F228409A00000002501A515500C414D455820426173652030318701019F2A0104";

    private static final String AIP = "1C00";

    @Override public String name() { return "AMEX"; }

    @Override public String defaultAid() { return "A00000002501"; }

    @Override public boolean matches(String pan) {
        return pan != null && (pan.startsWith("34") || pan.startsWith("37"));
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null && aid.startsWith("A000000025");
    }

    @Override public boolean msd() { return true; }

    @Override public String defaultIad() { return ""; }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(PPSE);
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{"00A4040009A0000000250100=" + FCI + "9000"};
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpoWithAip(AIP, atc);
    }
}
