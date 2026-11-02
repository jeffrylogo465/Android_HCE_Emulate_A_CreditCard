package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Visa.
 *
 * CONSTRUCTED, not replayed - there is no Visa dump behind this. The directory
 * and FCI are built around the card's own AID, one applet, label only, no 9F38,
 * so the terminal sends a PDOL-free GPO. The GPO is the same shape as the
 * Mastercard one with the institution digit in the IAD changed to 03.
 *
 * This is a first approximation and it will probably need the real Visa tags -
 * 9F66, 9F6E, 9F6D - adding once a tap shows where the kernel objects. Expect
 * to edit this file, not the service.
 */
public final class ProfileVisa implements CardProfile {

    private static final String IAD = "0110A000032400000102000000000000FF";

    @Override public String name() { return "VISA"; }

    @Override public String defaultAid() { return "A0000000031010"; }

    @Override public boolean matches(String pan) {
        return pan != null && pan.startsWith("4");
    }

    @Override public boolean matchesAid(String aid) {
        return aid != null && aid.startsWith("A000000003");
    }

    @Override public String selectPpse(String aid) {
        return Profiles.selectPpse(Profiles.hex(Profiles.oneAppPpse(aid)));
    }

    @Override public String[] selectApp(String aid, String label) {
        return new String[]{
                "00A4040007" + aid + "=" + Profiles.hex(Profiles.labelFci(aid, label)) + "9000",
        };
    }

    @Override public String gpo(String atc, String arqc) {
        return Profiles.gpo(IAD, atc, arqc);
    }
}
