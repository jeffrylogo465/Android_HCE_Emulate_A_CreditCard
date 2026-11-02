package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * One network's terminal script.
 *
 * Everything a tap needs from the network lives in an implementation of this -
 * the directory, the FCI, any extra applet, and the GPO. ShadowApduService asks
 * the profile in force for each of those and never holds network bytes itself,
 * so adding a network is one new file and one line in Profiles and nothing else.
 *
 * The ATC and the ARQC are passed in rather than held here: they belong to the
 * transaction, not the network, and the service is the only thing that can
 * climb an ATC.
 */
public interface CardProfile {

    /** Stable name, matching the selector and the card's profile pref. */
    String name();

    /** AID to advertise when the card's own AID belongs to another network. */
    String defaultAid();

    /** Whether this profile is the right one for a PAN. */
    boolean matches(String pan);

    /** Whether an AID belongs to this network, so a typed one is kept. */
    boolean matchesAid(String aid);

    /** One script line: SELECT PPSE and its directory response. */
    String selectPpse(String aid);

    /** One script line per applet this network answers. */
    String[] selectApp(String aid, String label);

    /** The GPO script line, with the live ATC and cryptogram. */
    String gpo(String atc, String arqc);
}
