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
 *
 * The last two members have defaults so an existing profile compiles unchanged.
 * They exist because two networks answer questions the first seven do not ask.
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

    /**
     * Whether this network runs mag-stripe mode with CVC3.
     *
     * Default false, so a profile that does not care is untouched. True makes
     * the service strip the EMV-mode AIP bit, serve the skeleton record at the
     * configured location and answer COMPUTE CRYPTOGRAPHIC CHECKSUM.
     *
     * It is a DEFAULT, not a lock: the card's msd pref ORs in on top, so a true
     * here means the card cannot be tapped in EMV mode. Correct for Amex, where
     * CVC3 is the only offline decision available without a key, and where the
     * AIP carries no EMV-mode bit anyway.
     */
    default boolean msd() { return false; }

    /**
     * IAD to use when the card has none typed and none captured.
     *
     * null means the service default, which is the M/Chip shape and carries a
     * CVN. An empty string means genuinely no IAD - Amex has no CVN-bearing IAD
     * and a fabricated one just puts garbage in 9F10.
     */
    default String defaultIad() { return null; }
}
