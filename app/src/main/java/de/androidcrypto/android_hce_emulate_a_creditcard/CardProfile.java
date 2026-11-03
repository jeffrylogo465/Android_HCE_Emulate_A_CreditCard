package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * One network's byte profile: the directory, the FCI, the GPO.
 *
 * msd(), defaultIad() and msdAip() have defaults so a profile only overrides
 * what its network actually does.
 */
public interface CardProfile {

    String name();

    String defaultAid();

    boolean matches(String pan);

    boolean matchesAid(String aid);

    String selectPpse(String aid);

    String[] selectApp(String aid, String label);

    String gpo(String atc, String arqc);

    /** Whether this network is mag-stripe by nature and cannot be turned off. */
    default boolean msd() { return false; }

    /** The IAD to serve when none is typed, or null for the generic default. */
    default String defaultIad() { return null; }

    /**
     * The AIP to serve in MSD, or null to mask the normal AIP instead.
     *
     * Needed because the MSD bit's meaning and position differ per network:
     * under Mastercard byte 2 b8 means EMV mode, so MSD is the ABSENCE of it
     * and a mask does the job; under Visa the same bit IS MSD, so the value
     * has to be supplied rather than derived.
     */
    default String msdAip() { return null; }
}
