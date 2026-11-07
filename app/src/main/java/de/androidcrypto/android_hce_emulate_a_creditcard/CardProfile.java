package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * One network's byte profile: the directory, the FCI, the GPO.
 *
 * msd(), defaultIad(), msdAip(), msdRecord() and msdScript() have defaults so a
 * profile only overrides what its network actually does.
 */
public interface CardProfile {

    String name();
    String defaultAid();
    boolean matches(String pan);
    boolean matchesAid(String aid);
    String selectPpse(String aid);
    String[] selectApp(String aid, String label);
    String gpo(String atc, String arqc);

    /**
     * Every hardcoded TLV this profile can serve, for TlvValidator.
     *
     * The directory and the FCI are the only bytes in this app whose lengths are
     * typed by hand, so they are the only ones a compiler cannot catch. Amex
     * shipped with every one of them wrong and nothing noticed until a terminal
     * refused it. ProfileTlvTest walks all three profiles and gates the build.
     *
     * Not a default: a profile that serves a directory has to say what is in it,
     * or the validator silently skips the only bytes that can go wrong.
     */
    String[] scriptConstants();

    /** Whether this network is mag-stripe by nature and cannot be turned off. */
    default boolean msd() { return false; }

    /**
     * The IAD to serve when none is typed. Null means "fall through to the
     * generic default"; an EMPTY string means "serve no IAD at all".
     *
     * The distinction is load-bearing: Amex returns "" so it cannot inherit the
     * M/Chip CVN block, which cvn() would then read.
     */
    default String defaultIad() { return null; }

    /**
     * The AIP to serve in MSD, or null to mask the normal AIP instead.
     *
     * Needed because the MSD bit's meaning and position differ per network:
     * under Mastercard byte 2 b8 means EMV mode, so MSD is the ABSENCE of it
     * and a mask does the job; under Visa the same bit IS MSD, so the value has
     * to be supplied rather than derived.
     */
    default String msdAip() { return null; }

    /**
     * The MSD record for a dump, as hex, with the CSC carved where this network
     * puts it. Null when the network has no mag-stripe shape.
     *
     * The length arithmetic belongs here rather than in the activity: a record
     * whose lengths are typed by hand desyncs the moment a PAN or DD changes
     * length, and the failure is silent.
     */
    default String msdRecord(String pan, String expiry, String svc, String dd) { return null; }

    /**
     * The replay script that serves the GPO and the CCC with no key.
     *
     * Both bodies go through Tlv.t so every length is computed. A hand-written
     * %02X is a minimum width, not a cap, and it also truncates against an
     * odd-length CSC - Tlv.t removes both classes of bug.
     *
     * The CCC line is keyed on 80AE alone, never 80AE8000: P1 varies by terminal
     * and scriptMatch matches by prefix, so a longer key misses and falls
     * through to ccc(), which needs an IMKCVC3 a dump cannot supply.
     */
    default String msdScript(String csc, String atc) {
        if (csc == null || csc.isEmpty() || atc == null || atc.isEmpty()) return null;
        String c = csc.length() % 2 != 0 ? csc + "F" : csc;

        byte[] body = Tlv.cat(
                Tlv.t(0x9F61, Hex.hex(c)),
                Tlv.t(0x9F36, Hex.hex(atc)));

        return "80A80000=80061880080101009000" + "\n"
                + "80AE=" + Hex.toHex(Tlv.t(0x77, body)) + "9000";
    }
}
