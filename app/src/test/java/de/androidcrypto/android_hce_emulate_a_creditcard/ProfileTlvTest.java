package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Structural gate on every byte a profile can serve without a compiler check.
 *
 * The directory, the FCI and the GPO are the only strings in this app whose
 * lengths are typed by hand or assembled outside tlv(). ProfileAmex shipped
 * with every one of them wrong and nothing noticed until a terminal refused it
 * after the SELECT. These tests walk all three profiles and fail the build
 * instead.
 *
 * Two things are deliberately NOT asserted here:
 *
 * - That a format 1 GPO is TLV. Its payload is two raw AIP bytes then the AFL,
 *   which is not a TLV sequence at all, so it is skipped rather than validated.
 * - That the replayed Mastercard directory carries a 9F2A. It is the plastic's
 *   own bytes, copied verbatim, and a real card is entitled to omit the kernel
 *   id; only the directories this app GENERATES have to name one.
 */
public class ProfileTlvTest {

    private static final String ATC  = "0001";
    private static final String ARQC = "0000000000000000";

    /**
     * The response body of a single script line: everything after the '=', minus
     * the trailing 9000. Null when the line carries no '='.
     */
    private static String body(String line) {
        if (line == null) return null;
        int eq = line.indexOf('=');
        if (eq < 0) return null;
        String s = line.substring(eq + 1);
        return s.endsWith("9000") ? s.substring(0, s.length() - 4) : s;
    }

    /**
     * Every hardcoded constant on every profile must balance.
     *
     * This is the test that would have caught Amex: its 4F declared 09 against a
     * six-byte AID and every outer length was wrong with it. A profile that
     * serves nothing is also a failure - the validator would otherwise skip it
     * silently.
     */
    @Test
    public void everyScriptConstantBalances() {
        for (String name : Profiles.names()) {
            if (Profiles.AUTO.equals(name)) continue;
            CardProfile p = Profiles.byName(name);
            assertNotNull("no profile registered for " + name, p);

            String[] consts = p.scriptConstants();
            assertTrue(p.name() + " serves no constants", consts.length > 0);

            for (String hex : consts) {
                String problem = TlvValidator.firstProblem(hex);
                assertNull(p.name() + ": " + problem + "\n  " + hex, problem);
            }
        }
    }

    /**
     * Any GPO that IS format 2 must balance.
     *
     * Format 1 is skipped by shape, not by profile, so a profile that later
     * switches framing is covered without touching this file. A GPO that is
     * neither (no body, or an outer tag that is not 77) is a failure, because
     * the terminal sees the raw line.
     */
    @Test
    public void everyFormat2GpoBalances() {
        for (String name : Profiles.names()) {
            if (Profiles.AUTO.equals(name)) continue;
            CardProfile p = Profiles.byName(name);

            String b = body(p.gpo(ATC, ARQC));
            assertNotNull(p.name() + " produced no GPO body", b);
            if (!b.startsWith("77")) continue;

            String problem = TlvValidator.firstProblem(b);
            assertNull(p.name() + ": " + problem + "\n  " + b, problem);
        }
    }

    /**
     * A cryptogram in the GPO must be accompanied by an IAD.
     *
     * A qVSDC kernel reads 9F26 and 9F10 together; an ARQC with no IAD is a
     * cryptogram the issuer cannot reconstruct, so it declines or the kernel
     * drops the app. Mastercard carries neither in the GPO (its AC belongs in
     * GENERATE AC), so it is skipped rather than failed.
     */
    @Test
    public void aCryptogramNeverArrivesWithoutAnIad() {
        for (String name : Profiles.names()) {
            if (Profiles.AUTO.equals(name)) continue;
            CardProfile p = Profiles.byName(name);

            String b = body(p.gpo(ATC, ARQC));
            if (b == null || !b.startsWith("77")) continue;

            byte[] tpl = Emv.hex(b);
            if (Emv.findTag(tpl, 0x9F26) == null) continue;

            assertNotNull(p.name() + " carries an ARQC but no IAD: " + b,
                    Emv.findTag(tpl, 0x9F10));
        }
    }

    /**
     * A directory this app BUILDS has to name its kernel.
     *
     * Without 9F2A the terminal picks the kernel off the AID alone and, for a
     * constructed Visa directory, lands on the wrong one. Visa qVSDC is Kernel 3
     * and ExpressPay is Kernel 4; both are asserted as full tag-and-value so a
     * one-byte length change cannot slip through.
     */
    @Test
    public void everyGeneratedDirectoryNamesItsKernel() {
        String visa = new ProfileVisa().scriptConstants()[0];
        assertTrue("Visa directory names no kernel: " + visa, visa.contains("9F2A0103"));

        String amex = new ProfileAmex().scriptConstants()[0];
        assertTrue("Amex directory names no kernel: " + amex, amex.contains("9F2A0104"));
    }
}
