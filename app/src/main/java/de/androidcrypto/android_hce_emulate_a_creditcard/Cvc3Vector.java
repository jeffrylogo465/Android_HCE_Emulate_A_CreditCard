package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Arrays;

/**
 * Stage 1. CVC3 known-answer harness. Run before any tap.
 *
 * Constants only - nothing comes from prefs, so a failure cannot be a stale box
 * and a pass cannot be a coincidence. Structure is asserted before values, so a
 * layout bug reports as a layout bug rather than as a value mismatch.
 *
 * GOLDEN is a regression baseline recorded from the first clean run, not an
 * oracle. Cross-check kd and cvc3 once against an HSM or a reference tool;
 * after that the assertion catches drift.
 */
public final class Cvc3Vector {

    static final String MK  = "0123456789ABCDEFFEDCBA9876543210";
    static final String PAN = "371234567890123";
    static final String PSN = "01";
    static final String ATC = "0001";
    static final String IV  = "3E01";
    static final String UN  = "11223344";

    private static String GOLDEN = null;
    public static void setGolden(String hex) { GOLDEN = hex; }

    public static String run() {
        StringBuilder r = new StringBuilder();
        int fail = 0;
        try {
            byte[][] k = EmvCrypto.iccMasterKeys(MK, PAN, PSN);
            byte[] kd = Tlv.cat(k[0], k[1]);
            r.append("iccL    ").append(Hex.toHex(k[0])).append('\n');
            r.append("iccR    ").append(Hex.toHex(k[1])).append('\n');
            r.append("kd      ").append(Hex.toHex(kd)).append('\n');

            if (k[0].length != 8 || k[1].length != 8) {
                r.append("FAIL halves ").append(k[0].length).append('/')
                 .append(k[1].length).append(", want 8/8\n"); fail++;
            }
            if (Arrays.equals(kd, Hex.hex(MK))) {
                r.append("FAIL kd == mk, derivation is a no-op\n"); fail++;
            }
            if (Arrays.equals(kd, new byte[16])) {
                r.append("FAIL kd is zero\n"); fail++;
            }

            byte[] block = Tlv.cat(Hex.hex(IV), Hex.hex(UN), Hex.hex(ATC));
            r.append("block   ").append(Hex.toHex(block)).append('\n');
            if (!Arrays.equals(Arrays.copyOfRange(block, 2, 6), Hex.hex(UN))) {
                r.append("FAIL un not at 2-5, block order wrong\n"); fail++;
            }
            if (!Arrays.equals(Arrays.copyOfRange(block, 6, 8), Hex.hex(ATC))) {
                r.append("FAIL atc not at 6-7, block order wrong\n"); fail++;
            }

            byte[] cvc3 = Arrays.copyOfRange(EmvCrypto.des3(kd, block), 6, 8);
            r.append("cvc3    ").append(Hex.toHex(cvc3)).append('\n');
            r.append("kcv(kd) ").append(EmvCrypto.kcv(Hex.toHex(kd))).append('\n');

            if (Arrays.equals(cvc3, new byte[2])) {
                r.append("FAIL cvc3 0000 - the zero fallback fired\n"); fail++;
            }
            byte[] alt = block.clone();
            alt[7] ^= 0x01;
            if (Arrays.equals(cvc3, Arrays.copyOfRange(EmvCrypto.des3(kd, alt), 6, 8))) {
                r.append("FAIL atc does not reach the block\n"); fail++;
            }

            String got = Hex.toHex(cvc3);
            if (GOLDEN == null) {
                r.append("GOLDEN unset - record ").append(got).append(" and re-run\n");
            } else if (!GOLDEN.equalsIgnoreCase(got)) {
                r.append("FAIL golden ").append(GOLDEN).append(" != ").append(got).append('\n');
                fail++;
            }
            r.append(fail == 0 ? "\nSTAGE 1 PASS" : "\nSTAGE 1 FAIL (" + fail + ")");
        } catch (Exception e) {
            r.append("\nSTAGE 1 FAIL - threw ").append(e).append('\n');
        }
        return r.toString();
    }

    private Cvc3Vector() { }
}
