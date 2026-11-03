package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Arrays;

/**
 * Stage 1. CVC3 harness. Run before any tap; if this fails, stop.
 *
 * Constants only - nothing is read from prefs, so a failure cannot be a stale
 * box and a pass cannot be a coincidence. The values are the ones the staged
 * vector in MainActivity already uses, so the two agree by construction.
 *
 * Structure asserts run before the value assert, so a layout bug reports as a
 * layout bug instead of as a golden mismatch.
 */
public final class Cvc3Vector {

    static final String MK  = "0123456789ABCDEFFEDCBA9876543210";
    static final String PAN = "5413330089600010";
    static final String PSN = "01";
    static final String ATC = "0001";
    static final String IV  = "3E01";
    static final String UN  = "12345678";

    static final String GOLDEN_KD   = "438F4A976EC80DB3F4D31C0DCB32A226";
    static final String GOLDEN_CVC3 = "CF70";

    public static String run() {
        StringBuilder r = new StringBuilder();
        int fail = 0;
        try {
            byte[] kat = EmvCrypto.des(Hex.hex("133457799BBCDFF1"), Hex.hex("0123456789ABCDEF"));
            r.append("des kat ").append(Hex.toHex(kat)).append('\n');
            if (!"85E813540F0AB405".equals(Hex.toHex(kat))) {
                return r.append("FAIL stage 0 DES KAT\n").toString();
            }

            byte[][] k = EmvCrypto.iccMasterKeys(MK, PAN, PSN);
            String kd = Hex.toHex(k[0]) + Hex.toHex(k[1]);
            r.append("kd      ").append(kd).append('\n');
            if (!GOLDEN_KD.equals(kd)) {
                return r.append("FAIL kd want ").append(GOLDEN_KD).append('\n').toString();
            }

            byte[] block = Tlv.cat(Hex.hex(IV), Hex.hex(UN), Hex.hex(ATC));
            r.append("block   ").append(Hex.toHex(block)).append('\n');
            if (!Arrays.equals(Arrays.copyOfRange(block, 2, 6), Hex.hex(UN))) {
                r.append("FAIL un not at 2-5\n"); fail++;
            }
            if (!Arrays.equals(Arrays.copyOfRange(block, 6, 8), Hex.hex(ATC))) {
                r.append("FAIL atc not at 6-7\n"); fail++;
            }

            byte[] key = Hex.hex(kd);
            String ct = Hex.toHex(EmvCrypto.des3(key, block));
            String cvc3 = ct.substring(12);
            r.append("ct      ").append(ct).append('\n');
            r.append("cvc3    ").append(cvc3).append('\n');

            if (!GOLDEN_CVC3.equals(cvc3)) {
                r.append("FAIL cvc3 want ").append(GOLDEN_CVC3).append('\n'); fail++;
            }

            byte[] alt = block.clone();
            alt[7] ^= 0x01;
            if (cvc3.equals(Hex.toHex(EmvCrypto.des3(key, alt)).substring(12))) {
                r.append("FAIL atc does not reach the block\n"); fail++;
            }

            r.append(fail == 0 ? "\nSTAGE 1 PASS" : "\nSTAGE 1 FAIL (" + fail + ")");
        } catch (Exception e) {
            r.append("\nSTAGE 1 FAIL - threw ").append(e).append('\n');
        }
        return r.toString();
    }

    private Cvc3Vector() { }
}
