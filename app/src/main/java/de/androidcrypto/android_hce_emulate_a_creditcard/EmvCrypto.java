package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EmvCrypto {

    /** Kept so any existing caller of EmvCrypto.hex() still compiles. */
    static byte[] hex(String s) { return Hex.hex(s); }

    static byte[] des(byte[] k8, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k8, "DES"));
        return c.doFinal(d);
    }

    static byte[] desDec(byte[] k8, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k8, "DES"));
        return c.doFinal(d);
    }

    static byte[] des3(byte[] k16or24, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k16or24, "DESede"));
        return c.doFinal(d);
    }

    /** Odd parity on every byte, as EMV requires of DES key material. */
    private static void oddParity(byte[] k) {
        for (int i = 0; i < k.length; i++) {
            int b = k[i] & 0xFF;
            int ones = Integer.bitCount(b & 0xFE);
            k[i] = (byte) ((b & 0xFE) | ((ones & 1) == 0 ? 1 : 0));
        }
    }

    /**
     * IMK-AC -> MK-AC -> SK-AC, BOTH stages, per EMV Book 2 A1.3.1 and A1.4.
     *
     * Stage 1 diversifies the IMK by the card: D_L is the rightmost 16 digits of
     * PAN||PSN as packed BCD, D_R is its bitwise inverse, and MK-AC is the two
     * DES3 results concatenated. Stage 2 diversifies MK-AC by the ATC, with the
     * blocks ATC || F0 || five zeros and ATC || 0F || five zeros.
     *
     * The old version did one DES3 under the IMK and put the ATC block where
     * MK-AC's right half belongs, so MK-AC was never formed.
     *
     * option 0 = derivation data PAN || PSN
     * option 1 = derivation data PAN || PSN || PAN
     */
    static byte[] sessionKeyAc(String imkHex, String pan, String panSeq,
                               String atcHex, int option) throws Exception {
        byte[] imk = Hex.hex(imkHex);

        byte[] z = (option == 1)
                ? Tlv.cat(Hex.bcd(pan), Hex.bcd(panSeq), Hex.bcd(pan))
                : Tlv.cat(Hex.bcd(pan), Hex.bcd(panSeq));

        byte[] dl = new byte[8];
        int n = Math.min(8, z.length);
        System.arraycopy(z, z.length - n, dl, 8 - n, n);

        byte[] dr = new byte[8];
        for (int i = 0; i < 8; i++) dr[i] = (byte) ~dl[i];

        byte[] mk = Tlv.cat(des3(imk, dl), des3(imk, dr));
        oddParity(mk);

        byte[] atc = Hex.hex(atcHex);
        byte[] bl = new byte[8];
        byte[] br = new byte[8];
        bl[0] = atc[0];
        bl[1] = atc[1];
        bl[2] = (byte) 0xF0;
        br[0] = atc[0];
        br[1] = atc[1];
        br[2] = (byte) 0x0F;

        byte[] sk = Tlv.cat(des3(mk, bl), des3(mk, br));
        oddParity(sk);
        return sk;
    }

    static byte[] sessionKeyAc(String imkHex, String pan, String panSeq, String atcHex)
            throws Exception {
        return sessionKeyAc(imkHex, pan, panSeq, atcHex, 0);
    }

    /** ISO 9797-1 MAC Algorithm 3, padding method 2. This was already correct. */
    static byte[] mac(byte[] k16, byte[] data) throws Exception {
        int pad = 8 - (data.length % 8);
        byte[] p = Arrays.copyOf(data, data.length + pad);
        p[data.length] = (byte) 0x80;
        byte[] k1 = Arrays.copyOfRange(k16, 0, 8);
        byte[] k2 = Arrays.copyOfRange(k16, 8, 16);
        byte[] x = new byte[8];
        for (int i = 0; i < p.length; i += 8) {
            for (int j = 0; j < 8; j++) x[j] ^= p[i + j];
            x = des(k1, x);
        }
        x = desDec(k2, x);
        return des(k1, x);
    }

    static byte[] arqc(String imkHex, String pan, String panSeq, String atcHex,
                       byte[] macInput, int option) throws Exception {
        return mac(sessionKeyAc(imkHex, pan, panSeq, atcHex, option), macInput);
    }

    static byte[] arqc(String imkHex, String pan, String panSeq, String atcHex, byte[] macInput)
            throws Exception {
        return arqc(imkHex, pan, panSeq, atcHex, macInput, 0);
    }

    private EmvCrypto() {}
}
