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

    /**
     * EMV Book 2 A1.3.1 session key derivation.
     *
     * option 0 = Option A, derivation data PAN || PSN
     * option 1 = Option B, derivation data PAN || PSN || PAN
     *
     * SK = DES3(MK, Z || ATC || F0F0F0F0F0F0), with Z right-justified in 8 bytes.
     *
     * FIX 1: this is ONE DES3 over 16 bytes. The old code did two DES3 calls and
     *        handed an 8-byte result back to des3(), which wants 16 or 24.
     * FIX 2: derivation data is built by concatenating BCD BYTE ARRAYS, not by
     *        joining strings and hex-decoding. Joining strings puts the odd-length
     *        pad nibble after the PSN instead of inside the PAN:
     *          broken: 01 14 99 43 20 07 70 40 1F
     *          correct:01 14 99 43 20 07 70 4F 01
     *        Different bytes -> different session key -> wrong ARQC.
     */
    static byte[] sessionKeyAc(String mkAcHex, String pan, String panSeq,
                               String atcHex, int option) throws Exception {
        byte[] mk = Hex.hex(mkAcHex);

        byte[] z = (option == 1)
                ? Tlv.cat(Hex.bcd(pan), Hex.bcd(panSeq), Hex.bcd(pan))
                : Tlv.cat(Hex.bcd(pan), Hex.bcd(panSeq));

        byte[] z8 = new byte[8];
        int n = Math.min(8, z.length);
        System.arraycopy(z, z.length - n, z8, 8 - n, n);

        byte[] atc = Hex.hex(atcHex);
        byte[] input = new byte[16];
        System.arraycopy(z8, 0, input, 0, 8);
        input[8] = atc[0];
        input[9] = atc[1];
        Arrays.fill(input, 10, 16, (byte) 0xF0);

        return des3(mk, input);
    }

    static byte[] sessionKeyAc(String mkAcHex, String pan, String panSeq, String atcHex)
            throws Exception {
        return sessionKeyAc(mkAcHex, pan, panSeq, atcHex, 0);
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

    static byte[] arqc(String mkAcHex, String pan, String panSeq, String atcHex,
                       byte[] macInput, int option) throws Exception {
        return mac(sessionKeyAc(mkAcHex, pan, panSeq, atcHex, option), macInput);
    }

    static byte[] arqc(String mkAcHex, String pan, String panSeq, String atcHex, byte[] macInput)
            throws Exception {
        return arqc(mkAcHex, pan, panSeq, atcHex, macInput, 0);
    }

    private EmvCrypto() {}
}
