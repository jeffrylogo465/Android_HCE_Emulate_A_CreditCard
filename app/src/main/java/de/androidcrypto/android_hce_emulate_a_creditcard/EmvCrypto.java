package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EmvCrypto {

    static byte[] hex(String s) {
        s = s.replaceAll("[^0-9A-Fa-f]", "");
        if (s.length() % 2 != 0) s = s + "F";
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

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

    static byte[] des3(byte[] k16, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k16, "DESede"));
        return c.doFinal(d);
    }

    /**
     * Session key derivation.
     * option 0 = EMV Option A, derivation data PAN || PSN
     * option 1 = EMV Option B, derivation data PAN || PSN || PAN
     * Same key hierarchy either way. A wrong choice makes a correct key test wrong.
     */
    static byte[] sessionKeyAc(String mkAcHex, String pan, String panSeq, String atcHex, int option)
            throws Exception {
        byte[] mk = hex(mkAcHex);
        String zHex = (option == 1) ? (pan + panSeq + pan) : (pan + panSeq);
        byte[] z = hex(zHex);
        byte[] z8 = new byte[8];
        int n = Math.min(8, z.length);
        System.arraycopy(z, z.length - n, z8, 8 - n, n);
        byte[] sk = des3(mk, z8);
        return des3(sk, hex(atcHex + "F0F0F0F0F0F0"));
    }

    static byte[] sessionKeyAc(String mkAcHex, String pan, String panSeq, String atcHex)
            throws Exception {
        return sessionKeyAc(mkAcHex, pan, panSeq, atcHex, 0);
    }

    /** ISO 9797-1 MAC Algorithm 3, padding method 2. */
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
}
