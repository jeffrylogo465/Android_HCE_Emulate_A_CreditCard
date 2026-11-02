package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EmvCrypto {

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

    /** SunJCE DESede refuses a 16-byte key. K1|K2|K1 is the same cipher. */
    static byte[] to24(byte[] k) {
        if (k == null) return null;
        if (k.length == 24) return k;
        if (k.length == 16) {
            byte[] k24 = new byte[24];
            System.arraycopy(k, 0, k24, 0, 16);
            System.arraycopy(k, 0, k24, 16, 8);
            return k24;
        }
        return k;
    }

    static byte[] des3(byte[] k16or24, byte[] d) throws Exception {
        byte[] k = to24(k16or24);
        if (k == null || k.length != 24) {
            throw new IllegalArgumentException("3DES key must be 16 or 24 bytes, got "
                    + (k16or24 == null ? -1 : k16or24.length));
        }
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "DESede"));
        return c.doFinal(d);
    }

    /**
     * CSK, CVN 20/21. option 0 = Option A (PAN||PSN), option 1 = Option B
     * (PAN||PSN||PAN). SK = DES3(MK, Z || ATC || F0 x 6), Z right-justified.
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

    /**
     * SKD, CVN 16/17. SK = DES3(K, ATC || F0 || 00 || UN) ||
     * DES3(K, ATC || 0F || 00 || UN). Key goes straight in; the ICC-master-key
     * step is not applied, so the vector (MK, ATC, UN) reproduces.
     */
    static byte[] sessionKeySkd(String mkAcHex, String pan, String panSeq,
                                String atcHex, byte[] un, int option) throws Exception {
        if (un == null || un.length != 4) {
            throw new IllegalArgumentException("UN must be 4 bytes, got "
                    + (un == null ? -1 : un.length));
        }
        byte[] mk = Hex.hex(mkAcHex);
        byte[] atc = Hex.hex(atcHex);
        if (atc.length != 2) throw new IllegalArgumentException("ATC must be 2 bytes");

        byte[] input = new byte[16];

        input[0] = atc[0];
        input[1] = atc[1];
        input[2] = (byte) 0xF0;
        input[3] = 0x00;
        System.arraycopy(un, 0, input, 4, 4);

        input[8] = atc[0];
        input[9] = atc[1];
        input[10] = (byte) 0x0F;
        input[11] = 0x00;
        System.arraycopy(un, 0, input, 12, 4);

        return des3(mk, input);
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

    static byte[] arqcSkd(String mkAcHex, String pan, String panSeq, String atcHex,
                          byte[] un, byte[] macInput, int option) throws Exception {
        return mac(sessionKeySkd(mkAcHex, pan, panSeq, atcHex, un, option), macInput);
    }

    /** KCV: leftmost 3 bytes of E_K(00 x 8). 0123...3210 -> 08D7B4. */
    static String kcv(String keyHex) throws Exception {
        byte[] k = Hex.hex(keyHex);
        if (k.length != 16 && k.length != 24) {
            throw new IllegalArgumentException("KCV needs a 16 or 24 byte key, got " + k.length);
        }
        byte[] e = des3(k, new byte[8]);
        return Hex.toHex(Arrays.copyOfRange(e, 0, 3));
    }
}
