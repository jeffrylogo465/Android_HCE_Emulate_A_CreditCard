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

    /**
     * SunJCE DESede rejects a 16-byte key with InvalidKeyException "Wrong key
     * size", which is exactly the length an EMV AC key has. Expand K1|K2 to
     * K1|K2|K1 - byte-identical to two-key 3DES, so no output changes - and the
     * throw stops.
     *
     * Every des3 caller was affected: kcv, both session keys, and therefore
     * every ARQC. computeAc caught the throw and returned eight zero bytes, so
     * the failure looked like a wrong key rather than a wrong call.
     */
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
     * EMV Book 2 A1.3.1 session key derivation, CSK. CVN 20/21 only.
     *
     * option 0 = Option A, derivation data PAN || PSN
     * option 1 = Option B, derivation data PAN || PSN || PAN
     *
     * SK = DES3(MK, Z || A
