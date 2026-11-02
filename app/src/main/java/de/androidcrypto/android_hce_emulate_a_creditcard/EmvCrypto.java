package com.jeffrylogo.android_hce_emulate_a_creditcard;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Card-side cryptogram primitives.
 *
 * Two session-key schemes live here:
 *   CSK  - EMV Common Session Key, CVN 20/21. ATC only.
 *   SKD  - Mastercard Proprietary Session Key Derivation, CVN 16. ATC plus UN.
 *
 * Dispatch happens on CVN, which the caller reads out of IAD byte 2.
 * CVN 16 is the scheme the reference card actually declares.
 */
public final class EmvCrypto {

    private EmvCrypto() {}

    /* ---------------- byte helpers ---------------- */

    public static byte[] hex(String s) {
        if (s == null) return new byte[0];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                sb.append(c);
            }
        }
        if ((sb.length() & 1) == 1) sb.append('F');
        byte[] out = new byte[sb.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(sb.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String toHex(byte[] b) {
        if (b == null) return "";
        final char[] d = "0123456789ABCDEF".toCharArray();
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            out[i * 2] = d[(b[i] >> 4) & 0x0F];
            out[i * 2 + 1] = d[b[i] & 0x0F];
        }
        return new String(out);
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) if (p != null) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            if (p == null) continue;
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    public static byte[] xor(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    /* ---------------- primitives ---------------- */

    static byte[] des(byte[] key8, byte[] data, boolean encrypt) throws Exception {
        if (key8 == null || key8.length != 8) {
            throw new IllegalArgumentException("DES key must be 8 bytes, got "
                    + (key8 == null ? -1 : key8.length));
        }
        SecretKeySpec k = new SecretKeySpec(key8, "DES");
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, k);
        return c.doFinal(data);
    }

    static byte[] desDec(byte[] key8, byte[] data) throws Exception {
        return des(key8, data, false);
    }

    /**
     * SunJCE's DESede rejects 16-byte keys outright with InvalidKeyException
     * "Wrong key size". Expand K1|K2 to K1|K2|K1, which is byte-identical to
     * two-key 3DES, so output is unchanged and the exception stops.
     */
    static byte[] to24(byte[] key) {
        if (key == null) return null;
        if (key.length == 24) return key;
        if (key.length == 16) {
            byte[] out = new byte[24];
            System.arraycopy(key, 0, out, 0, 16);
            System.arraycopy(key, 0, out, 16, 8);
            return out;
        }
        return key;
    }

    static byte[] des3(byte[] key, byte[] data, boolean encrypt) throws Exception {
        byte[] k24 = to24(key);
        if (k24 == null || k24.length != 24) {
            throw new IllegalArgumentException("3DES key must be 16 or 24 bytes, got "
                    + (key == null ? -1 : key.length));
        }
        SecretKeySpec k = new SecretKeySpec(k24, "DESede");
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, k);
        return c.doFinal(data);
    }

    public static void oddParity(byte[] b) {
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xFE;
            int ones = Integer.bitCount(v);
            if ((ones & 1) == 0) v |= 1;
            b[i] = (byte) v;
        }
    }

    /* ---------------- key derivation ---------------- */

    /** KCV = leftmost 3 bytes of E_K(00 x 8). */
    public static String kcv(byte[] key) throws Exception {
        if (key == null || (key.length != 16 && key.length != 24)) {
            throw new IllegalArgumentException("KCV needs a 16 or 24 byte key, got "
                    + (key == null ? -1 : key.length));
        }
        byte[] enc = des3(key, new byte[8], true);
        return toHex(new byte[]{enc[0], enc[1], enc[2]});
    }

    /**
     * EMV CSK Option A ICC master key from an issuer master key.
     * A = (PAN || PSN), right padded with 00 to 16 bytes, left truncated to 16.
     * A gets odd parity. K1 = 3DES(A), K2 = 3DES(A XOR FF).
     */
    public static byte[] cardKey(byte[] mk, String pan, String psn) throws Exception {
        if (mk == null || (mk.length != 16 && mk.length != 24)) {
            throw new IllegalArgumentException("IMK must be 16 or 24 bytes, got "
                    + (mk == null ? -1 : mk.length));
        }
        if (pan == null || pan.length() < 10) {
            throw new IllegalArgumentException("PAN too short");
        }
        String panHex = (pan.length() & 1) == 1 ? pan + "F" : pan;
        String psnHex = psn == null ? "00" : ((psn.length() & 1) == 1 ? "0" + psn : psn);

        byte[] raw = concat(hex(panHex), hex(psnHex));
        byte[] a = new byte[16];
        if (raw.length >= 16) {
            System.arraycopy(raw, raw.length - 16, a, 0, 16);
        } else {
            System.arraycopy(raw, 0, a, 0, raw.length);
        }
        oddParity(a);

        byte[] b = new byte[16];
        for (int i = 0; i < 16; i++) b[i] = (byte) (a[i] ^ 0xFF);

        byte[] k1 = des3(mk, a, true);
        byte[] k2 = des3(mk, b, true);
        byte[] k = new byte[16];
        System.arraycopy(k1, 0, k, 0, 8);
        System.arraycopy(k2, 0, k, 8, 8);
        return k;
    }

    /* ---------------- session keys ---------------- */

    /**
     * EMV CSK session key, CVN 20/21.
     * SK = 3DES_K[ATC || F0 || 0000000000] || 3DES_K[ATC || 0F || 0000000000]
     */
    public static byte[] sessionKeyCsk(byte[] iccMk, byte[] atc) throws Exception {
        byte[] blkA = concat(atc, hex("F00000000000"));
        byte[] blkB = concat(atc, hex("0F0000000000"));
        return concat(des3(iccMk, blkA, true), des3(iccMk, blkB, true));
    }

    /**
     * Mastercard Proprietary SKD session key, CVN 16.
     * SK = 3DES_K[ATC || F0 || 00 || UN] || 3DES_K[ATC || 0F || 00 || UN]
     * The UN is the 4-byte unpredictable number from the GENERATE AC command.
     */
    public static byte[] sessionKeySkd(byte[] iccMk, byte[] atc, byte[] un) throws Exception {
        if (atc == null || atc.length != 2) {
            throw new IllegalArgumentException("ATC must be 2 bytes");
        }
        if (un == null || un.length != 4) {
            throw new IllegalArgumentException("UN must be 4 bytes, got "
                    + (un == null ? -1 : un.length));
        }
        byte[] blkA = concat(atc, hex("F000"), un);
        byte[] blkB = concat(atc, hex("0F00"), un);
        return concat(des3(iccMk, blkA, true), des3(iccMk, blkB, true));
    }

    /* ---------------- MAC ---------------- */

    /**
     * ISO 9797-1 MAC Algorithm 3, 2-key TDES, padding method 2.
     * CBC with K1, then D_K2, then E_K1 over the final block.
     */
    public static byte[] mac(byte[] sk, byte[] data) throws Exception {
        if (sk == null || sk.length != 16) {
            throw new IllegalArgumentException("MAC key must be 16 bytes, got "
                    + (sk == null ? -1 : sk.length));
        }
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        System.arraycopy(sk, 0, k1, 0, 8);
        System.arraycopy(sk, 8, k2, 0, 8);

        int padLen = 8 - (data.length % 8);
        byte[] msg = new byte[data.length + padLen];
        System.arraycopy(data, 0, msg, 0, data.length);
        msg[data.length] = (byte) 0x80;

        byte[] y = new byte[8];
        for (int off = 0; off < msg.length; off += 8) {
            byte[] blk = new byte[8];
            System.arraycopy(msg, off, blk, 0, 8);
            y = des(k1, xor(y, blk), true);
        }
        y = desDec(k2, y);
        return des(k1, y, true);
    }

    /** ARQC over an arbitrary MAC input. */
    public static byte[] arqc(byte[] sk, byte[] macIn) throws Exception {
        return mac(sk, macIn);
    }
}
