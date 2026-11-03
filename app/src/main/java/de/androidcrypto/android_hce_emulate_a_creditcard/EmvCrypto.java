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

    /** Odd parity on every byte. Java's DES ignores parity, so this is spec
     *  fidelity rather than function - it does not change a single ciphertext. */
    static byte[] oddParity(byte[] k) {
        if (k == null) return null;
        for (int i = 0; i < k.length; i++) {
            int b = k[i] & 0xFF;
            int ones = Integer.bitCount(b & 0xFE);
            k[i] = (byte) ((b & 0xFE) | (ones % 2 == 0 ? 1 : 0));
        }
        return k;
    }

    /**
     * ICC master key pair, Option A.
     *
     * X = the rightmost 16 digits of PAN||PSN, left-padded with zero nibbles to
     * 16 digits when the pair is shorter. MK_L = DES3(MKiss, X),
     * MK_R = DES3(MKiss, X xor FF x 8), both odd-parity adjusted.
     *
     * The PAN/PSN step lives HERE and not in the session key: PAN and PSN never
     * reach the SK derivation, they only shape the ICC key. That is why the box
     * has to hold the issuer MK, and why feeding it straight to the SK gave a
     * wrong ARQC from a right key.
     *
     * Both CSK and SKD start here. They differ only in the session-key block.
     */
    static byte[][] iccMasterKeys(String mkissHex, String pan, String panSeq) throws Exception {
        String d = ((pan == null ? "" : pan) + (panSeq == null ? "" : panSeq))
                .replaceAll("[^0-9]", "");
        StringBuilder sb = new StringBuilder();
        for (int i = d.length(); i < 16; i++) sb.append('0');
        sb.append(d);
        d = sb.substring(sb.length() - 16);

        byte[] x = Hex.bcd(d);
        byte[] xr = new byte[8];
        for (int i = 0; i < 8; i++) xr[i] = (byte) (x[i] ^ 0xFF);

        byte[] mk = Hex.hex(mkissHex);
        return new byte[][]{ oddParity(des3(mk, x)), oddParity(des3(mk, xr)) };
    }

    /** One 8-byte SK input block: ATC || marker || 00 || UN. */
    private static byte[] skBlock(String atcHex, byte marker, byte[] un) throws Exception {
        if (un == null || un.length != 4) {
            throw new IllegalArgumentException("UN must be 4 bytes, got "
                    + (un == null ? -1 : un.length));
        }
        byte[] atc = Hex.hex(atcHex);
        if (atc.length != 2) throw new IllegalArgumentException("ATC must be 2 bytes");

        byte[] b = new byte[8];
        b[0] = atc[0];
        b[1] = atc[1];
        b[2] = marker;
        b[3] = 0x00;
        System.arraycopy(un, 0, b, 4, 4);
        return b;
    }

    /** One 8-byte CSK input block: ATC || marker || 00 x 5. No UN. */
    private static byte[] cskBlock(String atcHex, byte marker) throws Exception {
        byte[] atc = Hex.hex(atcHex);
        if (atc.length != 2) throw new IllegalArgumentException("ATC must be 2 bytes");

        byte[] b = new byte[8];
        b[0] = atc[0];
        b[1] = atc[1];
        b[2] = marker;
        return b;
    }

    /**
     * SKD from an ICC master key pair. SK_L uses MK_L over the F0 block, SK_R
     * uses MK_R over the 0F block. F0 and 0F are the complementary markers.
     */
    static byte[] sessionKeySkdRaw(byte[] mkL, byte[] mkR, String atcHex, byte[] un)
            throws Exception {
        return Tlv.cat(
                oddParity(des3(mkL, skBlock(atcHex, (byte) 0xF0, un))),
                oddParity(des3(mkR, skBlock(atcHex, (byte) 0x0F, un))));
    }

    /**
     * CSK from an ICC master key pair, Book 2 A1.3.
     *
     * The UN is NOT part of a CSK session key - it goes into the MAC input
     * instead, which is the whole reason the two schemes cannot share a
     * builder. The block is ATC || marker || 00 x 5.
     */
    static byte[] sessionKeyCskRaw(byte[] mkL, byte[] mkR, String atcHex) throws Exception {
        return Tlv.cat(
                oddParity(des3(mkL, cskBlock(atcHex, (byte) 0xF0))),
                oddParity(des3(mkR, cskBlock(atcHex, (byte) 0x0F))));
    }

    /**
     * SKD, CVN 16/17, full chain: issuer MK -> ICC master key pair -> SK.
     *
     * option is carried for signature compatibility and unused - PAN/PSN are
     * consumed by the ICC key derivation, not by the SK.
     */
    static byte[] sessionKeySkd(String mkissHex, String pan, String panSeq,
                                String atcHex, byte[] un, int option) throws Exception {
        byte[][] k = iccMasterKeys(mkissHex, pan, panSeq);
        return sessionKeySkdRaw(k[0], k[1], atcHex, un);
    }

    /**
     * CSK, CVN 20/21, full chain. option is carried and unused, as for SKD.
     *
     * This used to build a right-justified PAN||PSN and encrypt 16 bytes with
     * one key in a single pass, which is neither scheme: no ICC derivation, and
     * the Z block belonged in the ICC key, not the SK.
     */
    static byte[] sessionKeyAc(String mkAcHex, String pan, String panSeq,
                               String atcHex, int option) throws Exception {
        byte[][] k = iccMasterKeys(mkAcHex, pan, panSeq);
        return sessionKeyCskRaw(k[0], k[1], atcHex);
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
