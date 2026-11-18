package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Offline data authentication per EMV Book 2: the issuer and ICC certificate
 * chains, the Signed Dynamic Application Data (DDA) and the Signed Static
 * Application Data (SDA). Pure Java, no Android types. Hash is SHA-1 (algo 01).
 *
 * Nothing here hardcodes a key or certificate length. They come from the
 * recovered block and from the key the block was recovered with.
 *
 * Hash ranges (all start at the format byte, offset 1):
 *   issuer: block[1 .. len-21) || remainder || exponent
 *   ICC:    block[1 .. len-21) || remainder || exponent || staticData
 *   SDAD:   block[1 .. len-21) || DDOL data
 *   SSAD:   block[1 .. len-21) || staticData
 * The 0xBB padding sits inside block[1 .. len-21), so it IS hashed.
 */
public final class OdaVerifier {

    public enum Step {
        /** No tag 84 (AID) in the dump, or it was under 6 bytes - no RID to look a CA key up by. */
        NO_AID,
        /** An AID/RID was available, but no CA key is on file for it at this index. */
        CA_KEY,
        ISSUER_RECOVER, ISSUER_HEADER, ISSUER_LAYOUT, ISSUER_HASH,
        ICC_RECOVER, ICC_HEADER, ICC_LAYOUT, ICC_HASH,
        SDAD_RECOVER, SDAD_HEADER, SDAD_LAYOUT, SDAD_HASH,
        SSAD_RECOVER, SSAD_HEADER, SSAD_LAYOUT, SSAD_HASH,
        STATIC_DATA
    }

    public static final class Result {
        public final boolean ok;
        /** First step that failed, null when ok. */
        public final Step failedStep;
        public final String detail;
        /** Recovered issuer or ICC public key modulus (certificate steps). */
        public final byte[] modulus;
        /** PAN field of the ICC certificate (10 bytes, as stored). */
        public final byte[] pan;
        /** ICC Dynamic Data (SDAD) */
        public final byte[] dynamicData;
        /** Data Authentication Code (SSAD) */
        public final byte[] dac;

        private Result(boolean ok, Step s, String d, byte[] modulus, byte[] pan, byte[] dyn, byte[] dac) {
            this.ok = ok;
            this.failedStep = s;
            this.detail = d;
            this.modulus = modulus;
            this.pan = pan;
            this.dynamicData = dyn;
            this.dac = dac;
        }

        static Result fail(Step s, String d) {
            return new Result(false, s, d, null, null, null, null);
        }

        @Override
        public String toString() {
            return ok ? "OK" : failedStep + ": " + detail;
        }
    }

    public interface RecordSource {
        /** @return the full record (including its 70 template) or null when absent. */
        byte[] read(int sfi, int record);
    }

    private static final int ISSUER_HEADER_LEN = 15;
    private static final int ICC_HEADER_LEN = 21;
    private static final int TRAILER_LEN = 21; // 20 hash + BC

    private OdaVerifier() {
    }

    // ------------------------------------------------------------------ issuer

    /**
     * @param cert      tag 90, as long as the CA modulus
     * @param remainder tag 92, null or empty when absent
     * @param exponent  tag 9F32
     */
    public static Result verifyIssuerCert(CaKeySet.Key ca, byte[] cert, byte[] remainder, byte[] exponent) {
        if (ca == null) return Result.fail(Step.CA_KEY, "no CA key for this RID/index");
        return verifyCert("ISSUER", (byte) 0x02, ISSUER_HEADER_LEN, ca.modulus, ca.exponent,
                cert, remainder, exponent, new byte[0]);
    }

    /**
     * @param issuerModulus   recovered by {@link #verifyIssuerCert}
     * @param issuerExponent  tag 9F32
     * @param cert            tag 9F46, as long as the issuer modulus
     * @param remainder       tag 9F48, null or empty when absent
     * @param iccExponent     tag 9F47
     * @param staticData      from {@link #buildStaticData}
     */
    public static Result verifyIccCert(byte[] issuerModulus, byte[] issuerExponent, byte[] cert,
                                       byte[] remainder, byte[] iccExponent, byte[] staticData) {
        return verifyCert("ICC", (byte) 0x04, ICC_HEADER_LEN, issuerModulus, issuerExponent,
                cert, remainder, iccExponent, staticData);
    }

    private static Result verifyCert(String p, byte format, int hdr, byte[] mod, byte[] e,
                                     byte[] cert, byte[] remainder, byte[] exponent, byte[] extra) {
        Step recoverStep = Step.valueOf(p + "_RECOVER");
        Step headerStep = Step.valueOf(p + "_HEADER");
        Step layoutStep = Step.valueOf(p + "_LAYOUT");
        Step hashStep = Step.valueOf(p + "_HASH");
        byte[] rem = remainder == null ? new byte[0] : remainder;

        byte[] b = recover(mod, e, cert);
        if (b == null) return Result.fail(recoverStep, "signature length " + cert.length + " vs modulus " + mod.length);
        int len = b.length;
        if (b[0] != 0x6A) return Result.fail(headerStep, "header byte is not 6A");
        if (b[1] != format) return Result.fail(headerStep, "format byte is not " + hex(format));
        if (b[len - 1] != (byte) 0xBC) return Result.fail(headerStep, "trailer byte is not BC");
        if (b[hdr - 4] != 0x01) return Result.fail(headerStep, "hash algorithm indicator is not 01 (SHA-1)");

        int keyLen = b[hdr - 2] & 0xFF;
        int expLen = b[hdr - 1] & 0xFF;
        if (expLen != exponent.length) {
            return Result.fail(layoutStep, "exponent length field " + expLen + " vs supplied " + exponent.length);
        }
        int leftmost = keyLen - rem.length;
        if (leftmost < 0) return Result.fail(layoutStep, "remainder longer than key length");
        int region = len - hdr - TRAILER_LEN;           // bytes between header and hash
        int pad = region - leftmost;
        if (pad < 0) return Result.fail(layoutStep, "leftmost digits overrun the certificate");
        if (hdr + leftmost + pad + TRAILER_LEN != len) {
            return Result.fail(layoutStep, "header + leftmost + pad + 21 != cert length");
        }
        for (int i = hdr + leftmost; i < len - TRAILER_LEN; i++) {
            if (b[i] != (byte) 0xBB) return Result.fail(layoutStep, "pad byte at " + i + " is not BB");
        }

        byte[] expected = sha1(slice(b, 1, len - TRAILER_LEN), rem, exponent, extra);
        byte[] actual = slice(b, len - TRAILER_LEN, len - 1);
        if (!Arrays.equals(expected, actual)) return Result.fail(hashStep, "hash mismatch");

        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.write(b, hdr, leftmost);
        m.write(rem, 0, rem.length);
        // ICC-only: the issuer cert has no PAN field at all (Book 2 Table 6 -
        // confirmed against the real recovered cert, see commit history).
        // This exists for the DDA verifier (verifyIccCert's PAN comes back
        // here), not for SDA, which never calls this with format 0x02's PAN
        // in mind.
        byte[] pan = format == 0x04 ? slice(b, 2, 12) : null;
        return new Result(true, null, "", m.toByteArray(), pan, null, null);
    }

    // -------------------------------------------------------------------- SDAD

    /**
     * @param iccModulus  recovered by {@link #verifyIccCert}
     * @param sdad        tag 9F4B
     * @param ddolData    the terminal data the DDOL asked for (e.g. the UN)
     */
    public static Result verifySdad(byte[] iccModulus, byte[] iccExponent, byte[] sdad, byte[] ddolData) {
        byte[] b = recover(iccModulus, iccExponent, sdad);
        if (b == null) return Result.fail(Step.SDAD_RECOVER, "signature length " + sdad.length + " vs modulus " + iccModulus.length);
        int len = b.length;
        if (b[0] != 0x6A || b[1] != 0x05 || b[len - 1] != (byte) 0xBC) {
            return Result.fail(Step.SDAD_HEADER, "not 6A 05 .. BC");
        }
        if (b[2] != 0x01) return Result.fail(Step.SDAD_HEADER, "hash algorithm indicator is not 01 (SHA-1)");
        int ldd = b[3] & 0xFF;
        int padStart = 4 + ldd;
        if (padStart > len - TRAILER_LEN) return Result.fail(Step.SDAD_LAYOUT, "dynamic data overruns the block");
        for (int i = padStart; i < len - TRAILER_LEN; i++) {
            if (b[i] != (byte) 0xBB) return Result.fail(Step.SDAD_LAYOUT, "pad byte at " + i + " is not BB");
        }
        byte[] expected = sha1(slice(b, 1, len - TRAILER_LEN), ddolData);
        if (!Arrays.equals(expected, slice(b, len - TRAILER_LEN, len - 1))) {
            return Result.fail(Step.SDAD_HASH, "hash mismatch");
        }
        return new Result(true, null, "", null, null, slice(b, 4, padStart), null);
    }

    // --------------------------------------------------------------------- SDA

    /**
     * Full SDA per Book 2 6.2: recover the issuer certificate under the CA
     * key, rebuild the static data the AFL names, then recover and hash-check
     * the SSAD against it. No ICC key or ICC certificate anywhere in this
     * path - SDA never touches them.
     *
     * @param ca         the CA key the issuer cert claims (by RID + tag 8F)
     * @param issuerCert tag 90
     * @param issuerRem  tag 92, empty when absent
     * @param issuerExp  tag 9F32
     * @param afl        tag 94
     * @param records    the AFL-named records (see {@link #buildStaticData})
     * @param aip        tag 82
     * @param sdaTagList tag 9F4A, null when absent
     * @param ssad       tag 93, null when the dump carried none
     */
    public static Result verifySda(CaKeySet.Key ca, byte[] issuerCert, byte[] issuerRem, byte[] issuerExp,
                                   byte[] afl, RecordSource records, byte[] aip, byte[] sdaTagList, byte[] ssad) {
        Result issuer = verifyIssuerCert(ca, issuerCert, issuerRem, issuerExp);
        if (!issuer.ok) return issuer;

        byte[] staticData = buildStaticData(afl, records, aip, sdaTagList);
        if (staticData == null) return Result.fail(Step.STATIC_DATA, "could not build the AFL's static data");

        if (ssad == null) return Result.fail(Step.SSAD_RECOVER, "no tag 93 (SSAD) in the dump");
        return verifySsad(issuer.modulus, issuerExp, ssad, staticData);
    }

    // -------------------------------------------------------------------- SSAD

    /**
     * @param issuerModulus recovered by {@link #verifyIssuerCert}
     * @param ssad          tag 93
     */
    public static Result verifySsad(byte[] issuerModulus, byte[] issuerExponent, byte[] ssad, byte[] staticData) {
        byte[] b = recover(issuerModulus, issuerExponent, ssad);
        if (b == null) return Result.fail(Step.SSAD_RECOVER, "signature length " + ssad.length + " vs modulus " + issuerModulus.length);
        int len = b.length;
        if (b[0] != 0x6A || b[1] != 0x03 || b[len - 1] != (byte) 0xBC) {
            return Result.fail(Step.SSAD_HEADER, "not 6A 03 .. BC");
        }
        if (b[2] != 0x01) return Result.fail(Step.SSAD_HEADER, "hash algorithm indicator is not 01 (SHA-1)");
        // 6A, 03, hash algo, DAC(2), pad BB.., hash(20), BC
        for (int i = 5; i < len - TRAILER_LEN; i++) {
            if (b[i] != (byte) 0xBB) return Result.fail(Step.SSAD_LAYOUT, "pad byte at " + i + " is not BB");
        }
        byte[] expected = sha1(slice(b, 1, len - TRAILER_LEN), staticData);
        if (!Arrays.equals(expected, slice(b, len - TRAILER_LEN, len - 1))) {
            return Result.fail(Step.SSAD_HASH, "hash mismatch");
        }
        return new Result(true, null, "", null, null, null, slice(b, 3, 5));
    }

    // -------------------------------------------------------------- static data

    /**
     * Whether buildStaticData() right-pads its result with 0x00 to a
     * multiple of 8, per the padding sentence in Book 3 10.3. UNVERIFIED
     * against the spec text itself - only a real SDA card's own static data,
     * run through this and compared against a real terminal's verdict,
     * settles whether this padding step belongs here at all.
     */
    static final boolean STATIC_DATA_PAD = true;

    /**
     * Whether the AFL's 4th byte (the count of records, from "first", that
     * are involved in offline data authentication - Book 3 10.3) is read
     * literally (true, the default) or ignored in favour of treating every
     * record in [first, last] as an ODA record (count = last - first + 1).
     *
     * The redundancy argument for defaulting to the literal reading: Book 3
     * never requires a card to put a record in an SFI's AFL range that is
     * NOT used for ODA - there is no other reason for a record to be there
     * at all, since the AFL range outside of READ RECORD's own use is only
     * ever consulted for ODA. So on every real card we have seen, byte 4
     * already equals last-first+1, and the two readings agree; the literal
     * reading is kept as the one Book 3 actually specifies, with the
     * [first,last] reading available behind this switch for a captured dump
     * where the two disagree - e.g. a card that puts a record in the AFL for
     * READ RECORD only, outside of any ODA use, which byte 4 would then
     * correctly exclude but the switch's alternate reading would not.
     */
    static final boolean COUNT_FROM_FOURTH_BYTE = true;

    /**
     * Static data to be authenticated: the records the AFL flags for offline
     * data authentication, in AFL order (SFI 1-10: contents of the 70 template;
     * SFI 11+: the whole record), then the AIP only if the 9F4A tag list is
     * exactly tag 82, then (when STATIC_DATA_PAD) 0x00 bytes up to a multiple
     * of 8. The AFL itself is not hashed.
     *
     * The AFL walk goes through DumpChain.aflWellFormed()/afterAflEntry()
     * rather than a bare "i += 4" loop: afl here is routinely a dump's own
     * tag 94 (DumpChain.afl, passed straight through verifySda()), which
     * DumpChain.parse() already allows to carry a trailing, length-prefixed
     * AID list after its real entries (see that class's own doc). A flat
     * 4-byte walk would misread those bytes as a bogus further entry and
     * either read the wrong records into the hash or throw records.read()
     * at an SFI/record that was never really named - sharing DumpChain's
     * walk instead of a second copy keeps the two from disagreeing on what
     * the AFL "actually says" for the same dump.
     *
     * @param sdaTagList tag 9F4A, null when the card has none
     * @return the bytes, or null when a flagged record is missing or malformed
     */
    public static byte[] buildStaticData(byte[] afl, RecordSource records, byte[] aip, byte[] sdaTagList) {
        if (!DumpChain.aflWellFormed(afl)) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i + 4 <= afl.length; i = DumpChain.afterAflEntry(afl, i)) {
            int sfi = (afl[i] & 0xFF) >> 3;
            int first = afl[i + 1] & 0xFF;
            int last = afl[i + 2] & 0xFF;
            int count = COUNT_FROM_FOURTH_BYTE ? (afl[i + 3] & 0xFF) : (last - first + 1);
            for (int r = first; r < first + count; r++) {
                byte[] rec = records.read(sfi, r);
                if (rec == null) return null;
                if (sfi >= 1 && sfi <= 10) {
                    int off = templateContentOffset(rec);
                    if (off < 0) return null;
                    out.write(rec, off, rec.length - off);
                } else {
                    out.write(rec, 0, rec.length);
                }
            }
        }
        if (sdaTagList != null && sdaTagList.length > 0) {
            if (sdaTagList.length != 1 || sdaTagList[0] != (byte) 0x82) return null;
            if (aip == null) return null;
            out.write(aip, 0, aip.length);
        }
        if (STATIC_DATA_PAD) {
            int rem = out.size() % 8;
            if (rem != 0) {
                for (int i = rem; i < 8; i++) out.write(0);
            }
        }
        return out.toByteArray();
    }

    /** Offset of the content after tag 70 and its length bytes, or -1. */
    private static int templateContentOffset(byte[] rec) {
        if (rec.length < 2 || rec[0] != 0x70) return -1;
        int l = rec[1] & 0xFF;
        int off;
        if (l < 0x80) off = 2;
        else if (l == 0x81) off = 3;
        else if (l == 0x82) off = 4;
        else return -1;
        return off <= rec.length ? off : -1;
    }

    // ----------------------------------------------------------------- helpers

    /** Raw RSA public operation; null if the input is not exactly modulus-long or is >= modulus. */
    static byte[] recover(byte[] modulus, byte[] exponent, byte[] sig) {
        if (sig.length != modulus.length) return null;
        BigInteger n = new BigInteger(1, modulus);
        BigInteger s = new BigInteger(1, sig);
        if (s.compareTo(n) >= 0) return null;
        byte[] raw = s.modPow(new BigInteger(1, exponent), n).toByteArray();
        byte[] out = new byte[modulus.length];
        int copy = Math.min(raw.length, out.length);
        System.arraycopy(raw, raw.length - copy, out, out.length - copy, copy);
        return out;
    }

    private static byte[] sha1(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static byte[] slice(byte[] b, int from, int to) {
        return Arrays.copyOfRange(b, from, to);
    }

    private static String hex(byte b) {
        return String.format("%02X", b & 0xFF);
    }
}
