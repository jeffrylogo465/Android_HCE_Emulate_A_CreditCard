package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A set of CA public keys, looked up by RID (5 bytes) + index (tag 8F).
 * Pure Java, no Android types.
 *
 * Text format, one key per line, whitespace separated, hex:
 *   RID INDEX EXPONENT MODULUS
 * Blank lines and lines starting with '#' are ignored. Lengths come from the
 * hex itself; nothing here knows a key size.
 */
public final class CaKeySet {

    public static final class Key {
        public final byte[] rid;
        public final int index;
        public final byte[] exponent;
        public final byte[] modulus;

        public Key(byte[] rid, int index, byte[] exponent, byte[] modulus) {
            this.rid = rid.clone();
            this.index = index & 0xFF;
            this.exponent = exponent.clone();
            this.modulus = modulus.clone();
        }
    }

    private final List<Key> keys = new ArrayList<>();

    public void add(Key k) {
        keys.add(k);
    }

    public int size() {
        return keys.size();
    }

    /** @return the key, or null when no key has this RID and index. */
    public Key find(byte[] rid, int index) {
        for (Key k : keys) {
            if (k.index == (index & 0xFF) && Arrays.equals(k.rid, rid)) return k;
        }
        return null;
    }

    public static Key parseLine(String line) {
        String[] f = line.trim().split("\\s+");
        if (f.length != 4) {
            throw new IllegalArgumentException("expected RID INDEX EXPONENT MODULUS, got " + f.length + " fields");
        }
        byte[] idx = fromHex(f[1]);
        if (idx.length != 1) throw new IllegalArgumentException("index must be one byte");
        return new Key(fromHex(f[0]), idx[0], fromHex(f[2]), fromHex(f[3]));
    }

    public static CaKeySet load(Reader r) throws IOException {
        CaKeySet set = new CaKeySet();
        BufferedReader br = new BufferedReader(r);
        String line;
        while ((line = br.readLine()) != null) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            set.add(parseLine(t));
        }
        return set;
    }

    static byte[] fromHex(String s) {
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("bad hex at " + (2 * i));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
