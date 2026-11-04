package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Locale;

/**
 * BER-TLV writer. Lengths are computed, never typed.
 *
 * A hand-written length is the one class of bug in this app that compiles clean
 * and fails silently at the terminal, so nothing here trusts a caller's count.
 *
 * Both ceilings throw rather than truncate. A truncated length desyncs the whole
 * remainder of a template and a decoder reads it as data, so the failure is
 * invisible; a throw lands on the status line instead.
 *
 * Two-byte tags are accepted only when the lead byte carries the continuation
 * pattern (low 5 bits set). Without that check a value like 0x8000 would emit
 * "80 00", which a decoder reads as tag 0x80 with a zero length.
 */
final class Tlv {

    static byte[] t(int tag, byte[] value) {
        if (value == null) throw new IllegalArgumentException("null value for tag 0x"
                + Integer.toHexString(tag).toUpperCase(Locale.ROOT));

        int len = value.length;

        // ---- tag ----
        byte[] tagBytes;
        if (tag > 0xFFFF) {
            throw new IllegalArgumentException(String.format(Locale.ROOT,
                    "Three-byte tag 0x%X: only one- and two-byte tags are supported", tag));
        } else if (tag > 0xFF) {
            if (((tag >> 8) & 0x1F) != 0x1F) {
                throw new IllegalArgumentException(String.format(Locale.ROOT,
                        "Malformed multi-byte tag 0x%X: lead byte 0x%02X does not have "
                                + "the low 5 bits set", tag, (tag >> 8) & 0xFF));
            }
            tagBytes = new byte[]{(byte) (tag >> 8), (byte) tag};
        } else {
            tagBytes = new byte[]{(byte) tag};
        }

        // ---- length ----
        byte[] lenBytes;
        if (len < 0x80) {
            lenBytes = new byte[]{(byte) len};
        } else if (len <= 0xFF) {
            lenBytes = new byte[]{(byte) 0x81, (byte) len};
        } else {
            if (len > 0xFFFF) {
                throw new IllegalArgumentException(String.format(Locale.ROOT,
                        "TLV value too long for a 0x82 length: %d bytes (max 65535), tag 0x%X",
                        len, tag));
            }
            lenBytes = new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
        }

        // ---- assemble ----
        byte[] out = new byte[tagBytes.length + lenBytes.length + len];
        int p = 0;
        System.arraycopy(tagBytes, 0, out, p, tagBytes.length);
        p += tagBytes.length;
        System.arraycopy(lenBytes, 0, out, p, lenBytes.length);
        p += lenBytes.length;
        System.arraycopy(value, 0, out, p, len);
        return out;
    }

    static byte[] t(int tag, byte[]... parts) { return t(tag, cat(parts)); }

    static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) if (p != null) n += p.length;
        byte[] out = new byte[n];
        int i = 0;
        for (byte[] p : parts) {
            if (p == null) continue;
            System.arraycopy(p, 0, out, i, p.length);
            i += p.length;
        }
        return out;
    }

    private Tlv() { }
}
