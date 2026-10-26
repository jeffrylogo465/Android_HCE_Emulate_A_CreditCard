package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.io.ByteArrayOutputStream;

final class Tlv {

    static byte[] t(int tag, byte[] value) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        writeTag(o, tag);
        writeLen(o, value.length);
        o.write(value, 0, value.length);
        return o.toByteArray();
    }

    static byte[] t(int tag, byte[]... parts) { return t(tag, cat(parts)); }

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) if (p != null) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    private static void writeTag(ByteArrayOutputStream o, int tag) {
        if (tag > 0xFFFF)    { o.write((tag >> 16) & 0xFF); o.write((tag >> 8) & 0xFF); }
        else if (tag > 0xFF) { o.write((tag >> 8) & 0xFF); }
        o.write(tag & 0xFF);
    }

    private static void writeLen(ByteArrayOutputStream o, int len) {
        if (len < 0x80)       { o.write(len); }
        else if (len <= 0xFF) { o.write(0x81); o.write(len); }
        else                  { o.write(0x82); o.write((len >> 8) & 0xFF); o.write(len & 0xFF); }
    }

    private Tlv() {}
}
