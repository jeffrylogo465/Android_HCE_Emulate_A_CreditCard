package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HceCcEmulationServiceVisa extends HostApduService {

    private static final byte[] SW_OK  = hex("9000");
    private static final byte[] SW_BAD = hex("6A82");
    private static final byte[] PPSE   = hex("325041592E5359532E4444463031");

    static byte[] hex(String s) {
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    static byte[] tlv(int tag, byte[] v) {
        byte[] t = (tag > 0xFF)
                ? new byte[]{(byte) (tag >> 8), (byte) tag}
                : new byte[]{(byte) tag};
        byte[] l = (v.length < 0x80)
                ? new byte[]{(byte) v.length}
                : new byte[]{(byte) 0x81, (byte) v.length};
        byte[] out = new byte[t.length + l.length + v.length];
        System.arraycopy(t, 0, out, 0, t.length);
        System.arraycopy(l, 0, out, t.length, l.length);
        System.arraycopy(v, 0, out, t.length + l.length, v.length);
        return out;
    }

    static byte[] cat(byte[]... arrs) {
        int len = 0;
        for (byte[] a : arrs) len += a.length;
        byte[] out = new byte[len];
        int p = 0;
        for (byte[] a : arrs) { System.arraycopy(a, 0, out, p, a.length); p += a.length; }
        return out;
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("card", Context.MODE_PRIVATE);
    }

    private String p(String k, String d) {
        return prefs().getString(k, d);
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        int ins = apdu[1] & 0xFF;
        int p1  = apdu[2] & 0xFF;

        if (ins == 0xA4 && p1 == 0x04) return select(apdu);
        if (ins == 0xA8) return gpo();
        if (ins == 0xB2) return readRecord();
        if (ins == 0xAE) return genac();
        return SW_BAD;
    }

    private byte[] select(byte[] apdu) {
        int lc = apdu[4] & 0xFF;
        byte[] name = new byte[lc];
        System.arraycopy(apdu, 5, name, 0, lc);

        String aid = p("aid", "A0000000031010");
        String label = p("label", "CARD");

        if (Arrays.equals(name, PPSE)) {
            return cat(
                tlv(0x6F, cat(
                    tlv(0x84, PPSE),
                    tlv(0xA5, tlv(0xBF0C,
                        tlv(0x61, cat(
                            tlv(0x4F, hex(aid)),
                            tlv(0x50, label.getBytes(StandardCharsets.US_ASCII))))))
                )), SW_OK);
        }
        if (Arrays.equals(name, hex(aid))) {
            return cat(
                tlv(0x6F, cat(
                    tlv(0x84, hex(aid)),
                    tlv(0xA5, cat(
                        tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                        tlv(0x87, new byte[]{0x01}))))
                )), SW_OK);
        }
        return SW_BAD;
    }

    private byte[] gpo() {
        return cat(tlv(0x77, cat(
            tlv(0x82, hex(p("aip", "1C00"))),
            tlv(0x94, hex(p("afl", "08010100")))
        )), SW_OK);
    }

    private byte[] readRecord() {
        String pan  = p("pan", "4111111111111111");
        String exp  = p("expiry", "3112");
        String sc   = p("serviceCode", "201");
        String disc = p("disc", "");

        String track = pan + "D" + exp + sc + disc;
        if (track.length() % 2 != 0) track = track + "F";

        return cat(tlv(0x70, cat(
            tlv(0x5A, hex(pan.length() % 2 == 0 ? pan : pan + "F")),
            tlv(0x5F24, hex(exp + "00")),
            tlv(0x57, hex(track))
        )), SW_OK);
    }

    private byte[] genac() {
        return cat(tlv(0x77, cat(
            tlv(0x9F27, hex(p("cid", "80"))),
            tlv(0x9F36, hex(p("atc", "001B"))),
            tlv(0x9F26, hex(p("arqc", "0000000000000000"))),
            tlv(0x9F10, hex(p("iad", "06010A03A0B800")))
        )), SW_OK);
    }

    @Override
    public void onDeactivated(int reason) { }
}
