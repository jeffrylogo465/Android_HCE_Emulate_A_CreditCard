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
        for (int i = 0; i < n; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    static byte[] tlv(int tag, byte[] v) {
        byte[] t;
        if (tag > 0xFF) {
            t = new byte[]{(byte) (tag >> 8), (byte) tag};
        } else {
            t = new byte[]{(byte) tag};
        }
        byte[] l;
        if (v.length < 0x80) {
            l = new byte[]{(byte) v.length};
        } else {
            l = new byte[]{(byte) 0x81, (byte) v.length};
        }
        byte[] out = new byte[t.length + l.length + v.length];
        System.arraycopy(t, 0, out, 0, t.length);
        System.arraycopy(l, 0, out, t.length, l.length);
        System.arraycopy(v, 0, out, t.length + l.length, v.length);
        return out;
    }

    static byte[] cat(byte[]... arrs) {
        int len = 0;
        for (byte[] a : arrs) {
            len += a.length;
        }
        byte[] out = new byte[len];
        int p = 0;
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, p, a.length);
            p += a.length;
        }
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

        if (ins == 0xA4 && p1 == 0x04) {
            return select(apdu);
        }
        if (ins == 0xA8) {
            return gpo();
        }
        if (ins == 0xB2) {
            return readRecord();
        }
        if (ins == 0xAE) {
            return genac();
        }
        return SW_BAD;
    }

    private byte[] select(byte[] apdu) {
        int lc = apdu[4] & 0xFF;
        byte[] name = new byte[lc];
        System.arraycopy(apdu, 5, name, 0, lc);

        String aid = p("aid", "A0000000031010");
        String label = p("label", "CARD");

        if (Arrays.equals(name, PPSE)) {
            byte[] entry = cat(
                    tlv(0x4F, hex(aid)),
                    tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)));
            byte[] dir = tlv(0x61, entry);
            byte[] fci = tlv(0xBF0C, dir);
            byte[] inner = cat(tlv(0x84, PPSE), tlv(0xA5, fci));
            return cat(tlv(0x6F, inner), SW_OK);
        }

        if (Arrays.equals(name, hex(aid))) {
            byte[] prop = cat(
                    tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                    tlv(0x87, new byte[]{0x01}));
            byte[] inner = cat(tlv(0x84, hex(aid)), tlv(0xA5, prop));
            return cat(tlv(0x6F, inner), SW_OK);
        }

        return SW_BAD;
    }

    private byte[] gpo() {
        byte[] aip = tlv(0x82, hex(p("aip", "1C00")));
        byte[] afl = tlv(0x94, hex(p("afl", "08010100")));
        return cat(tlv(0x77, cat(aip, afl)), SW_OK);
    }

    private byte[] readRecord() {
        String pan  = p("pan", "4111111111111111");
        String exp  = p("expiry", "3112");
        String sc   = p("serviceCode", "201");
        String disc = p("disc", "");

        String track = pan + "D" + exp + sc + disc;
        if (track.length() % 2 != 0) {
            track = track + "F";
        }
        if (pan.length() % 2 != 0) {
            pan = pan + "F";
        }

        byte[] panT   = tlv(0x5A, hex(pan));
        byte[] expT   = tlv(0x5F24, hex(exp + "00"));
        byte[] trackT = tlv(0x57, hex(track));

        return cat(tlv(0x70, cat(panT, expT, trackT)), SW_OK);
    }

    private byte[] genac() {
        byte[] cidT  = tlv(0x9F27, hex(p("cid", "80")));
        byte[] atcT  = tlv(0x9F36, hex(p("atc", "001B")));
        byte[] arqcT = tlv(0x9F26, hex(p("arqc", "0000000000000000")));
        byte[] iadT  = tlv(0x9F10, hex(p("iad", "06010A03A0B800")));

        return cat(tlv(0x77, cat(cidT, atcT, arqcT, iadT)), SW_OK);
    }

    @Override
    public void onDeactivated(int reason) {
    }
}
