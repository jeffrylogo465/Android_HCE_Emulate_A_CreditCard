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

    private static final String PDOL    = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL1   = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL2   = "9F02069F03069F1A0295055F2A029A039C019F37049F3403";
    private static final String CVMLIST = "000013881F0602071E03";

    static byte[] hex(String s) {
        if (s == null) return new byte[0];
        s = s.replaceAll("[^0-9A-Fa-f]", "");
        if (s.length() % 2 != 0) s = s + "F";
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
        } else if (v.length < 0x100) {
            l = new byte[]{(byte) 0x81, (byte) v.length};
        } else {
            l = new byte[]{(byte) 0x82, (byte) (v.length >> 8), (byte) v.length};
        }
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
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, p, a.length);
            p += a.length;
        }
        return out;
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("hce_card", Context.MODE_PRIVATE);
    }

    private String sel() {
        return "card" + prefs().getInt("selected", 0) + "_";
    }

    private String p(String k, String d) {
        return prefs().getString(sel() + k, d);
    }

    private void put(String k, String v) {
        prefs().edit().putString(sel() + k, v).apply();
    }

    private boolean isMsd() {
        return "1".equals(p("msd", "1"));
    }

    private String nextAtc() {
        int atc = 0x001B;
        try {
            String cur = p("atc", "001B").replaceAll("[^0-9A-Fa-f]", "");
            if (!cur.isEmpty()) atc = Integer.parseInt(cur, 16);
        } catch (Exception ignored) {}
        atc = (atc + 1) & 0xFFFF;
        String h = String.format("%04X", atc);
        put("atc", h);
        return h;
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        try {
            if (apdu == null || apdu.length < 4) return SW_BAD;

            int ins = apdu[1] & 0xFF;
            int p1  = apdu[2] & 0xFF;

            if (ins == 0xA4 && p1 == 0x04) {
                if (apdu.length < 5) return SW_BAD;
                return select(apdu);
            }
            if (ins == 0xA8) return gpo();
            if (ins == 0xB2) return readRecord();
            if (ins == 0xAE) return genac(apdu);
            if (ins == 0xCA) return getData(apdu);
            return SW_BAD;
        } catch (Exception e) {
            return SW_BAD;
        }
    }

    private byte[] select(byte[] apdu) {
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return SW_BAD;
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
                    tlv(0x87, new byte[]{0x01}),
                    tlv(0x9F38, hex(PDOL)));
            byte[] inner = cat(tlv(0x84, hex(aid)), tlv(0xA5, prop));
            return cat(tlv(0x6F, inner), SW_OK);
        }

        return SW_BAD;
    }

    private byte[] gpo() {
        String aip = p("aip", "3800");
        String afl = p("afl", "08010100");

        if (isMsd()) {
            return cat(tlv(0x80, cat(hex(aip), hex(afl))), SW_OK);
        }
        return cat(tlv(0x77, cat(tlv(0x82, hex(aip)), tlv(0x94, hex(afl)))), SW_OK);
    }

    private byte[] readRecord() {
        String track2Hex = p("track2", "").trim();
        String pan  = p("pan", "4111111111111111");
        String exp  = p("expiry", "3112");
        String sc   = p("service", "201");
        String disc = p("discretionary", "");

        String track;
        if (!track2Hex.isEmpty()) {
            track = track2Hex;
        } else {
            track = pan + "D" + exp + sc + disc;
            if (track.length() % 2 != 0) track = track + "F";
        }
        if (pan.length() % 2 != 0) pan = pan + "F";

        byte[] panT   = tlv(0x5A, hex(pan));
        byte[] expT   = tlv(0x5F24, hex(exp + "00"));
        byte[] trackT = tlv(0x57, hex(track));
        byte[] cdol1T = tlv(0x8C, hex(CDOL1));
        byte[] cdol2T = tlv(0x8D, hex(CDOL2));
        byte[] cvmT   = tlv(0x8E, hex(CVMLIST));

        return cat(tlv(0x70, cat(panT, expT, trackT, cdol1T, cdol2T, cvmT)), SW_OK);
    }

    private byte[] genac(byte[] apdu) {
        int p1 = apdu[2] & 0xFF;

        String atc = ((p1 & 0xC0) == 0x80) ? nextAtc() : p("atc", "001B");

        byte[] cdol = new byte[0];
        if (apdu.length >= 5) {
            int lc = apdu[4] & 0xFF;
            if (lc > 0 && apdu.length >= 5 + lc) {
                cdol = Arrays.copyOfRange(apdu, 5, 5 + lc);
            }
        }

        int cid;
        if ((p1 & 0xC0) == 0x80)      cid = 0x80;
        else if ((p1 & 0xC0) == 0x40) cid = 0x40;
        else                          cid = 0x00;

        byte[] ac = computeAc(atc, cdol);

        byte[] cidT  = tlv(0x9F27, new byte[]{(byte) cid});
        byte[] atcT  = tlv(0x9F36, hex(atc));
        byte[] arqcT = tlv(0x9F26, ac);
        byte[] iadT  = tlv(0x9F10, hex(p("iad", "06010A03A0B800")));
        return cat(tlv(0x77, cat(cidT, atcT, arqcT, iadT)), SW_OK);
    }

    private byte[] computeAc(String atc, byte[] cdol) {
        String mk = p("mkac", "").replaceAll("[^0-9A-Fa-f]", "");
        if (mk.length() < 32) return new byte[8];
        try {
            byte[] macIn = cat(hex(p("aip", "3800")), hex(atc), cdol);
            return EmvCrypto.arqc(mk, p("pan", "4111111111111111"), "00", atc, macIn);
        } catch (Exception e) {
            return new byte[8];
        }
    }

    private byte[] getData(byte[] apdu) {
        if (apdu.length < 6) return SW_BAD;
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return SW_BAD;

        int tag = 0;
        for (int i = 0; i < lc; i++) tag = (tag << 8) | (apdu[5 + i] & 0xFF);

        byte[] val;
        if (tag == 0x9F36)      val = hex(p("atc", "001B"));
        else if (tag == 0x9F13) val = hex("00");
        else if (tag == 0x9F17) val = hex("00");
        else return SW_BAD;

        return cat(tlv(tag, val), SW_OK);
    }

    @Override
    public void onDeactivated(int reason) {
    }
}
