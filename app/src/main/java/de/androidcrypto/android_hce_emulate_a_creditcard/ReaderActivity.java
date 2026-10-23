package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ReaderActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final byte[] PPSE = hex("325041592E5359532E4444463031");

    private NfcAdapter nfcAdapter;
    private IsoDep isoDep;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private TextView txtStatus, txtPan, txtExpiry, txtService, txtDisc, txtTrack2, txtAid;
    private Button btnUseCard, btnCopyReader, btnCancelReader;

    private String rPan = "", rExpiry = "", rService = "", rDisc = "", rTrack2 = "", rAid = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reader);
        setTitle("Read Card");

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        txtStatus = findViewById(R.id.txtReaderStatus);
        txtPan = findViewById(R.id.txtReaderPan);
        txtExpiry = findViewById(R.id.txtReaderExpiry);
        txtService = findViewById(R.id.txtReaderService);
        txtDisc = findViewById(R.id.txtReaderDisc);
        txtTrack2 = findViewById(R.id.txtReaderTrack2);
        txtAid = findViewById(R.id.txtReaderAid);

        btnUseCard = findViewById(R.id.btnUseCard);
        btnCopyReader = findViewById(R.id.btnCopyReader);
        btnCancelReader = findViewById(R.id.btnCancelReader);

        if (btnUseCard != null) {
            btnUseCard.setEnabled(false);
            btnUseCard.setOnClickListener(v -> useCard());
        }
        if (btnCopyReader != null) {
            btnCopyReader.setOnClickListener(v -> copyAll());
        }
        if (btnCancelReader != null) {
            btnCancelReader.setOnClickListener(v -> finish());
        }

        status("Hold the card flat on the back of the phone");
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter == null) {
            status("This phone has no NFC");
            return;
        }
        nfcAdapter.enableReaderMode(this, this,
                NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B |
                        NfcAdapter.FLAG_READER_NFC_F | NfcAdapter.FLAG_READER_NFC_V |
                        NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) nfcAdapter.disableReaderMode(this);
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        status("Card found, reading...");
        try {
            readCard(tag);
        } catch (Exception e) {
            status("Read failed: " + e.getMessage());
        } finally {
            try {
                if (isoDep != null) isoDep.close();
            } catch (IOException ignored) {
            }
            isoDep = null;
        }
    }

    // ---------------------------------------------------------------- reading

    private void readCard(Tag tag) throws IOException {
        isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            status("Not an ISO-DEP card");
            return;
        }
        isoDep.connect();
        isoDep.setTimeout(3000);

        byte[] ppseResp = send(select(PPSE));
        List<byte[]> aidList = new ArrayList<>();
        findAll(ppseResp, 0x4F, aidList);
        if (aidList.isEmpty()) {
            status("No EMV app on this card");
            return;
        }

        rAid = chooseAid(aidList);
        set(txtAid, rAid);

        byte[] fci = send(select(hex(rAid)));

        byte[] pdol = findTag(fci, 0x9F38);
        byte[] pdolData = (pdol == null) ? new byte[0] : buildPdolData(pdol);

        ByteArrayOutputStream gpo = new ByteArrayOutputStream();
        gpo.write(0x80);
        gpo.write(0xA8);
        gpo.write(0x00);
        gpo.write(0x00);
        gpo.write(pdolData.length);
        gpo.write(pdolData, 0, pdolData.length);
        gpo.write(0x00);
        byte[] gpoResp = send(gpo.toByteArray());

        byte[] track2 = null;
        byte[] afl = findTag(gpoResp, 0x94);
        if (afl == null) afl = findTag(fci, 0x94);

        if (afl != null) {
            byte[] records = readRecords(afl);
            track2 = findTag(records, 0x57);
            if (track2 == null) {
                byte[] pan = findTag(records, 0x5A);
                byte[] exp = findTag(records, 0x5F24);
                if (pan != null) {
                    rPan = bcdToTrack2(pan);
                    set(txtPan, rPan);
                }
                if (exp != null) {
                    rExpiry = bcdToTrack2(exp);
                    set(txtExpiry, rExpiry);
                }
            }
        }

        if (track2 == null) track2 = findTag(gpoResp, 0x57);

        if (track2 != null) {
            parseTrack2(track2);
            vibrate();
            ui.post(() -> {
                if (btnUseCard != null) btnUseCard.setEnabled(true);
            });
            status("Card read OK - tap USE THIS CARD");
        } else if (!rPan.isEmpty()) {
            ui.post(() -> {
                if (btnUseCard != null) btnUseCard.setEnabled(true);
            });
            status("PAN read OK - tap USE THIS CARD");
        } else {
            status("Could not find track 2 data");
        }
    }

    private void parseTrack2(byte[] b) {
        String s = bcdToTrack2(b).replaceAll("F+$", "");
        rTrack2 = s.replace('D', '=');
        set(txtTrack2, rTrack2);

        int idx = s.indexOf('D');
        if (idx > 0) {
            rPan = s.substring(0, idx);
            String rest = s.substring(idx + 1);
            if (rest.length() >= 4) rExpiry = rest.substring(0, 4);
            if (rest.length() >= 7) rService = rest.substring(4, 7);
            if (rest.length() > 7) rDisc = rest.substring(7).replaceAll("F+$", "");
        } else {
            rPan = s;
        }
        set(txtPan, rPan);
        set(txtExpiry, rExpiry);
        set(txtService, rService);
        set(txtDisc, rDisc);
    }

    private byte[] readRecords(byte[] afl) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i + 3 < afl.length; i += 4) {
            int sfi = (afl[i] >> 3) & 0x1F;
            int first = afl[i + 1] & 0xFF;
            int last = afl[i + 2] & 0xFF;
            int end = (last == 0) ? first : last;
            for (int rec = first; rec <= end; rec++) {
                byte[] cmd = new byte[]{0x00, (byte) 0xB2, (byte) rec, (byte) ((sfi << 3) | 4), 0x00};
                byte[] resp = send(cmd);
                out.write(resp, 0, Math.max(0, resp.length - 2));
            }
        }
        return out.toByteArray();
    }

    private String chooseAid(List<byte[]> aids) {
        String[] pref = {"A0000000031010", "A0000000041010", "A00000002501",
                "A0000001523010", "A0000000651010"};
        for (String p : pref) {
            for (byte[] a : aids) {
                if (toHex(a).equalsIgnoreCase(p)) return p;
            }
        }
        return toHex(aids.get(0));
    }

    private byte[] buildPdolData(byte[] pdol) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        while (off < pdol.length) {
            int tag = pdol[off++] & 0xFF;
            if ((tag & 0x1F) == 0x1F && off < pdol.length) {
                tag = (tag << 8) | (pdol[off++] & 0xFF);
            }
            if (off >= pdol.length) break;
            int len = pdol[off++] & 0xFF;
            for (int i = 0; i < len; i++) {
                if (tag == 0x9F37) {
                    out.write((int) (Math.random() * 256));
                } else if (tag == 0x9F66 && i == 0) {
                    out.write(0x36);
                } else {
                    out.write(0x00);
                }
            }
        }
        return out.toByteArray();
    }

    // ---------------------------------------------------------------- buttons

    private void useCard() {
        Intent data = new Intent();
        data.putExtra("pan", rPan);
        data.putExtra("expiry", rExpiry);
        data.putExtra("service", rService);
        data.putExtra("disc", rDisc);
        data.putExtra("track2", rTrack2);
        data.putExtra("aid", rAid);
        setResult(Activity.RESULT_OK, data);
        finish();
    }

    private void copyAll() {
        String all = "PAN: " + rPan + "\nExpiry: " + rExpiry + "\nService: " + rService
                + "\nDiscretionary: " + rDisc + "\nTrack2: " + rTrack2 + "\nAID: " + rAid;
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("card", all));
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
    }

    private void vibrate() {
        try {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            if (v == null) return;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                v.vibrate(VibrationEffect.createOneShot(60, VibrationEffect.DEFAULT_AMPLITUDE));
            } else {
                v.vibrate(60);
            }
        } catch (Exception ignored) {
        }
    }

    private void status(String s) {
        ui.post(() -> set(txtStatus, s));
    }

    private static void set(TextView tv, String s) {
        if (tv != null) tv.setText(s);
    }

    // ---------------------------------------------------------------- APDU

    private byte[] send(byte[] cmd) throws IOException {
        byte[] resp = isoDep.transceive(cmd);
        if (resp.length >= 2 && (resp[resp.length - 2] & 0xFF) == 0x6C) {
            cmd[cmd.length - 1] = resp[resp.length - 1];
            resp = isoDep.transceive(cmd);
        }
        while (resp.length >= 2 && (resp[resp.length - 2] & 0xFF) == 0x61) {
            byte[] getResp = new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, resp[resp.length - 1]};
            byte[] more = isoDep.transceive(getResp);
            byte[] joined = new byte[resp.length - 2 + more.length];
            System.arraycopy(resp, 0, joined, 0, resp.length - 2);
            System.arraycopy(more, 0, joined, resp.length - 2, more.length);
            resp = joined;
        }
        return resp;
    }

    private static byte[] select(byte[] aid) {
        byte[] cmd = new byte[5 + aid.length + 1];
        cmd[0] = 0x00;
        cmd[1] = (byte) 0xA4;
        cmd[2] = 0x04;
        cmd[3] = 0x00;
        cmd[4] = (byte) aid.length;
        System.arraycopy(aid, 0, cmd, 5, aid.length);
        cmd[cmd.length - 1] = 0x00;
        return cmd;
    }

    // ---------------------------------------------------------------- TLV

    private static class Tlv {
        int tag;
        int firstByte;
        int len;
        int valOff;
    }

    private static Tlv nextTlv(byte[] d, int off) {
        if (off + 2 > d.length) return null;
        int first = d[off] & 0xFF;
        int tag = first;
        int p = off + 1;
        if ((tag & 0x1F) == 0x1F) {
            while (p < d.length) {
                int b = d[p++] & 0xFF;
                tag = (tag << 8) | b;
                if ((b & 0x80) == 0) break;
            }
        }
        if (p >= d.length) return null;
        int len = d[p++] & 0xFF;
        if ((len & 0x80) != 0) {
            int n = len & 0x7F;
            len = 0;
            for (int i = 0; i < n && p < d.length; i++) len = (len << 8) | (d[p++] & 0xFF);
        }
        if (p + len > d.length) return null;
        Tlv t = new Tlv();
        t.tag = tag;
        t.firstByte = first;
        t.len = len;
        t.valOff = p;
        return t;
    }

    private static byte[] findTag(byte[] d, int tag) {
        int off = 0;
        while (off < d.length) {
            Tlv t = nextTlv(d, off);
            if (t == null) break;
            if (t.tag == tag) return Arrays.copyOfRange(d, t.valOff, t.valOff + t.len);
            if (isConstructed(t)) {
                byte[] sub = findTag(Arrays.copyOfRange(d, t.valOff, t.valOff + t.len), tag);
                if (sub != null) return sub;
           
