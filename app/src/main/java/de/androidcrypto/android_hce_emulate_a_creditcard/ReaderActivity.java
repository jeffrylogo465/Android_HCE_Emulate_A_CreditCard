package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * Reads a physical contactless card and hands it to MainActivity.
 *
 * STAGING. Everything is written to tmp_* during a read and promoted to cap_*
 * only once the read has produced something usable. A tap that dies halfway
 * therefore leaves the previous good capture intact instead of replacing it
 * with a partial one.
 *
 * The service reads these back as:
 *   cap_rec<sfi>_<rec>   -> readRecord()   (NOT a flat cap_rec0, cap_rec1)
 *   cap_rawfci           -> rawFci()       (real FCI replay)
 *   cap_rawgpo           -> rawGpo()       (framing + AIP source)
 *   cap_rawgpo_msd       -> the format 1 probe, for reference
 *   cap_genaccmd         -> MainActivity's key scan
 *   cap_rawgenac         -> MainActivity's key scan
 *   cap_aid              -> "the real AID" for the PPSE and the select log
 *   cap_holder, cap_label -> fallbacks for name and directory label
 */
public class ReaderActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    public static final String EXTRA_CARD_INDEX = "card_index";
    public static final String EXTRA_PAN = "pan";
    public static final String EXTRA_EXPIRY = "expiry";
    public static final String EXTRA_SERVICE = "service";
    public static final String EXTRA_DISC = "disc";
    public static final String EXTRA_AID = "aid";
    public static final String EXTRA_TRACK2 = "track2";
    public static final String EXTRA_PSN = "psn";
    public static final String EXTRA_IAD = "iad";
    public static final String EXTRA_ATC = "atc";
    public static final String EXTRA_AIP = "aip";

    private static final String PREF = "hce_card";
    private static final String PPSE = "325041592E5359532E4444463031";

    /**
     * TTQ byte 1 is: 0x80 mag-stripe mode supported, 0x20 EMV mode supported,
     * 0x10 RFU, 0x08 offline PIN, 0x04 online PIN, 0x02 signature, 0x01 RFU.
     *
     * 3600 sets EMV mode (0x20) but NOT mag-stripe - which is why every capture
     * so far has come back as a 77. 8000 is mag-stripe only and forces a card
     * that supports MSD to answer format 1, which is the shape still unsettled.
     *
     * So a read probes with 8000 first, then re-selects and probes with 2000.
     * The format 1 response lands in cap_rawgpo_msd for reference; the EMV one
     * in cap_rawgpo and is what the emulator replays and what the key scan needs.
     */
    private static final String TTQ_MSD = "8000";
    private static final String TTQ_EMV = "2000";

    private static final String[] FALLBACK_AIDS = {
            "A0000000031010", "A0000000032010",
            "A0000000041010", "A0000000043060",
            "A0000001523010",
            "A00000002501", "A0000000250104", "A0000000250001",
            "A0000000651010",
            "A000000333010101"
    };

    private SharedPreferences prefs;
    private NfcAdapter nfc;

    private TextView txtLog;
    private Button btnUse;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean busy = false;

    private String rPan = "", rExpiry = "", rService = "", rDisc = "", rAid = "",
            rTrack2 = "", rPsn = "", rIad = "", rAtc = "", rAip = "", rHolder = "";
    private boolean read = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREF, MODE_PRIVATE);
        buildUi();
        nfc = NfcAdapter.getDefaultAdapter(this);
        if (nfc == null) log("No NFC adapter on this device");
    }

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0B0F14);
        int p = dp(16);
        root.setPadding(p, p, p, p);

        TextView title = new TextView(this);
        title.setText("READ CARD");
        title.setTextColor(0xFF14B8A6);
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Hold the physical card flat against the back of the phone.\n"
                + "One read per tap. Probes format 1 (TTQ " + TTQ_MSD + ") then re-selects\n"
                + "and takes the EMV path (TTQ " + TTQ_EMV + ") for records and GENERATE AC.");
        hint.setTextColor(0xFF9CA3AF);
        hint.setTextSize(12);
        hint.setPadding(0, dp(6), 0, dp(10));
        root.addView(hint);

        txtLog = new TextView(this);
        txtLog.setTextColor(0xFFE5E7EB);
        txtLog.setTextSize(11);
        txtLog.setTypeface(Typeface.MONOSPACE);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(txtLog);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        scroll.setLayoutParams(lp);
        root.addView(scroll);

        btnUse = new Button(this);
        btnUse.setText("USE CARD");
        btnUse.setEnabled(false);
        btnUse.setOnClickListener(v -> returnResult());
        root.addView(btnUse);

        Button btnCancel = new Button(this);
        btnCancel.setText("CANCEL");
        btnCancel.setOnClickListener(v -> {
            setResult(Activity.RESULT_CANCELED);
            finish();
        });
        root.addView(btnCancel);

        setContentView(root);
    }

    private void log(String s) {
        ui.post(() -> {
            txtLog.append(s + "\n");
            ScrollView sv = (ScrollView) txtLog.getParent();
            if (sv != null) sv.fullScroll(View.FOCUS_DOWN);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfc != null && nfc.isEnabled()) {
            Bundle opts = new Bundle();
            opts.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500);
            nfc.enableReaderMode(this, this,
                    NfcAdapter.FLAG_READER_NFC_A
                            | NfcAdapter.FLAG_READER_NFC_B
                            | NfcAdapter.FLAG_READER_NFC_F
                            | NfcAdapter.FLAG_READER_NFC_V
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                    opts);
        } else {
            log("NFC is off - enable it and come back");
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfc != null) nfc.disableReaderMode(this);
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        if (busy) return;
        busy = true;
        IsoDep iso = IsoDep.get(tag);
        if (iso == null) {
            log("That is not an ISO14443-4 card (no APDU layer)");
            busy = false;
            return;
        }
        try {
            iso.connect();
            iso.setTimeout(3000);
            readCard(iso);
        } catch (Exception e) {
            log("Read error: " + e);
        } finally {
            try { iso.close(); } catch (Exception ignored) { }
            busy = false;
        }
    }

    private void readCard(IsoDep iso) throws IOException {
        read = false;
        rPan = rExpiry = rService = rDisc = rAid = "";
        rTrack2 = rPsn = rIad = rAtc = rAip = rHolder = "";
        ui.post(() -> {
            txtLog.setText("");
            btnUse.setEnabled(false);
        });
        clearTmp();

        log("-- SELECT PPSE");
        List<byte[]> aids = new ArrayList<>();
        try {
            byte[] fci = send(iso, apdu(0x00, 0xA4, 0x04, 0x00, hexToBytes(PPSE), 0x00));
            collect(fci, 0x4F, aids);
        } catch (IOException e) {
            log("   PPSE failed: " + e.getMessage());
        }
        if (aids.isEmpty()) {
            log("   PPSE gave no AID - trying known ones");
            for (String a : FALLBACK_AIDS) aids.add(hexToBytes(a));
        }

        log("-- SELECT AID");
        byte[] fci = null;
        byte[] aidBytes = null;
        for (byte[] a : aids) {
            try {
                fci = send(iso, apdu(0x00, 0xA4, 0x04, 0x00, a, 0x00));
                aidBytes = a;
                rAid = bytesToHex(a);
                log("   ok " + rAid);
                break;
            } catch (IOException ignored) {
                log("   no " + bytesToHex(a));
            }
        }
        if (fci == null || aidBytes == null) {
            log("Nothing would SELECT - is this a payment card?");
            return;
        }

        stage("rawfci", bytesToHex(fci));
        stage("aid", rAid);

        // FIX: the FCI carries 50 (label) and 9F12 (preferred name) and the
        // reader never pulled either out, so every emulated card introduced
        // itself as the fallback word "CARD".
        String cardLabel = firstText(fci, 0x50);
        if (cardLabel.isEmpty()) cardLabel = firstText(fci, 0x9F12);
        if (!cardLabel.isEmpty()) {
            stage("label", cardLabel);
            log("   label on the card: " + cardLabel);
        }

        log("-- GET PROCESSING OPTIONS");
        List<byte[]> pdolL = new ArrayList<>();
        collect(fci, 0x9F38, pdolL);
        byte[] pdol = pdolL.isEmpty() ? new byte[0] : pdolL.get(0);

        byte[] gpoMsd = null;
        try {
            gpoMsd = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, buildTemplateData(pdol, TTQ_MSD), 0x00));
            log("   probe TTQ " + TTQ_MSD + ": " + bytesToHex(gpoMsd));
        } catch (IOException e) {
            log("   probe TTQ " + TTQ_MSD + " failed: " + e.getMessage());
        }

        boolean msdShape = gpoMsd != null && gpoMsd.length > 3 && (gpoMsd[0] & 0xFF) == 0x80;
        if (msdShape) stage("rawgpo_msd", bytesToHex(gpoMsd));

        byte[] gpo;
        if (msdShape) {
            log("   card answered format 1 - re-selecting for the EMV probe");
            try { send(iso, apdu(0x00, 0xA4, 0x04, 0x00, aidBytes, 0x00)); } catch (IOException ignored) { }
            try {
                gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, buildTemplateData(pdol, TTQ_EMV), 0x00));
                log("   probe TTQ " + TTQ_EMV + ": " + bytesToHex(gpo));
            } catch (IOException e) {
                log("   EMV probe failed (" + e.getMessage() + "), keeping the format 1 response");
                gpo = gpoMsd;
            }
        } else if (gpoMsd != null) {
            gpo = gpoMsd;
        } else {
            gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, buildTemplateData(pdol, TTQ_EMV), 0x00));
        }
        stage("rawgpo", bytesToHex(gpo));

        byte[] aip = null, afl = null;
        if (gpo.length > 3 && (gpo[0] & 0xFF) == 0x80) {
            int l = gpo[1] & 0xFF;
            int off = 2;
            if (l == 0x81 && gpo.length > 2) {
                l = gpo[2] & 0xFF;
                off = 3;
            } else if (l == 0x82 && gpo.length > 3) {
                l = ((gpo[2] & 0xFF) << 8) | (gpo[3] & 0xFF);
                off = 4;
            }
            int end = Math.min(gpo.length, off + l);

            if (end - off >= 2) {
                aip = Arrays.copyOfRange(gpo, off, off + 2);
                byte[] rest = Arrays.copyOfRange(gpo, off + 2, end);
                log("   format 1 - after the AIP: " + bytesToHex(rest));

                if (rest.length >= 2 && (rest[0] & 0xFF) == 0x57
                        && (rest[1] & 0xFF) == rest.length - 2) {
                    rTrack2 = bcd(Arrays.copyOfRange(rest, 2, rest.length));
                    log("   payload is 57 <len> track 2 - no AFL");
                } else if (rest.length % 4 == 0 && saneAfl(rest)) {
                    afl = rest;
                    log("   payload looks like a bare AFL");
                } else if (rest.length > 4 && saneAfl(Arrays.copyOfRange(rest, 0, 4))) {
                    afl = Arrays.copyOfRange(rest, 0, 4);
                    rTrack2 = bcd(Arrays.copyOfRange(rest, 4, rest.length));
                    log("   first 4 bytes taken as an AFL, the rest as the track 2");
                } else {
                    rTrack2 = bcd(rest);
                    log("   no sane AFL - treating the whole payload as the track 2");
                }
            }
        } else {
            List<byte[]> l = new ArrayList<>();
            collect(gpo, 0x82, l);
            if (!l.isEmpty()) aip = l.get(0);
            l.clear();
            collect(gpo, 0x94, l);
            if (!l.isEmpty()) afl = l.get(0);
        }
        if (aip != null) rAip = bytesToHex(aip);
        log("   AIP " + (rAip.isEmpty() ? "(none)" : rAip)
                + (afl == null ? "  no AFL" : "  AFL " + bytesToHex(afl)));

        log("-- READ RECORD");
        List<byte[]> records = new ArrayList<>();
        int recNo = 0;
        if (afl != null) {
            for (int i = 0; i + 3 < afl.length; i += 4) {
                int sfi = (afl[i] & 0xFF) >> 3;
                int first = afl[i + 1] & 0xFF;
                int last = afl[i + 2] & 0xFF;
                if (sfi < 1 || sfi > 10 || first < 1 || first > 31) continue;
                if (last < first || last > 31) last = first;
                for (int r = first; r <= last; r++) {
                    try {
                        byte[] rec = send(iso, apdu(0x00, 0xB2, r, (sfi << 3) | 4, null, 0x00));
                        stage("rec" + sfi + "_" + r, bytesToHex(rec));
                        records.add(rec);
                        recNo++;
                        log("   sfi " + sfi + " rec " + r + " ok");
                    } catch (IOException e) {
                        log("   sfi " + sfi + " rec " + r + " " + e.getMessage());
                    }
                }
            }
        }
        log("   " + recNo + " record(s)");

        byte[] cdol1 = null;
        for (byte[] rec : records) {
            if (rPan.isEmpty()) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x5A, l);
                if (!l.isEmpty()) rPan = bcd(l.get(0));
            }
            if (rTrack2.isEmpty()) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x57, l);
                if (!l.isEmpty()) rTrack2 = bcd(l.get(0));
            }
            if (rExpiry.isEmpty()) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x5F24, l);
                if (!l.isEmpty()) {
                    rExpiry = bcd(l.get(0));
                    if (rExpiry.length() > 4) rExpiry = rExpiry.substring(0, 4);
                }
            }
            if (rPsn.isEmpty()) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x5F34, l);
                if (!l.isEmpty()) rPsn = bcd(l.get(0));
            }
            if (rHolder.isEmpty()) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x5F20, l);
                if (!l.isEmpty()) {
                    rHolder = new String(l.get(0), java.nio.charset.StandardCharsets.ISO_8859_1)
                            .toUpperCase().replaceAll("[^A-Z0-9 ./'-]", "").trim();
                    if (rHolder.length() > 26) rHolder = rHolder.substring(0, 26);
                }
            }
            if (rIad.isEmpty()) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x9F10, l);
                if (!l.isEmpty()) rIad = bytesToHex(l.get(0));
            }
            if (cdol1 == null) {
                List<byte[]> l = new ArrayList<>();
                collect(rec, 0x8C, l);
                if (!l.isEmpty()) cdol1 = l.get(0);
            }
        }
        if (!rHolder.isEmpty()) stage("holder", rHolder);

        int dsep = rTrack2.indexOf('D');
        if (dsep > 0 && rTrack2.length() >= dsep + 8) {
            if (rExpiry.isEmpty()) rExpiry = rTrack2.substring(dsep + 1, dsep + 5);
            if (rService.isEmpty()) rService = rTrack2.substring(dsep + 5, dsep + 8);
            if (rDisc.isEmpty()) rDisc = rTrack2.substring(dsep + 8);
        }
        if (rPan.isEmpty() && !rTrack2.isEmpty()) {
            int d = rTrack2.indexOf('D');
            if (d >= 12 && d <= 19) {
                rPan = rTrack2.substring(0, d);
                log("   PAN taken from the track 2");
            }
        }

        if (rService.length() != 3) rService = "201";
        if (rPsn.length() > 2) rPsn = rPsn.substring(0, 2);
        if (rExpiry.length() > 4) rExpiry = rExpiry.substring(0, 4);

        if (cdol1 != null && cdol1.length > 0) {
            log("-- GENERATE AC");
            byte[] cdolData = buildTemplateData(cdol1, TTQ_EMV);
            byte[] cmd = apdu(0x80, 0xAE, 0x00, 0x00, cdolData, 0x00);
            try {
                byte[] rsp = send(iso, cmd);
                stage("genaccmd", bytesToHex(cmd));
                stage("rawgenac", bytesToHex(rsp));

                List<byte[]> l = new ArrayList<>();
                collect(rsp, 0x9F36, l);
                if (!l.isEmpty()) rAtc = bytesToHex(l.get(0));
                l.clear();
                collect(rsp, 0x9F27, l);
                String cid = l.isEmpty() ? "" : bytesToHex(l.get(0));
                l.clear();
                collect(rsp, 0x9F10, l);
                if (!l.isEmpty()) rIad = bytesToHex(l.get(0));
                l.clear();
                collect(rsp, 0x9F26, l);
                String arqc = l.isEmpty() ? "" : bytesToHex(l.get(0));

                log("   CID  " + (cid.isEmpty() ? "?" : cid));
                log("   ATC  " + (rAtc.isEmpty() ? "?" : rAtc));
                log("   ARQC " + (arqc.isEmpty() ? "?" : arqc));
                if (arqc.isEmpty()) log("   no 9F26 in the response");
            } catch (IOException e) {
                log("   GENERATE AC failed: " + e.getMessage());
            }
        } else {
            log("-- no 8C CDOL1 in the records, GENERATE AC skipped");
        }

        read = !rPan.isEmpty() || !rTrack2.isEmpty();

        // Only now do the partial capture replace the previous one.
        if (read) promoteStaging();

        StringBuilder sb = new StringBuilder();
        sb.append("PAN    : ").append(rPan.isEmpty() ? "(none)" : rPan).append('\n');
        sb.append("expiry : ").append(rExpiry.isEmpty() ? "(none)" : rExpiry).append('\n');
        sb.append("track2 : ").append(rTrack2.isEmpty() ? "(none)" : rTrack2).append('\n');
        sb.append("AID    : ").append(rAid).append('\n');
        sb.append("AIP    : ").append(rAip).append('\n');
        sb.append("ATC    : ").append(rAtc.isEmpty() ? "(none)" : rAtc).append('\n');
        sb.append("records: ").append(recNo).append('\n');
        sb.append("genac  : ").append(
                prefs.getString("cap_genaccmd", "").isEmpty() ? "NOT captured" : "captured");
        sb.append(read ? "staged : promoted to cap_*" : "staged : read failed, cap_* untouched");
        log("\n" + sb);

        ui.post(() -> {
            btnUse.setEnabled(read);
            if (!read) Toast.makeText(this, "Nothing usable read", Toast.LENGTH_SHORT).show();
        });
    }

    /** First AFL entry must look like SFI 1-10 with record numbers 1-31. */
    private static boolean saneAfl(byte[] a) {
        if (a == null || a.length < 4) return false;
        int sfi = (a[0] & 0xFF) >> 3;
        int first = a[1] & 0xFF;
        int last = a[2] & 0xFF;
        return sfi >= 1 && sfi <= 10 && first >= 1 && first <= 31 && last >= first && last <= 31;
    }

    /** First value of a tag anywhere in the tree, as sanitised ASCII text. */
    private static String firstText(byte[] d, int tag) {
        List<byte[]> l = new ArrayList<>();
        collect(d, tag, l);
        if (l.isEmpty()) return "";
        String s = new String(l.get(0), java.nio.charset.StandardCharsets.ISO_8859_1)
                .toUpperCase().replaceAll("[^A-Z0-9 ./'-]", "").trim();
        if (s.length() > 16) s = s.substring(0, 16);
        return s;
    }

    private void returnResult() {
        if (!read) {
            Toast.makeText(this, "Nothing read yet", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent out = new Intent();
        out.putExtra(EXTRA_CARD_INDEX, getIntent().getIntExtra(EXTRA_CARD_INDEX, -1));
        out.putExtra(EXTRA_PAN, rPan);
        out.putExtra(EXTRA_EXPIRY, rExpiry);
        out.putExtra(EXTRA_SERVICE, rService);
        out.putExtra(EXTRA_DISC, rDisc);
        out.putExtra(EXTRA_AID, rAid);
        out.putExtra(EXTRA_TRACK2, rTrack2);
        out.putExtra(EXTRA_PSN, rPsn);
        out.putExtra(EXTRA_IAD, rIad);
        out.putExtra(EXTRA_ATC, rAtc);
        out.putExtra(EXTRA_AIP, rAip);
        setResult(Activity.RESULT_OK, out);
        finish();
    }

    // ---------- staging: tmp_ during the read, cap_ only on success ----------

    private void clearTmp() {
        SharedPreferences.Editor e = prefs.edit();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("tmp_")) e.remove(k);
        }
        e.apply();
    }

    private void stage(String shortName, String value) {
        prefs.edit().putString("tmp_" + shortName, value).apply();
    }

    private void promoteStaging() {
        SharedPreferences.Editor e = prefs.edit();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_")) e.remove(k);
        }
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("tmp_")) {
                e.putString("cap_" + k.substring(4), prefs.getString(k, ""));
            }
        }
        e.apply();
        clearTmp();
    }

    private static int sw(byte[] r) {
        if (r == null || r.length < 2) return 0;
        return ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
    }

    private static byte[] apdu(int cla, int ins, int p1, int p2, byte[] data, int le) {
        if (data == null) {
            return new byte[]{(byte) cla, (byte) ins, (byte) p1, (byte) p2, (byte) le};
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(cla & 0xFF);
        o.write(ins & 0xFF);
        o.write(p1 & 0xFF);
        o.write(p2 & 0xFF);
        if (data.length > 255) {
            o.write(0x00);
            o.write((data.length >> 8) & 0xFF);
            o.write(data.length & 0xFF);
            o.write(data, 0, data.length);
            o.write(0x00);
            o.write(0x00);
        } else {
            o.write(data.length & 0xFF);
            o.write(data, 0, data.length);
            o.write(le & 0xFF);
        }
        return o.toByteArray();
    }

    /** True when this APDU we just built used extended length. */
    private static boolean isExtended(byte[] apdu) {
        return apdu.length >= 7 && (apdu[4] & 0xFF) == 0x00
                && (((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF)) > 0;
    }

    private byte[] send(IsoDep iso, byte[] apdu) throws IOException {
        byte[] rsp = iso.transceive(apdu);
        int code = sw(rsp);

        // 6Cxx = wrong Le. For an extended APDU the last TWO bytes are Le.
        if ((code & 0xFF00) == 0x6C00) {
            byte[] retry = apdu.clone();
            if (isExtended(retry)) {
                retry[retry.length - 2] = 0x00;
                retry[retry.length - 1] = (byte) (code & 0xFF);
            } else if (retry.length >= 1) {
                retry[retry.length - 1] = (byte) (code & 0xFF);
            }
            rsp = iso.transceive(retry);
            code = sw(rsp);
        }

        // 61xx = more data. Chain until it stops, not just once.
        if ((code & 0xFF00) == 0x6100) {
            ByteArrayOutputStream acc = new ByteArrayOutputStream();
            acc.write(Arrays.copyOf(rsp, rsp.length - 2), 0, rsp.length - 2);
            int guard = 0;
            while ((code & 0xFF00) == 0x6100 && guard++ < 10) {
                byte[] more = iso.transceive(new byte[]{
                        0x00, (byte) 0xC0, 0x00, 0x00, (byte) (code & 0xFF)});
                code = sw(more);
                if ((code & 0xFF00) == 0x6100) {
                    acc.write(more, 0, more.length - 2);
                } else if (code == 0x9000) {
                    acc.write(more, 0, more.length - 2);
                } else {
                    throw new IOException(String.format(Locale.US, "SW %04X", code));
                }
            }
            return acc.toByteArray();
        }

        if (code != 0x9000) throw new IOException(String.format(Locale.US, "SW %04X", code));
        return Arrays.copyOf(rsp, rsp.length - 2);
    }

    private static void collect(byte[] d, int want, List<byte[]> out) {
        if (d == null) return;
        int i = 0;
        while (i < d.length) {
            int t = d[i++] & 0xFF;
            if ((t & 0x1F) == 0x1F) {
                if (i >= d.length) return;
                t = (t << 8) | (d[i++] & 0xFF);
            }
            if (i >= d.length) return;
            int l = d[i++] & 0xFF;
            if ((l & 0x80) != 0) {
                int n = l & 0x7F;
                if (n == 0 || n > 3) return;
                l = 0;
                for (int k = 0; k < n; k++) {
                    if (i >= d.length) return;
                    l = (l << 8) | (d[i++] & 0xFF);
                }
            }
            if (i + l > d.length) return;
            if (t == want) out.add(Arrays.copyOfRange(d, i, i + l));
            if (isContainer(t)) collect(Arrays.copyOfRange(d, i, i + l), want, out);
            i += l;
        }
    }

    private static boolean isContainer(int t) {
        return t == 0x6F || t == 0x61 || t == 0xA5 || t == 0x77 || t == 0x70
                || t == 0x62 || t == 0x63 || t == 0x64
                || t == 0xBF0C || t == 0xBF0D;
    }

    /**
     * Build the value for a PDOL or CDOL1 template - the same thing, so the name
     * no longer says CDOL only.
     */
    private byte[] buildTemplateData(byte[] template, String ttq) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < template.length) {
            int tag = template[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= template.length) break;
                tag = (tag << 8) | (template[i++] & 0xFF);
            }
            if (i >= template.length) break;
            int len = template[i++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int k = 0; k < n && i < template.length; k++) {
                    len = (len << 8) | (template[i++] & 0xFF);
                }
            }
            byte[] v = defaultFor(tag, len, ttq);
            for (int k = 0; k < len; k++) {
                out.write(k < v.length ? v[k] : 0);
            }
        }
        return out.toByteArray();
    }

    private byte[] defaultFor(int tag, int len, String ttq) {
        switch (tag) {
            case 0x9F02: return hexToBytes("000000001000");
            case 0x9F03: return new byte[6];
            case 0x9F1A: return hexToBytes("0840");
            case 0x5F2A: return hexToBytes("0840");
            case 0x9A: {
                Calendar c = Calendar.getInstance();
                return hexToBytes(String.format(Locale.US, "%02d%02d%02d",
                        c.get(Calendar.YEAR) % 100,
                        c.get(Calendar.MONTH) + 1,
                        c.get(Calendar.DAY_OF_MONTH)));
            }
            case 0x9F21: return hexToBytes("120000");
            case 0x9F37: {
                byte[] r = new byte[4];
                new Random().nextBytes(r);
                return r;
            }
            case 0x9F35: return hexToBytes("22");
            case 0x9F33: return hexToBytes("000000");
            case 0x9F34: return hexToBytes("000000");
            case 0x9F40: return hexToBytes("0000000000");
            case 0x9F66: return hexToBytes(ttq);
            default: return new byte[len];
        }
    }

    private static byte[] cat(byte[]... arrs) {
        int n = 0;
        for (byte[] a : arrs) n += a.length;
        byte[] out = new byte[n];
        int p = 0;
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, p, a.length);
            p += a.length;
        }
        return out;
    }

    private static byte[] hexToBytes(String h) {
        h = h.replaceAll("[^0-9A-Fa-f]", "").toUpperCase(Locale.US);
        if (h.length() % 2 != 0) h = h + "F";
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format(Locale.US, "%02X", b & 0xFF));
        return sb.toString();
    }

    private static String bcd(byte[] d) {
        String h = bytesToHex(d);
        while (h.endsWith("F")) h = h.substring(0, h.length() - 1);
        return h;
    }
}
