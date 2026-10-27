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
 * STAGING KEY NAMES MATTER. The service reads them back as:
 *   cap_rec<sfi>_<rec>   -> readRecord()   (NOT a flat cap_rec0, cap_rec1)
 *   cap_rawfci           -> rawFci()       (real FCI replay)
 *   cap_rawgpo           -> rawGpo()       (framing + AIP source)
 *   cap_genaccmd         -> MainActivity's key scan
 *   cap_rawgenac         -> MainActivity's key scan
 *   cap_aid              -> "the real AID" for the PPSE and the select log
 *   cap_holder           -> fallback cardholder name
 * All of these live under the "cap_" prefix, which copyStagingToCard() moves to
 * "card<N>_cap_...".
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
     * TTQ sent inside the PDOL. 0x80 = magstripe mode supported, 0x40 = EMV mode
     * supported.
     *
     * 8000 sets ONLY the magstripe bit, so a card that supports MSD answers the
     * GPO in format 1. Every capture so far has been a 77 because 3600 asked for
     * EMV - which is why the MSD payload shape has never been settled. Flip this
     * back to "3600" once the shape is known and you want the EMV read path with
     * a real GENERATE AC.
     */
    private static final String TTQ = "8000";

    private static final String[] FALLBACK_AIDS = {
            "A0000000031010", "A0000000041010", "A0000001523010",
            "A00000002501", "A0000000651010", "A000000333010101"
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
                + "One read per tap. PPSE, GPO, records, then GENERATE AC.\n"
                + "TTQ " + TTQ + " - magstripe bit only, so an MSD card answers format 1.");
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
        clearStaging();

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
        for (byte[] a : aids) {
            try {
                fci = send(iso, apdu(0x00, 0xA4, 0x04, 0x00, a, 0x00));
                rAid = bytesToHex(a);
                log("   ok " + rAid);
                break;
            } catch (IOException ignored) {
                log("   no " + bytesToHex(a));
            }
        }
        if (fci == null) {
            log("Nothing would SELECT - is this a payment card?");
            return;
        }

        // The real FCI, so the service can replay it instead of generating one.
        stage("cap_rawfci", bytesToHex(fci));
        stage("cap_aid", rAid);

        log("-- GET PROCESSING OPTIONS (TTQ " + TTQ + ")");
        List<byte[]> pdolL = new ArrayList<>();
        collect(fci, 0x9F38, pdolL);
        byte[] pdolData = pdolL.isEmpty() ? new byte[0] : buildCdolData(pdolL.get(0));
        byte[] gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, pdolData, 0x00));
        stage("cap_rawgpo", bytesToHex(gpo));

        byte[] aip = null, afl = null;
        if (gpo.length > 3 && (gpo[0] & 0xFF) == 0x80) {
            // Format 1: 80 <len> <AIP 2> <payload>. The length can be long form.
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

                // FIX: this used to assume AIP + AFL unconditionally. If the real
                // payload is 57 <len> <track 2> then the track 2 was being parsed
                // as an AFL - nonsense SFIs, 6A83 on every record, no CDOL1 and
                // so no ARQC. The three shapes are told apart here instead, and
                // the raw bytes are logged so a wrong guess is visible.
                if (rest.length >= 2 && (rest[0] & 0xFF) == 0x57
                        && (rest[1] & 0xFF) == rest.length - 2) {
                    rTrack2 = bcd(Arrays.copyOfRange(rest, 2, rest.length));
                    log("   payload is 57 <len> track 2 - no AFL, MSD never walks records");
                } else if (rest.length % 4 == 0) {
                    afl = rest;
                    log("   payload looks like a bare AFL");
                } else {
                    afl = Arrays.copyOfRange(rest, 0, 4);
                    rTrack2 = bcd(Arrays.copyOfRange(rest, 4, rest.length));
                    log("   first 4 bytes taken as an AFL, the rest as the track 2");
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
                // Sanity: a real AFL entry has SFI 1-10 and record numbers 1-31.
                if (sfi < 1 || sfi > 10 || first < 1 || first > 31) continue;
                if (last < first || last > 31) last = first;
                for (int r = first; r <= last; r++) {
                    try {
                        byte[] rec = send(iso, apdu(0x00, 0xB2, r, (sfi << 3) | 4, null, 0x00));
                        // KEY NAME: cap_rec<sfi>_<rec> - the service parses the
                        // underscore. A flat cap_rec0 is silently dropped by afl().
                        stage("cap_rec" + sfi + "_" + r, bytesToHex(rec));
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
        if (!rHolder.isEmpty()) stage("cap_holder", rHolder);

        int dsep = rTrack2.indexOf('D');
        if (dsep > 0 && rTrack2.length() >= dsep + 8) {
            if (rExpiry.isEmpty()) rExpiry = rTrack2.substring(dsep + 1, dsep + 5);
            if (rService.isEmpty()) rService = rTrack2.substring(dsep + 5, dsep + 8);
            if (rDisc.isEmpty()) rDisc = rTrack2.substring(dsep + 8);
        }

        // FIX: the PAN used to come only from 5A inside a record, so an MSD read
        // - which has no records at all - produced no PAN, read stayed false and
        // the whole capture was discarded. Fall back to the track 2.
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
            byte[] cdolData = buildCdolData(cdol1);
            byte[] cmd = apdu(0x80, 0xAE, 0x00, 0x00, cdolData, 0x00);
            try {
                byte[] rsp = send(iso, cmd);
                stage("cap_genaccmd", bytesToHex(cmd));
                stage("cap_rawgenac", bytesToHex(rsp));

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
        log("\n" + sb);

        ui.post(() -> {
            btnUse.setEnabled(read);
            if (!read) Toast.makeText(this, "Nothing usable read", Toast.LENGTH_SHORT).show();
        });
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

    private void clearStaging() {
        SharedPreferences.Editor e = prefs.edit();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_")) e.remove(k);
        }
        e.apply();
    }

    private void stage(String name, String value) {
        prefs.edit().putString(name, value).apply();
    }

    private static int sw(byte[] r) {
        if (r == null || r.length < 2) return 0;
        return ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
    }

    /**
     * FIX: data.length used to be written straight into one byte, so anything
     * over 255 silently wrapped. Extended length is now used when it is needed
     * and short form stays the default, because plenty of cards still reject
     * extended APDUs.
     */
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

    private byte[] send(IsoDep iso, byte[] apdu) throws IOException {
        byte[] rsp = iso.transceive(apdu);
        int code = sw(rsp);

        if ((code & 0xFF00) == 0x6C00 && apdu.length >= 1) {
            byte[] retry = apdu.clone();
            retry[retry.length - 1] = (byte) (code & 0xFF);
            rsp = iso.transceive(retry);
            code = sw(rsp);
        }

        if ((code & 0xFF00) == 0x6100) {
            byte[] head = Arrays.copyOf(rsp, rsp.length - 2);
            byte[] more = iso.transceive(new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, (byte) (code & 0xFF)});
            int c2 = sw(more);
            if (c2 != 0x9000) throw new IOException(String.format(Locale.US, "SW %04X", c2));
            return cat(head, Arrays.copyOf(more, more.length - 2));
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

    private byte[] buildCdolData(byte[] template) {
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
            byte[] v = defaultFor(tag, len);
            for (int k = 0; k < len; k++) {
                out.write(k < v.length ? v[k] : 0);
            }
        }
        return out.toByteArray();
    }

    private byte[] defaultFor(int tag, int len) {
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
            case 0x9F66: return hexToBytes(TTQ);
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
