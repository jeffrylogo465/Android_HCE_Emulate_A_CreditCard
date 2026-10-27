package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
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
 *   cap_label            -> directory label when the editor field is empty
 *   cap_holder           -> fallback cardholder name
 * All of these live under the "cap_" prefix, which copyStagingToCard() moves to
 * "card<N>_cap_...".
 *
 * TTQ. One field, ttq, persisted and normalised on load. 0x36 sets neither mode
 * bit, so it is a sweep value only; the cycle is 4000 / C000 / 8000.
 *
 * A 6A80 from every value means the problem is a PDOL *value*. Rather than keep
 * guessing which one, gpoWithRetry() ends with a BRUTE FORCE: it builds the data
 * once, then walks one byte at a time through 0x00..0xFF for the TTQ and for
 * each byte of the Discover-proprietary trio, resending the GPO each time. If
 * the card wants any single byte at a particular value, this finds it and says
 * which. Every AID in the PPSE is tried, not just the first.
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
    private static final String TTQ_KEY = "readerttq";

    private static final String DEFAULT_PDOL =
            "9F66029F02069F03069F1A025F2A029F37049F35019F45029F4C089F34039F2103";

    private String ttq = "4000";
    private static final String[] TTQ_CYCLE = {"4000", "C000", "8000", "3600"};

    private static final String[] FALLBACK_AIDS = {
            "A0000000031010", "A0000000032010", "A0000000041010",
            "A0000000043060", "A0000001523010", "A0000001524010",
            "A0000000250101", "A0000000651010", "A000000333010101",
            "A0000003841010"
    };

    private String ovTtq;
    private String ovTrio;

    private SharedPreferences prefs;
    private NfcAdapter nfc;

    private TextView txtLog, txtHint;
    private Button btnUse, btnTtq;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean busy = false;

    private String rPan = "", rExpiry = "", rService = "", rDisc = "", rAid = "",
            rTrack2 = "", rPsn = "", rIad = "", rAtc = "", rAip = "", rHolder = "";
    private boolean read = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREF, MODE_PRIVATE);
        ttq = prefs.getString(TTQ_KEY, "4000");
        if ("3600".equals(ttq)) ttq = "4000";
        if (!Arrays.asList(TTQ_CYCLE).contains(ttq)) ttq = TTQ_CYCLE[0];
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

        txtHint = new TextView(this);
        txtHint.setTextColor(0xFF9CA3AF);
        txtHint.setTextSize(12);
        txtHint.setPadding(0, dp(6), 0, dp(10));
        root.addView(txtHint);
        updateHint();

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

        btnTtq = new Button(this);
        btnTtq.setText("TTQ: " + ttq);
        btnTtq.setOnClickListener(v -> toggleTtq());
        root.addView(btnTtq);

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

    private void updateHint() {
        String mode;
        if ("8000".equals(ttq))           mode = " - magstripe only: format 1, no records, no cryptogram.";
        else if ("C000".equals(ttq))      mode = " - both modes: the card chooses.";
        else if ("3600".equals(ttq))      mode = " - no mode bit: the card may fall back to MSD.";
        else                              mode = " - EMV mode: format 2, an AFL, records and a real ARQC.";
        txtHint.setText("Hold the physical card flat against the back of the phone,\n"
                + "and keep it still until it says USE CARD.\n"
                + "One read per tap. PPSE, GPO, records, then GENERATE AC.\n"
                + "TTQ " + ttq + mode
                + "\nTap the TTQ button to switch.");
    }

    private void toggleTtq() {
        int i = 0;
        for (int k = 0; k < TTQ_CYCLE.length; k++) {
            if (TTQ_CYCLE[k].equals(ttq)) { i = (k + 1) % TTQ_CYCLE.length; break; }
        }
        ttq = TTQ_CYCLE[i];
        prefs.edit().putString(TTQ_KEY, ttq).apply();
        if (btnTtq != null) btnTtq.setText("TTQ: " + ttq);
        updateHint();
        Toast.makeText(this, "TTQ = " + ttq, Toast.LENGTH_SHORT).show();
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
        byte[] gpo = null;
        for (byte[] a : aids) {
            try {
                fci = send(iso, apdu(0x00, 0xA4, 0x04, 0x00, a, 0x00));
            } catch (IOException e) {
                log("   no " + bytesToHex(a) + " -> " + e.getMessage());
                fci = null;
                continue;
            }
            rAid = bytesToHex(a);
            log("   ok " + rAid);

            stage("cap_rawfci", bytesToHex(fci));
            stage("cap_aid", rAid);
            log("   FCI " + bytesToHex(fci));

            log("-- GET PROCESSING OPTIONS");
            List<byte[]> pdolL = new ArrayList<>();
            collect(fci, 0x9F38, pdolL);
            byte[] pdol = pdolL.isEmpty() ? hexToBytes(DEFAULT_PDOL) : pdolL.get(0);
            if (pdolL.isEmpty()) {
                log("   no 9F38 on the FCI - falling back to the standard contactless PDOL");
            }
            log("   PDOL " + bytesToHex(pdol));
            log("   PDOL tags " + describePdol(pdol));

            try {
                gpo = gpoWithRetry(iso, pdol);
            } catch (IOException e) {
                log("   GPO failed on every value: " + e.getMessage());
                gpo = null;
            }
            if (gpo != null) break;
            log("   next AID");
        }
        if (fci == null) {
            log("Nothing would SELECT - is this a payment card?");
            return;
        }
        if (gpo != null) stage("cap_rawgpo", bytesToHex(gpo));

        List<byte[]> labL = new ArrayList<>();
        collect(fci, 0x50, labL);
        if (!labL.isEmpty()) {
            String lb = new String(labL.get(0), java.nio.charset.StandardCharsets.US_ASCII)
                    .toUpperCase().replaceAll("[^A-Z0-9 ./'-]", "").trim();
            if (lb.length() > 16) lb = lb.substring(0, 16);
            if (!lb.isEmpty()) {
                stage("cap_label", lb);
                log("   label " + lb);
            }
        }

        byte[] aip = null, afl = null;
        if (gpo != null) {
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
                        log("   payload is 57 <len> track 2 - no AFL, MSD never walks records");
                    } else if (rest.length % 4 == 0 && looksLikeAfl(rest)) {
                        afl = rest;
                        log("   payload looks like a bare AFL");
                    } else if (rest.length > 4
                            && looksLikeAfl(Arrays.copyOfRange(rest, 0, 4))) {
                        afl = Arrays.copyOfRange(rest, 0, 4);
                        rTrack2 = bcd(Arrays.copyOfRange(rest, 4, rest.length));
                        log("   first 4 bytes as an AFL, rest as track 2");
                    } else {
                        rTrack2 = bcd(rest);
                        log("   payload read as a bare track 2");
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
                if (sfi < 1 || sfi > 30 || first < 1 || first > 31) continue;
                if (last < first || last > 31) last = first;
                for (int r = first; r <= last; r++) {
                    try {
                        byte[] rec = send(iso, apdu(0x00, 0xB2, r, (sfi << 3) | 4, null, 0x00));
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

    private static boolean looksLikeAfl(byte[] b) {
        if (b.length < 4 || b.length % 4 != 0) return false;
        for (int i = 0; i + 3 < b.length; i += 4) {
            int sfi = (b[i] & 0xFF) >> 3;
            int first = b[i + 1] & 0xFF;
            int last = b[i + 2] & 0xFF;
            if ((b[i] & 0x07) != 0) return false;
            if (sfi < 1 || sfi > 30) return false;
            if (first < 1 || first > 31) return false;
            if (last < first || last > 31) return false;
        }
        return true;
    }

    /**
     * Work down a list of attempts and stop at the first 9000:
     *
     *   1. the mode the button shows, then the rest of the cycle
     *   2. a sweep of mode x the Discover-proprietary trio
     *   3. all-zero PDOL data - does the card only care about length?
     *   4. the same data as a case-3 GPO, no trailing Le
     *   5. an empty-data GPO
     *   6. BRUTE FORCE - one byte at a time, 0x00..0xFF, for the TTQ and for
     *      each byte of DF70/DF71/DF72. If the card wants any single byte at a
     *      particular value this finds it and names it.
     *
     * The first error is kept and thrown, so the reported SW is a real refusal.
     */
    private byte[] gpoWithRetry(IsoDep iso, byte[] pdolTemplate) throws IOException {
        final String preferred = ttq;
        IOException first = null;

        List<String> order = new ArrayList<>();
        order.add(ttq);
        for (String t : TTQ_CYCLE) if (!t.equals(ttq)) order.add(t);

        for (String t : order) {
            ovTtq = null;
            ovTrio = null;
            try {
                byte[] gpo = sendGpo(iso, pdolTemplate, "TTQ " + t);
                accept(t);
                return gpo;
            } catch (IOException e) {
                if (first == null) first = e;
            }
        }

        String[] ttqs  = {"4000", "C000", "8000", "0000", "F600"};
        String[] trios = {"00", "01", "FF"};
        for (String t : ttqs) {
            for (String tr : trios) {
                ovTtq = t;
                ovTrio = tr;
                try {
                    byte[] gpo = sendGpo(iso, pdolTemplate, "TTQ " + t + " trio " + tr);
                    accept(t);
                    return gpo;
                } catch (IOException e) {
                    if (first == null) first = e;
                }
            }
        }

        ovTtq = null;
        ovTrio = null;

        if (pdolTemplate != null && pdolTemplate.length > 0) {
            byte[] z = new byte[buildCdolData(pdolTemplate).length];
            log("   GPO probe: all-zero data " + z.length + "B");
            try {
                byte[] gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, z, 0x00));
                log("   GPO ok with all-zero data");
                return gpo;
            } catch (IOException e) {
                log("   GPO all-zero -> " + e.getMessage());
                if (first == null) first = e;
            }

            byte[] d = buildCdolData(pdolTemplate);
            byte[] c3 = new byte[5 + d.length];
            c3[0] = (byte) 0x80;
            c3[1] = (byte) 0xA8;
            c3[4] = (byte) d.length;
            System.arraycopy(d, 0, c3, 5, d.length);
            log("   GPO probe: case 3, no Le");
            try {
                byte[] gpo = send(iso, c3);
                log("   GPO ok as case 3");
                return gpo;
            } catch (IOException e) {
                log("   GPO case 3 -> " + e.getMessage());
                if (first == null) first = e;
            }

            log("   GPO last resort: empty data");
            try {
                byte[] gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, new byte[0], 0x00));
                log("   GPO ok with empty data");
                return gpo;
            } catch (IOException e) {
                log("   GPO empty -> " + e.getMessage());
                if (first == null) first = e;
            }

            // ---- brute force ----
            log("   -- brute force, 0x00..0xFF per byte --");
            ovTtq = "4000";
            ovTrio = "00";
            int[][] jobs = {
                    {0x9F66, 0}, {0xDF70, 0}, {0xDF71, 0}, {0xDF71, 1},
                    {0xDF72, 0}, {0xDF72, 1}
            };
            for (int[] j : jobs) {
                byte[] gpo = brute(iso, pdolTemplate, j[0], j[1]);
                if (gpo != null) {
                    ovTtq = null;
                    ovTrio = null;
                    return gpo;
                }
            }
            ovTtq = null;
            ovTrio = null;
        }

        accept(preferred);
        throw first != null ? first : new IOException("GPO failed");
    }

    /**
     * Build the GPO data once, then walk one byte through 0x00..0xFF, resending
     * each time. Stops and reports on the first 9000.
     */
    private byte[] brute(IsoDep iso, byte[] pdolTemplate, int tag, int byteIdx) {
        byte[] data = buildCdolData(pdolTemplate);
        int off = valueOffset(pdolTemplate, tag);
        if (off < 0 || off + byteIdx >= data.length) {
            log("   brute " + String.format(Locale.US, "%04X", tag) + " not in the PDOL");
            return null;
        }
        String label = String.format(Locale.US, "%04X", tag) + "[" + byteIdx + "]";
        for (int v = 0; v <= 0xFF; v++) {
            data[off + byteIdx] = (byte) v;
            try {
                byte[] gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, data, 0x00));
                log("   GPO brute " + label + "=0x" + String.format(Locale.US, "%02X", v)
                        + " -> 9000  <-- THIS");
                return gpo;
            } catch (IOException ignored) { }
        }
        log("   brute " + label + " -> all refused");
        return null;
    }

    /** Offset of a tag's value inside the data built from this template. */
    private static int valueOffset(byte[] t, int want) {
        int i = 0, off = 0;
        while (i < t.length) {
            int tag = t[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= t.length) return -1;
                tag = (tag << 8) | (t[i++] & 0xFF);
            }
            if (i >= t.length) return -1;
            int len = t[i++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int k = 0; k < n && i < t.length; k++) {
                    len = (len << 8) | (t[i++] & 0xFF);
                }
            }
            if (tag == want) return off;
            off += len;
        }
        return -1;
    }

    private byte[] sendGpo(IsoDep iso, byte[] pdolTemplate, String what) throws IOException {
        byte[] d = pdolTemplate == null ? new byte[0] : buildCdolData(pdolTemplate);
        byte[] cmd = apdu(0x80, 0xA8, 0x00, 0x00, d, 0x00);
        log("   GPO try " + what + "  " + bytesToHex(cmd));
        try {
            return send(iso, cmd);
        } catch (IOException e) {
            log("   GPO " + what + " -> " + e.getMessage());
            throw e;
        }
    }

    private void accept(String t) {
        ovTtq = null;
        ovTrio = null;
        ttq = t;
        prefs.edit().putString(TTQ_KEY, ttq).apply();
        ui.post(() -> {
            if (btnTtq != null) btnTtq.setText("TTQ: " + ttq);
            updateHint();
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
            boolean ext = apdu.length > 6 && (apdu[4] & 0xFF) == 0x00;
            if (ext) retry[retry.length - 3] = 0x00;
            retry[retry.length - 1] = (byte) (code & 0xFF);
            rsp = iso.transceive(retry);
            code = sw(rsp);
        }

        if ((code & 0xFF00) == 0x6100) {
            ByteArrayOutputStream acc = new ByteArrayOutputStream();
            acc.write(rsp, 0, rsp.length - 2);
            int guard = 0;
            while ((code & 0xFF00) == 0x6100 && guard++ < 16) {
                byte[] more = iso.transceive(new byte[]{
                        0x00, (byte) 0xC0, 0x00, 0x00, (byte) (code & 0xFF)});
                code = sw(more);
                if (code == 0x9000 || (code & 0xFF00) == 0x6100) {
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

    private byte[] buildCdolData(byte[] template) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int declared = 0;
        int i = 0;
        while (i < template.length) {
            int at = i;
            int tag = template[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= template.length) {
                    log("   PDOL truncated mid-tag at " + at);
                    break;
                }
                tag = (tag << 8) | (template[i++] & 0xFF);
            }
            if (i >= template.length) {
                log("   PDOL truncated after tag " + String.format(Locale.US, "%04X", tag));
                break;
            }
            int len = template[i++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int k = 0; k < n && i < template.length; k++) {
                    len = (len << 8) | (template[i++] & 0xFF);
                }
            }
            declared += len;

            byte[] v = defaultFor(tag, len);
            byte[] emit = new byte[len];
            System.arraycopy(v, 0, emit, 0, Math.min(v.length, len));
            String hex = bytesToHex(emit);
            String tn = String.format(Locale.US, "%04X", tag);
            if (v.length > len) {
                log("   PDOL tag " + tn + " len " + len + " = " + hex
                        + "  (value was " + v.length + "B, truncated)");
            } else if (!knownTag(tag)) {
                log("   PDOL tag " + tn + " len " + len + " NOT in table -> " + hex);
            } else {
                log("   PDOL tag " + tn + " len " + len + " = " + hex);
            }
            out.write(emit, 0, emit.length);
        }
        byte[] data = out.toByteArray();
        if (data.length != declared) {
            log("   !! PDOL LENGTH DESYNC: built " + data.length
                    + " card declared " + declared);
        }
        return data;
    }

    private static String describePdol(byte[] t) {
        if (t == null) return "(none)";
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < t.length) {
            int tag = t[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= t.length) { sb.append("TRUNC"); break; }
                tag = (tag << 8) | (t[i++] & 0xFF);
            }
            if (i >= t.length) { sb.append("TRUNC"); break; }
            int len = t[i++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int k = 0; k < n && i < t.length; k++) {
                    len = (len << 8) | (t[i++] & 0xFF);
                }
            }
            sb.append(String.format(Locale.US, "%04X(%d) ", tag, len));
        }
        return sb.toString().trim();
    }

    private static boolean knownTag(int tag) {
        switch (tag) {
            case 0x9F02: case 0x9F03: case 0x9F1A: case 0x5F2A: case 0x9A:
            case 0x9C: case 0x9F21: case 0x9F37: case 0x9F35: case 0x9F33:
            case 0x9F34: case 0x9F40: case 0x9F66: case 0x95:
            case 0x9F6E: case 0x9F45: case 0x9F4C: case 0x9F1C: case 0x9F4E:
            case 0x9F15: case 0x9F39: case 0x9F41: case 0x9F09: case 0x9F08:
            case 0x9F4D: case 0x9F5A:
            case 0xDF70: case 0xDF71: case 0xDF72:
                return true;
            default:
                return false;
        }
    }

    private byte[] defaultFor(int tag, int len) {
        switch (tag) {
            case 0x9F02: return hexToBytes("000000001000");
            case 0x9F03: return hexToBytes("000000000000");
            case 0x9F1A: return hexToBytes("0840");
            case 0x5F2A: return hexToBytes("0840");
            case 0x9A: {
                Calendar c = Calendar.getInstance();
                return hexToBytes(String.format(Locale.US, "%02d%02d%02d",
                        c.get(Calendar.YEAR) % 100,
                        c.get(Calendar.MONTH) + 1,
                        c.get(Calendar.DAY_OF_MONTH)));
            }
            case 0x9C: return hexToBytes("00");
            case 0x95: return hexToBytes("0000000000");
            case 0x9F21: return hexToBytes("120000");
            case 0x9F37: {
                byte[] r = new byte[4];
                new Random().nextBytes(r);
                return r;
            }
            case 0x9F35: return hexToBytes("22");
            case 0x9F33: return hexToBytes("E0F8C8");
            case 0x9F34: return hexToBytes("1F0002");
            case 0x9F40: return hexToBytes("F0F0F0F0F0");
            case 0x9F66: return hexToBytes(ovTtq != null ? ovTtq : ttq);
            case 0x9F6E: return hexToBytes("00000000");
            case 0x9F45: return hexToBytes("0000");
            case 0x9F4C: return ascii("TERM0001");
            case 0x9F1C: return ascii("TERM0001");
            case 0x9F4E: return ascii("SHOP");
            case 0x9F15: return hexToBytes("5411");
            case 0x9F39: return hexToBytes("02");
            case 0x9F41: return hexToBytes("0001");
            case 0x9F09: return hexToBytes("0002");
            case 0x9F08: return hexToBytes("008C");
            case 0x9F4D: return hexToBytes("0000");
            case 0x9F5A: return hexToBytes("00");
            case 0xDF70: return hexToBytes(ovTrio != null ? ovTrio : "01");
            case 0xDF71: return hexToBytes(ovTrio != null ? ovTrio + ovTrio : "0001");
            case 0xDF72: return hexToBytes(ovTrio != null ? ovTrio + ovTrio : "0001");
            default: return new byte[len];
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
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
