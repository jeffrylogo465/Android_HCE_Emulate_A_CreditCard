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
 * Reads a physical contactless card and returns it to MainActivity.
 *
 * The whole point of this screen is the tail of readCard(): after the AFL walk
 * it sends GENERATE AC (80 AE) and stages the exact command and response under
 * cap_genaccmd / cap_rawgenac. MainActivity's key scan needs those two, and it
 * needs the command as the FULL apdu so it can pull Lc out of index 4.
 *
 * Staging keys written here (all under the "cap_" prefix, which
 * MainActivity.copyStagingToCard() moves to "card<N>_cap_..."):
 *   cap_rec0, cap_rec1 ...   every READ RECORD response
 *   cap_rawgpo               the GPO response (first byte 80 or 77)
 *   cap_genaccmd             full 80AE..00 frame
 *   cap_rawgenac             GENERATE AC response, contains 9F26 + 9F36
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

    /** Used only if the card will not answer the PPSE SELECT. */
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

    // result of the last good read
    private String rPan = "", rExpiry = "", rService = "", rDisc = "", rAid = "",
            rTrack2 = "", rPsn = "", rIad = "", rAtc = "", rAip = "";
    private boolean read = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREF, MODE_PRIVATE);
        buildUi();
        nfc = NfcAdapter.getDefaultAdapter(this);
        if (nfc == null) log("No NFC adapter on this device");
    }

    // ---------------- UI (programmatic, no layout dependency) ----------------

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
                + "One read per tap. It walks PPSE, GPO, the records, then GENERATE AC.");
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

        Button btnAgain = new Button(this);
        btnAgain.setText("READ AGAIN");
        btnAgain.setOnClickListener(v -> {
            txtLog.setText("");
            btnUse.setEnabled(false);
            read = false;
            armReader();
        });
        root.addView(btnAgain);

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
            View parent = (View) txtLog.getParent();
            if (parent instanceof ScrollView) ((ScrollView) parent).fullScroll(View.FOCUS_DOWN);
        });
    }

    // ---------------- reader mode ----------------

    private void armReader() {
        if (nfc == null) {
            log("No NFC adapter");
            return;
        }
        if (!nfc.isEnabled()) {
            log("NFC is off - turn it on and tap READ AGAIN");
            return;
        }
        Bundle opts = new Bundle();
        opts.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500);
        nfc.enableReaderMode(this, this,
                NfcAdapter.FLAG_READER_NFC_A
                        | NfcAdapter.FLAG_READER_NFC_B
                        | NfcAdapter.FLAG_READER_NFC_F
                        | NfcAdapter.FLAG_READER_NFC_V
                        | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                opts);
        log("Ready - tap the card on the back of the phone");
    }

    private void disarmReader() {
        if (nfc != null) {
            try { nfc.disableReaderMode(this); } catch (Exception ignored) { }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!read) armReader();
    }

    @Override
    protected void onPause() {
        super.onPause();
        disarmReader();
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        if (busy || read) return;
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

    // ---------------- the flow ----------------

    private void readCard(IsoDep iso) throws IOException {
        read = false;
        rPan = rExpiry = rService = rDisc = rAid = "";
        rTrack2 = rPsn = rIad = rAtc = rAip = "";
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

        log("-- GET PROCESSING OPTIONS");
        List<byte[]> pdolL = new ArrayList<>();
        collect(fci, 0x9F38, pdolL);
        byte[] pdolData = pdolL.isEmpty() ? new byte[0] : buildCdolData(pdolL.get(0));
        byte[] gpo = send(iso, apdu(0x80, 0xA8, 0x00, 0x00, pdolData, 0x00));
        stage("cap_rawgpo", bytesToHex(gpo));

        byte[] aip = null, afl = null;
        if (gpo.length > 1 && (gpo[0] & 0xFF) == 0x80) {
            // format 1: 80 <len> AIP(2) AFL(..)
            int len = gpo[1] & 0xFF;
            if (len >= 2 && 2 + len <= gpo.length) {
                aip = Arrays.copyOfRange(gpo, 2, 4);
                afl = Arrays.copyOfRange(gpo, 4, 2 + len);
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
                if (sfi == 0 || first == 0) continue;
                if (last == 0 || last < first) last = first;
                for (int r = first; r <= last; r++) {
                    try {
                        byte[] rec = send(iso, apdu(0x00, 0xB2, r, (sfi << 3) | 4, null, 0x00));
                        stage("cap_rec" + recNo, bytesToHex(rec));
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

        // pull the card data out of the records
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

        // derive expiry/service/discretionary from the track 2 when needed
        int dsep = rTrack2.indexOf('D');
        if (dsep > 0 && rTrack2.length() >= dsep + 8) {
            if (rExpiry.isEmpty()) rExpiry = rTrack2.substring(dsep + 1, dsep + 5);
            if (rService.isEmpty()) rService = rTrack2.substring(dsep + 5, dsep + 8);
            if (rDisc.isEmpty()) rDisc = rTrack2.substring(dsep + 8);
        }
        if (rService.length() != 3) rService = "201";
        if (rPsn.length() > 2) rPsn = rPsn.substring(0, 2);
        if (rExpiry.length() > 4) rExpiry = rExpiry.substring(0, 4);

        // ---- GENERATE AC: the whole reason this screen exists ----
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
            if (read) {
                disarmReader();
                log("Done - take the card off. Tap USE CARD, or READ AGAIN.");
            } else {
                Toast.makeText(this, "Nothing usable read", Toast.LENGTH_SHORT).show();
            }
        });
    }

    // ---------------- result ----------------

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

    // ---------------- staging ----------------

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

    // ---------------- APDU plumbing ----------------

    private static int sw(byte[] r) {
        if (r == null || r.length < 2) return 0;
        return ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
    }

    private static byte[] apdu(int cla, int ins, int p1, int p2, byte[] data, int le) {
        if (data == null) {
            return new byte[]{(byte) cla, (byte) ins, (byte) p1, (byte) p2, (byte) le};
        }
        byte[] out = new byte[5 + data.length + 1];
        out[0] = (byte) cla;
        out[1] = (byte) ins;
        out[2] = (byte) p1;
        out[3] = (byte) p2;
        out[4] = (byte) data.length;
        System.arraycopy(data, 0, out, 5, data.length);
        out[out.length - 1] = (byte) le;
        return out;
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

    // ---------------- TLV ----------------

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

    // ---------------- CDOL / PDOL builder ----------------

    /** The template is a bare list of tag+length with no values. Emit the right
     *  number of bytes for each, with sensible defaults where a zero would make
     *  the card unhappy. */
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
            case 0x9F02: return hexToBytes("000000001000");   // 10.00
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
            case 0x9F66: return hexToBytes("3600");
            default: return new byte[len];
        }
    }

    // ---------------- small helpers ----------------

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

    /** BCD to text, trailing F pad removed. 0xD nibbles stay as 'D', which is
     *  what the track 2 separator normalises to. */
    private static String bcd(byte[] d) {
        String h = bytesToHex(d);
        while (h.endsWith("F")) h = h.substring(0, h.length() - 1);
        return h;
    }
}
