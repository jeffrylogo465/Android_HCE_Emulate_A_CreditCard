package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.os.Vibrator;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

public class ReaderActivity extends Activity implements NfcAdapter.ReaderCallback {
    private static final String TAG = "READER";
    private final StringBuilder logBuf = new StringBuilder();
    private volatile boolean done = false;
    private volatile boolean reading = false;
    private int attempts = 0;
    private boolean fresh = true;
    private final android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());

    private void log(String s) {
        Log.d(TAG, s);
        final String text;
        synchronized (logBuf) {
            logBuf.append(s).append('\n');
            if (logBuf.length() > 4000) logBuf.delete(0, 2000);
            text = logBuf.toString();
        }
        if (done) return;
        String shown = text;
        int cut = shown.lastIndexOf('\n', Math.max(0, shown.length() - 240));
        if (cut > 0) shown = shown.substring(cut + 1);
        final String finalShown = shown;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (!done) txtReaderStatus.setText(finalShown);
            }
        });
    }

    /** Safe snapshot of the log buffer from any thread. */
    private String logText() {
        synchronized (logBuf) {
            return logBuf.toString();
        }
    }

    public static final String EXTRA_PAN = "extra_pan";
    public static final String EXTRA_EXPIRY = "extra_expiry";
    public static final String EXTRA_SERVICE = "extra_service";
    public static final String EXTRA_DISC = "extra_disc";
    public static final String EXTRA_TRACK2 = "extra_track2";
    public static final String EXTRA_AID = "extra_aid";
    public static final String EXTRA_PSN = "extra_psn";
    public static final String EXTRA_IAD = "extra_iad";
    public static final String EXTRA_ATC = "extra_atc";
    public static final String EXTRA_AIP = "extra_aip";
    /** Target wallet slot. The capture itself is staged, so this is informational. */
    public static final String EXTRA_CARD_INDEX = "extra_card_index";

    private static final byte[] PPSE_NAME = {
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31
    };
    private static final String[] FALLBACK_AIDS = {
            "A0000000031010",   // Visa
            "A0000000032010",   // Visa Electron
            "A0000000041010",   // Mastercard
            "A0000000043060",   // Maestro
            "A0000000046000",   // Cirrus
            "A00000002501",     // American Express
            "A0000000152001",   // Discover
            "A0000001523010",   // Diners
            "A0000000651010",   // JCB
            "A000000333010101", // UnionPay
            "A0000002771010",   // Interac
            "A00000038410",     // Eftpos
            "A0000003591010",   // Girocard
            "F0010203040506"    // generic HCE test application
    };

    private NfcAdapter nfcAdapter;

    private TextView txtReaderStatus, txtReaderPan, txtReaderExpiry, txtReaderService,
            txtReaderDisc, txtReaderTrack2, txtReaderAid;

    private int capturedRecords = 0;

    /** Status word of the most recent transceive. 0x9000 means the command worked. */
    private volatile int lastSw1 = 0, lastSw2 = 0;

    private String lastPan = "";
    private String lastExpiry = "";
    private String lastService = "";
    private String lastDisc = "";
    private String lastTrack2 = "";
    private String lastAid = "";
    private String lastArqc = "";
    private String lastIad = "";
    private String lastPsn = "";
    private String lastAtc = "";
    private String lastAip = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reader);

        txtReaderStatus = findViewById(R.id.txtReaderStatus);
        txtReaderPan = findViewById(R.id.txtReaderPan);
        txtReaderExpiry = findViewById(R.id.txtReaderExpiry);
        txtReaderService = findViewById(R.id.txtReaderService);
        txtReaderDisc = findViewById(R.id.txtReaderDisc);
        txtReaderTrack2 = findViewById(R.id.txtReaderTrack2);
        txtReaderAid = findViewById(R.id.txtReaderAid);

        Button btnCancelReader = findViewById(R.id.btnCancelReader);
        Button btnCopyReader = findViewById(R.id.btnCopyReader);
        Button btnUseCard = findViewById(R.id.btnUseCard);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        btnCancelReader.setOnClickListener(v -> finish());
        btnCopyReader.setOnClickListener(v -> copyEverything());
        btnCopyReader.setOnLongClickListener(v -> {
            startActivity(new Intent(ReaderActivity.this, CaptureActivity.class));
            return true;
        });
        btnUseCard.setOnClickListener(v -> useCard());

        clearFields();

        if (nfcAdapter == null) {
            txtReaderStatus.setText("This phone has no NFC hardware");
        } else if (!nfcAdapter.isEnabled()) {
            txtReaderStatus.setText("NFC is switched off - turn it on in Settings");
        } else {
            txtReaderStatus.setText("Hold the card flat on the back of the phone");
        }
    }

    private void restartDiscovery() {
        handler.post(() -> {
            if (nfcAdapter == null) return;
            nfcAdapter.disableReaderMode(ReaderActivity.this);
            handler.postDelayed(() -> {
                if (nfcAdapter != null) {
                    nfcAdapter.enableReaderMode(ReaderActivity.this, ReaderActivity.this,
                            NfcAdapter.FLAG_READER_NFC_A
                                    | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
                                    | NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                            null);
                }
            }, 350);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null && nfcAdapter.isEnabled()) {
            nfcAdapter.enableReaderMode(
                    this, this,
                    NfcAdapter.FLAG_READER_NFC_A
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
                            | NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) nfcAdapter.disableReaderMode(this);
    }

    // ---------- raw capture (staging area, MainActivity namespaces it) ----------

    private SharedPreferences prefs() {
        return getSharedPreferences("hce_card", MODE_PRIVATE);
    }

    private void saveRaw(String key, byte[] data) {
        if (data == null || data.length == 0) return;
        prefs().edit().putString("cap_" + key, bytesToHex(data)).apply();
    }

    private void saveText(String key, String value) {
        prefs().edit().putString("cap_" + key, value == null ? "" : value).apply();
    }

    private void clearRaw() {
        SharedPreferences.Editor e = prefs().edit();
        for (String k : prefs().getAll().keySet()) {
            if (k.startsWith("cap_")) e.remove(k);
        }
        e.apply();
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        if (done || reading) return;
        reading = true;
        attempts++;
        log("-- read attempt " + attempts);

        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            reading = false;
            setStatus("Found a tag, but it is not an ISO-DEP card");
            return;
        }
        try {
            isoDep.connect();
            isoDep.setTimeout(5000);
            try { Thread.sleep(150); } catch (InterruptedException ignored) { }
            log("connected, maxTransceiveLength=" + isoDep.getMaxTransceiveLength());

            if (fresh) {
                clearRaw();
                fresh = false;
            }

            List<byte[]> pool = new ArrayList<>();
            for (String k : prefs().getAll().keySet()) {
                if (k.startsWith("cap_rec") || k.startsWith("cap_raw")) {
                    String v = prefs().getString(k, "");
                    if (v != null && !v.isEmpty() && v.length() % 2 == 0) pool.add(hexToBytes(v));
                }
            }

            capturedRecords = 0;

            String aid = null;

            byte[] ppse = transceive(isoDep, selectByName(PPSE_NAME));
            if (ppse != null && lastOk()) {
                pool.add(ppse);
                saveRaw("rawppse", ppse);
                List<byte[]> aids = new ArrayList<>();
                collectTags(ppse, 0x4F, aids);
                for (byte[] candidate : aids) {
                    byte[] fci = transceive(isoDep, selectByName(candidate));
                    // FIX: require 9000. transceiveOnce returns the payload even on a
                    // failure status, so a rejected SELECT used to look like a good one.
                    if (fci != null && lastOk()) {
                        aid = bytesToHex(candidate);
                        pool.add(fci);
                        saveRaw("rawfci", fci);
                        break;
                    }
                }
            }

            if (aid == null) {
                for (String candidate : FALLBACK_AIDS) {
                    byte[] fci = transceive(isoDep, selectByName(hexToBytes(candidate)));
                    if (fci != null && lastOk()) {          // FIX: 9000 only
                        aid = candidate;
                        pool.add(fci);
                        saveRaw("rawfci", fci);
                        break;
                    }
                }
            }

            if (aid == null) {
                if (pool.isEmpty()) {
                    setStatus("Card found, but no card application answered");
                    return;
                }
                aid = prefs().getString("cap_aid", "");
            }

            byte[] pdol = firstTag(pool, 0x9F38);
            byte[] gpo = transceive(isoDep, gpoCommand(pdol));
            if (gpo != null && lastOk()) {
                pool.add(gpo);
                saveRaw("rawgpo", gpo);

                // FIX: in a magstripe (tag 80) GPO the AIP is two raw bytes, not a
                // TLV - and collectTags only recurses into CONSTRUCTED tags (bit 6),
                // which 0x80 is not. So firstTag(gpo, 0x82) can never find it there.
                // Without this the real card's AIP was silently lost and the
                // emulator fell back to DEFAULT_AIP "3080".
                byte[] aip = firstTag(gpo, 0x82);
                if (aip == null && gpo.length >= 4 && (gpo[0] & 0xFF) == 0x80) {
                    aip = new byte[]{gpo[2], gpo[3]};
                }
                if (aip != null) {
                    lastAip = bytesToHex(aip);
                    saveText("aip", lastAip);
                }

                byte[] afl = firstTag(gpo, 0x94);
                if (afl != null) {
                    for (int i = 0; i + 3 < afl.length; i += 4) {
                        int sfi = (afl[i] & 0xFF) >> 3;
                        int firstRecord = afl[i + 1] & 0xFF;
                        int lastRecord = afl[i + 2] & 0xFF;   // last, not count
                        for (int record = firstRecord; record <= lastRecord; record++) {
                            byte[] data = transceive(isoDep, readRecord(sfi, record));
                            if (data != null && lastOk()) {   // FIX: 9000 only
                                pool.add(data);
                                saveRaw("rec" + sfi + "_" + record, data);
                                capturedRecords++;
                            }
                        }
                    }
                }
            }

            byte[] aflSrc = (gpo != null) ? firstTag(gpo, 0x94) : null;
            if (aflSrc == null) {
                String gpoHex = prefs().getString("cap_rawgpo", "");
                if (!gpoHex.isEmpty()) aflSrc = firstTag(hexToBytes(gpoHex), 0x94);
            }

            int expected = 0;
            if (aflSrc != null) {
                for (int i = 0; i + 3 < aflSrc.length; i += 4) {
                    int firstRecord = aflSrc[i + 1] & 0xFF;
                    int lastRecord = aflSrc[i + 2] & 0xFF;
                    expected += (lastRecord - firstRecord + 1);
                }
            }

            // optional: ask the card to sign, and harvest the ATC / ARQC / IAD by tag
            try {
                byte[] cdol = firstTag(pool, 0x8C);
                if (cdol != null) {
                    byte[] genAcCmd = genAcCommand(cdol);
                    byte[] genAc = transceive(isoDep, genAcCmd);
                    if (genAc != null && lastOk()) {          // FIX: 9000 only
                        // keep the command too - its CDOL data is the MAC input
                        saveRaw("genaccmd", genAcCmd);
                        saveRaw("rawgenac", genAc);

                        byte[] arqcTag = firstTag(genAc, 0x9F26);
                        if (arqcTag != null) lastArqc = bytesToHex(arqcTag);

                        byte[] iadTag = firstTag(genAc, 0x9F10);
                        if (iadTag != null) lastIad = bytesToHex(iadTag);

                        byte[] atcTag = firstTag(genAc, 0x9F36);
                        if (atcTag != null) {
                            lastAtc = bytesToHex(atcTag);
                            saveText("atc", lastAtc);
                        }
                    }
                }
            } catch (IOException e) {
                log("GENERATE AC skipped: " + e);
            }

            log("STEP4 pool=" + pool.size() + " stored=" + capturedRecords + "/" + expected);

            String pan = digitsOrEmpty(firstTag(pool, 0x5A));
            String expiry = digitsOrEmpty(firstTag(pool, 0x5F24));
            String service = digitsOrEmpty(firstTag(pool, 0x5F30));
            String track2 = digitsOrEmpty(firstTag(pool, 0x57));
            String psn = digitsOrEmpty(firstTag(pool, 0x5F34));
            String disc = "";

            int separator = track2.indexOf('D');
            if (separator > 0) {
                if (pan.isEmpty()) pan = track2.substring(0, separator);
                if (expiry.isEmpty() && separator + 5 <= track2.length()) {
                    expiry = track2.substring(separator + 1, separator + 5);
                }
                if (service.isEmpty() && separator + 8 <= track2.length()) {
                    service = track2.substring(separator + 5, separator + 8);
                }
                if (separator + 8 < track2.length()) {
                    disc = track2.substring(separator + 8);
                }
            }

            // keep expiry as YYMM - that is what the emulator expects
            if (expiry.length() > 4) expiry = expiry.substring(0, 4);
            if (psn.isEmpty()) psn = "00";
            if (psn.length() > 2) psn = psn.substring(0, 2);

            lastPsn = psn;

            saveText("pan", pan);
            saveText("expiry", expiry);
            saveText("service", service);
            saveText("track2", track2);
            saveText("discretionary", disc);
            saveText("aid", aid);
            saveText("psn", psn);
            if (!lastIad.isEmpty()) saveText("iad", lastIad);

            // proves the record staging worked - check this line in logcat
            log("stored records: " + capturedRecords + " under cap_rec<sfi>_<rec>");

            vibrate();

            String tail = " (" + capturedRecords + " of " + expected + " records)";
            if (pan.isEmpty()) {
                showResult("Card read, but no card number was found" + tail,
                        pan, expiry, service, disc, track2, aid);
            } else {
                if (expected == 0 || capturedRecords >= expected) done = true;
                showResult("Card read successfully" + tail,
                        pan, expiry, service, disc, track2, aid);
            }

        } catch (Exception e) {
            log("FAILED: " + e);
            restartDiscovery();
        } finally {
            reading = false;
            try { isoDep.close(); } catch (IOException ignored) { }
        }
    }

    // ---------- screen ----------

    private void clearFields() {
        txtReaderPan.setText("-");
        txtReaderExpiry.setText("-");
        txtReaderService.setText("-");
        txtReaderDisc.setText("-");
        txtReaderTrack2.setText("-");
        txtReaderAid.setText("-");
    }

    private void setStatus(final String message) {
        runOnUiThread(() -> txtReaderStatus.setText(message));
    }

    private void showResult(final String status, final String pan, final String expiry,
                            final String service, final String disc, final String track2,
                            final String aid) {
        log("RESULT: " + status);
        lastPan = pan;
        lastExpiry = expiry;
        lastService = service;
        lastDisc = disc;
        lastTrack2 = track2;
        lastAid = aid;
        runOnUiThread(() -> {
            txtReaderStatus.setText(status);
            txtReaderPan.setText(emptyToDash(pan));
            txtReaderExpiry.setText(emptyToDash(expiry));
            txtReaderService.setText(emptyToDash(service));
            txtReaderDisc.setText(emptyToDash(disc));
            txtReaderTrack2.setText(emptyToDash(track2));
            txtReaderAid.setText(emptyToDash(aid));
        });
    }

    private void copyEverything() {
        String text = "CARD NUMBER: " + emptyToDash(lastPan)
                + "\nEXPIRY: " + emptyToDash(lastExpiry)
                + "\nSERVICE CODE: " + emptyToDash(lastService)
                + "\nDISCRETIONARY DATA: " + emptyToDash(lastDisc)
                + "\nTRACK 2: " + emptyToDash(lastTrack2)
                + "\nPAN SEQ: " + emptyToDash(lastPsn)
                + "\nARQC / 9F26: " + emptyToDash(lastArqc)
                + "\nIAD / 9F10: " + emptyToDash(lastIad)
                + "\nATC / 9F36: " + emptyToDash(lastAtc)
                + "\nAIP / 82: " + emptyToDash(lastAip)
                + "\nAID: " + emptyToDash(lastAid)
                + "\n\nLOG:\n" + logText();
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("card data", text));
        }
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
    }

    private void useCard() {
        if (lastPan.isEmpty()) {
            Toast.makeText(this, "Read a card first", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent result = new Intent();
        result.putExtra(EXTRA_PAN, lastPan);
        result.putExtra(EXTRA_EXPIRY, lastExpiry);
        result.putExtra(EXTRA_SERVICE, lastService);
        result.putExtra(EXTRA_DISC, lastDisc);
        result.putExtra(EXTRA_TRACK2, lastTrack2);
        result.putExtra(EXTRA_AID, lastAid);
        result.putExtra(EXTRA_PSN, lastPsn);
        result.putExtra(EXTRA_IAD, lastIad);
        result.putExtra(EXTRA_ATC, lastAtc);
        result.putExtra(EXTRA_AIP, lastAip);
        setResult(RESULT_OK, result);
        finish();
    }

    private void vibrate() {
        try {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            if (v != null) v.vibrate(150);
        } catch (Exception ignored) { }
    }

    // ---------- APDU helpers ----------

    /** True when the last command completed with 9000. */
    private boolean lastOk() {
        return lastSw1 == 0x90 && lastSw2 == 0x00;
    }

    private byte[] transceive(IsoDep isoDep, byte[] command) throws IOException {
        // FIX: clear first, so a stale 9000 from the previous command cannot leak
        // out and make a failed command look successful.
        lastSw1 = 0;
        lastSw2 = 0;

        IOException last = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                return transceiveOnce(isoDep, command);
            } catch (IOException e) {
                last = e;
                try { Thread.sleep(120); } catch (InterruptedException ignored) { }
                try {
                    if (!isoDep.isConnected()) isoDep.connect();
                } catch (Exception e2) {
                    log("!! tag went stale - recycling the field");
                    throw last;
                }
            }
        }
        throw last;
    }

    private byte[] transceiveOnce(IsoDep isoDep, byte[] command) throws IOException {
        log(">> " + bytesToHex(command));
        byte[] response;
        try {
            response = isoDep.transceive(command);
        } catch (IOException e) {
            log("!! " + e);
            throw e;
        }
        log("<< " + bytesToHex(response));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int guard = 0;
        while (guard++ < 16) {
            if (response.length < 2) {
                lastSw1 = 0;
                lastSw2 = 0;
                return out.size() > 0 ? out.toByteArray() : null;
            }
            int sw1 = response[response.length - 2] & 0xFF;
            int sw2 = response[response.length - 1] & 0xFF;
            lastSw1 = sw1;                                    // FIX: record the status
            lastSw2 = sw2;
            out.write(response, 0, response.length - 2);

            if (sw1 == 0x61) {
                response = isoDep.transceive(new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, (byte) sw2});
                continue;
            }
            if (sw1 == 0x6C) {
                byte[] retry = command.clone();
                retry[retry.length - 1] = (byte) sw2;
                response = isoDep.transceive(retry);
                continue;
            }
            if (sw1 == 0x90 && sw2 == 0x00) {
                return out.toByteArray();
            }
            // FIX: say the status out loud. A non-9000 used to be swallowed
            // entirely, so a rejected SELECT read exactly like a good one.
            log("!! sw=" + String.format("%02X%02X", sw1, sw2)
                    + " payload=" + out.size() + " bytes");
            return out.size() > 0 ? out.toByteArray() : null;
        }
        log("!! transceive loop guard hit");
        return out.size() > 0 ? out.toByteArray() : null;
    }

    private byte[] selectByName(byte[] name) {
        byte[] command = new byte[6 + name.length];
        command[0] = 0x00;
        command[1] = (byte) 0xA4;
        command[2] = 0x04;
        command[3] = 0x00;
        command[4] = (byte) name.length;
        System.arraycopy(name, 0, command, 5, name.length);
        command[command.length - 1] = 0x00;
        return command;
    }

    private byte[] gpoCommand(byte[] pdol) {
        byte[] data = buildPdolData(pdol == null ? new byte[0] : pdol);
        byte[] command = new byte[8 + data.length];
        command[0] = (byte) 0x80;
        command[1] = (byte) 0xA8;
        command[2] = 0x00;
        command[3] = 0x00;
        command[4] = (byte) (data.length + 2);
        command[5] = (byte) 0x83;
        command[6] = (byte) data.length;
        System.arraycopy(data, 0, command, 7, data.length);
        command[command.length - 1] = 0x00;
        return command;
    }

    private byte[] genAcCommand(byte[] cdol) {
        byte[] data = buildPdolData(cdol == null ? new byte[0] : cdol);
        byte[] command = new byte[6 + data.length];
        command[0] = (byte) 0x80;
        command[1] = (byte) 0xAE;
        command[2] = (byte) 0x80;   // ask for ARQC
        command[3] = 0x00;
        command[4] = (byte) data.length;
        System.arraycopy(data, 0, command, 5, data.length);
        command[command.length - 1] = 0x00;
        return command;
    }

    private static byte bcd(int v) {
        return (byte) (((v / 10) << 4) | (v % 10));
    }

    private byte[] buildPdolData(byte[] pdol) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i + 1 < pdol.length) {
            int tag = pdol[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= pdol.length) break;
                tag = (tag << 8) | (pdol[i++] & 0xFF);
            }
            if (i >= pdol.length) break;
            int len = pdol[i++] & 0xFF;
            byte[] value = new byte[len];
            switch (tag) {
                case 0x9F02: {
                    byte[] amount = hexToBytes("000000001000");
                    System.arraycopy(amount, 0, value, 0, Math.min(len, amount.length));
                    break;
                }
                case 0x9F1A:
                    if (len >= 2) { value[0] = 0x08; value[1] = 0x40; }
                    break;
                case 0x5F2A:
                    if (len >= 2) { value[0] = 0x08; value[1] = 0x40; }
                    break;
                case 0x9A: {
                    Calendar c = Calendar.getInstance();
                    if (len >= 3) {
                        value[0] = bcd(c.get(Calendar.YEAR) % 100);
                        value[1] = bcd(c.get(Calendar.MONTH) + 1);
                        value[2] = bcd(c.get(Calendar.DAY_OF_MONTH));
                    }
                    break;
                }
                case 0x9C:
                    if (len >= 1) value[0] = 0x00;
                    break;
                case 0x9F66:
                    if (len >= 1) value[0] = 0x76;
                    break;
                case 0x9F35:
                    if (len >= 1) value[0] = 0x22;
                    break;
                case 0x9F37: {
                    long n = System.nanoTime();
                    for (int k = len - 1; k >= 0; k--) { value[k] = (byte) n; n >>= 8; }
                    break;
                }
                default:
                    break;
            }
            out.write(value, 0, value.length);
        }
        return out.toByteArray();
    }

    private byte[] readRecord(int sfi, int record) {
        return new byte[]{0x00, (byte) 0xB2, (byte) record, (byte) ((sfi << 3) | 0x04), 0x00};
    }

    // ---------- TLV helpers ----------

    private void collectTags(byte[] data, int wanted, List<byte[]> out) {
        collectTags(data, wanted, out, 0);
    }

    private void collectTags(byte[] data, int wanted, List<byte[]> out, int depth) {
        if (depth > 8) return;
        int i = 0;
        while (i < data.length) {
            int tag = data[i++] & 0xFF;
            boolean constructed = (tag & 0x20) != 0;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= data.length) break;
                tag = (tag << 8) | (data[i++] & 0xFF);
            }
            if (i >= data.length) break;
            int length = data[i++] & 0xFF;
            if ((length & 0x80) != 0) {
                int n = length & 0x7F;
                length = 0;
                for (int k = 0; k < n && i < data.length; k++) {
                    length = (length << 8) | (data[i++] & 0xFF);
                }
            }
            if (i + length > data.length) break;
            byte[] value = new byte[length];
            System.arraycopy(data, i, value, 0, length);
            if (tag == wanted) out.add(value);
            if (constructed) collectTags(value, wanted, out, depth + 1);
            i += length;
        }
    }

    private byte[] firstTag(byte[] data, int tag) {
        List<byte[]> found = new ArrayList<>();
        collectTags(data, tag, found);
        return found.isEmpty() ? null : found.get(0);
    }

    private byte[] firstTag(List<byte[]> pool, int tag) {
        for (byte[] block : pool) {
            List<byte[]> found = new ArrayList<>();
            collectTags(block, tag, found);
            if (!found.isEmpty()) return found.get(0);
        }
        return null;
    }

    private static String digits(byte[] value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value) {
            int hi = (b >> 4) & 0x0F;
            int lo = b & 0x0F;
            if (hi != 0x0F) sb.append(Integer.toHexString(hi));
            if (lo != 0x0F) sb.append(Integer.toHexString(lo));
        }
        return sb.toString().toUpperCase();
    }

    private static String digitsOrEmpty(byte[] value) {
        return value == null ? "" : digits(value);
    }

    private static String emptyToDash(String value) {
        return (value == null || value.isEmpty()) ? "-" : value;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }
}
