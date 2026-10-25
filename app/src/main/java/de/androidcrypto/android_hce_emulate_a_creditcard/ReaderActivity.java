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
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

public class ReaderActivity extends Activity implements NfcAdapter.ReaderCallback {
    private static final String TAG = "READER";
    private final StringBuilder logBuf = new StringBuilder();
    private volatile boolean done = false;

    private void log(String s) {
        Log.d(TAG, s);
        logBuf.append(s).append('\n');
        if (logBuf.length() > 4000) logBuf.delete(0, 2000);
        if (done) return;
        String text = logBuf.toString();
        int cut = text.lastIndexOf('\n', Math.max(0, text.length() - 240));
        if (cut > 0) text = text.substring(cut + 1);
        final String shown = text;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (!done) txtReaderStatus.setText(shown);
            }
        });
    }
    public static final String EXTRA_PAN = "extra_pan";
    public static final String EXTRA_EXPIRY = "extra_expiry";
    public static final String EXTRA_SERVICE = "extra_service";
    public static final String EXTRA_DISC = "extra_disc";
    public static final String EXTRA_TRACK2 = "extra_track2";
    public static final String EXTRA_AID = "extra_aid";
    public static final String EXTRA_CARD_INDEX = "extra_card_index";

    // "2PAY.SYS.DDF01" - the contactless payment directory
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

    private TextView txtReaderStatus;
    private TextView txtReaderPan;
    private TextView txtReaderExpiry;
    private TextView txtReaderService;
    private TextView txtReaderDisc;
    private TextView txtReaderTrack2;
    private TextView txtReaderAid;

    private int cardIndex = 0;
    private int capturedRecords = 0;

    private String lastPan = "";
    private String lastExpiry = "";
    private String lastService = "";
    private String lastDisc = "";
    private String lastTrack2 = "";
    private String lastAid = "";
    private String lastArqc = "";
    private String lastIad = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reader);

        cardIndex = getIntent().getIntExtra(EXTRA_CARD_INDEX, 0);

        txtReaderStatus = (TextView) findViewById(R.id.txtReaderStatus);
        txtReaderPan = (TextView) findViewById(R.id.txtReaderPan);
        txtReaderExpiry = (TextView) findViewById(R.id.txtReaderExpiry);
        txtReaderService = (TextView) findViewById(R.id.txtReaderService);
        txtReaderDisc = (TextView) findViewById(R.id.txtReaderDisc);
        txtReaderTrack2 = (TextView) findViewById(R.id.txtReaderTrack2);
        txtReaderAid = (TextView) findViewById(R.id.txtReaderAid);

        Button btnCancelReader = (Button) findViewById(R.id.btnCancelReader);
        Button btnCopyReader = (Button) findViewById(R.id.btnCopyReader);
        Button btnUseCard = (Button) findViewById(R.id.btnUseCard);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        btnCancelReader.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        btnCopyReader.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                copyEverything();
            }
        });

        btnUseCard.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                useCard();
            }
        });

        clearFields();

        if (nfcAdapter == null) {
            txtReaderStatus.setText("This phone has no NFC hardware");
        } else if (!nfcAdapter.isEnabled()) {
            txtReaderStatus.setText("NFC is switched off - turn it on in Settings");
        } else {
            txtReaderStatus.setText("Hold the card flat on the back of the phone");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null) {
            nfcAdapter.enableReaderMode(
                    this, this,
                    NfcAdapter.FLAG_READER_NFC_A
                            | NfcAdapter.FLAG_READER_NFC_B
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
                            | NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableReaderMode(this);
        }
    }

    // ---------- raw capture ----------

    private SharedPreferences prefs() {
        return getSharedPreferences("hce_card", MODE_PRIVATE);
    }

    private void saveRaw(String key, byte[] data) {
        if (data == null || data.length == 0) return;
        prefs().edit().putString("card" + cardIndex + "_" + key, bytesToHex(data)).apply();
    }

    private void clearRaw() {
        SharedPreferences.Editor e = prefs().edit();
        String pfx = "card" + cardIndex + "_";
        for (String k : prefs().getAll().keySet()) {
            if (k.startsWith(pfx + "raw") || k.startsWith(pfx + "rec")) e.remove(k);
        }
        e.apply();
    }

    // runs on a background thread
    @Override
    public void onTagDiscovered(Tag tag) {
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            setStatus("Found a tag, but it is not an ISO-DEP card");
            return;
        }
        try {
            isoDep.connect();
            isoDep.setTimeout(5000);
            log("connected, maxTransceiveLength=" + isoDep.getMaxTransceiveLength());

            clearRaw();
            capturedRecords = 0;

            List<byte[]> pool = new ArrayList<>();
            String aid = null;

            // 1. ask the card for its payment directory
            byte[] ppse = transceive(isoDep, selectByName(PPSE_NAME));
            if (ppse != null) {
                pool.add(ppse);
                saveRaw("rawppse", ppse);
                List<byte[]> aids = new ArrayList<>();
                collectTags(ppse, 0x4F, aids);
                for (byte[] candidate : aids) {
                    byte[] fci = transceive(isoDep, selectByName(candidate));
                    if (fci != null) {
                        aid = bytesToHex(candidate);
                        pool.add(fci);
                        saveRaw("rawfci", fci);
                        break;
                    }
                }
            }

            // 2. fall back to well known application ids
            if (aid == null) {
                for (String candidate : FALLBACK_AIDS) {
                    byte[] fci = transceive(isoDep, selectByName(hexToBytes(candidate)));
                    if (fci != null) {
                        aid = candidate;
                        pool.add(fci);
                        saveRaw("rawfci", fci);
                        break;
                    }
                }
            }

            if (aid == null) {
                setStatus("Card found, but no card application answered");
                return;
            }

            // 3. start a transaction and read every record the card points at
            byte[] pdol = firstTag(pool, 0x9F38);
            byte[] gpo = transceive(isoDep, gpoCommand(pdol));
            if (gpo != null) {
                pool.add(gpo);
                saveRaw("rawgpo", gpo);

                byte[] afl = firstTag(gpo, 0x94);
                if (afl != null) {
                    for (int i = 0; i + 3 < afl.length; i += 4) {
                        int sfi = (afl[i] & 0xFF) >> 3;
                        int firstRecord = afl[i + 1] & 0xFF;
                        int recordCount = afl[i + 2] & 0xFF;
                        for (int record = firstRecord; record < firstRecord + recordCount; record++) {
                            byte[] data = transceive(isoDep, readRecord(sfi, record));
                            if (data != null) {
                                pool.add(data);
                                saveRaw("rec" + sfi + "_" + record, data);
                                capturedRecords++;
                            }
                        }
                    }
                }
            }

            // 3b. ask the card to sign a transaction (optional - never fail the whole read)
            try {
                byte[] cdol = firstTag(pool, 0x8C);
                if (cdol != null) {
                    byte[] genAc = transceive(isoDep, genAcCommand(cdol));
                    if (genAc != null) {
                        saveRaw("rawgenac", genAc);
                        byte[] payload = firstTag(genAc, 0x80);
                        if (payload == null) payload = genAc;
                        if (payload.length >= 9) {
                            lastArqc = bytesToHex(Arrays.copyOfRange(payload, 0, 8));
                            if (payload.length > 9) {
                                lastIad = bytesToHex(Arrays.copyOfRange(payload, 9, payload.length));
                            }
                        }
                    }
                }
            } catch (IOException e) {
                log("GENERATE AC skipped: " + e);
            }

            log("STEP4 pool=" + pool.size());
            // 4. pull the fields out of everything we collected
            String pan = digitsOrEmpty(firstTag(pool, 0x5A));
            String expiry = digitsOrEmpty(firstTag(pool, 0x5F24));
            String service = digitsOrEmpty(firstTag(pool, 0x5F30));
            String track2 = digitsOrEmpty(firstTag(pool, 0x57));
            String disc = "";

            // track 2 also carries the discretionary data
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

            if (expiry.length() >= 4) {
                expiry = expiry.substring(2, 4) + "/" + expiry.substring(0, 2);
            }

            vibrate();

            String tail = " (" + capturedRecords + " records captured)";
            if (pan.isEmpty()) {
                showResult("Card read, but no card number was found" + tail,
                        pan, expiry, service, disc, track2, aid);
            } else {
                showResult("Card read successfully" + tail,
                        pan, expiry, service, disc, track2, aid);
            }

        } catch (Exception e) {
          log("FAILED: " + e);
        } finally {
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

    private void setStatus(final String
