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

    private void log(String s) {
        Log.d(TAG, s);
        logBuf.append(s).append('\n');
        if (logBuf.length() > 4000) logBuf.delete(0, 2000);
        final String text = logBuf.toString();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                txtReaderStatus.setText(text);
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
            "A0000000041010",   // Mastercard
            "A0000000651010",   // JCB
            "A00000002501",     // American Express
            "F0010203040506"    // common HCE test application
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

            // 3b. ask the card to sign a transaction
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

        } catch (IOException e) {
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

    private void setStatus(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                txtReaderStatus.setText(message);
            }
        });
    }

    private void showResult(final String status, final String pan, final String expiry, final String service,
                            final String disc, final String track2, final String aid) {
        lastPan = pan;
        lastExpiry = expiry;
        lastService = service;
        lastDisc = disc;
        lastTrack2 = track2;
        lastAid = aid;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                txtReaderStatus.setText(status);
                txtReaderPan.setText(emptyToDash(pan));
                txtReaderExpiry.setText(emptyToDash(expiry));
                txtReaderService.setText(emptyToDash(service));
                txtReaderDisc.setText(emptyToDash(disc));
                txtReaderTrack2.setText(emptyToDash(track2));
                txtReaderAid.setText(emptyToDash(aid));
            }
        });
    }

    private void copyEverything() {
        String text = "CARD NUMBER: " + emptyToDash(lastPan)
                + "\nEXPIRY: " + emptyToDash(lastExpiry)
                + "\nSERVICE CODE: " + emptyToDash(lastService)
                + "\nDISCRETIONARY DATA: " + emptyToDash(lastDisc)
                + "\nTRACK 2: " + emptyToDash(lastTrack2)
                + "\nARQC / 9F26: " + emptyToDash(lastArqc)
                + "\nIAD / 9F10: " + emptyToDash(lastIad)
                + "\nAID: " + emptyToDash(lastAid);
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
        setResult(RESULT_OK, result);
        finish();
    }

    private void vibrate() {
        Vibrator vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        if (vibrator != null) {
            vibrator.vibrate(150);
        }
    }

    // ---------- APDU helpers ----------

    private byte[] transceive(IsoDep isoDep, byte[] command) throws IOException {
        log(">> " + bytesToHex(command));
        byte[] response;
        try {
            response = isoDep.transceive(command);
        } catch (IOException e) {
            log("!! transceive threw: " + e);
            throw e;
        }
        log("<< " + bytesToHex(response));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            if (response.length < 2) {
                return out.size() > 0 ? out.toByteArray() : null;
            }
            int sw1 = response[response.length - 2] & 0xFF;
            int sw2 = response[response.length - 1] & 0xFF;
            out.write(response, 0, response.length - 2);

            // the card has more data waiting
            if (sw1 == 0x61) {
                response = isoDep.transceive(new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, (byte) sw2});
                continue;
            }
            // wrong length - retry with the length the card asked for
            if (sw1 == 0x6C) {
                byte[] retry = command.clone();
                retry[retry.length - 1] = (byte) sw2;
                response = isoDep.transceive(retry);
                continue;
            }
            if (sw1 == 0x90 && sw2 == 0x00) {
                return out.toByteArray();
            }
            return null;
        }
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
        byte[] command = new byte[7 + data.length];
        command[0] = (byte) 0x80;
        command[1] = (byte) 0xA8;
        command[2] = 0x00;
        command[3] = 0x00;
        command[4] = (byte) (data.length + 2);
        command[5] = (byte) 0x83;
        command[6] = (byte) data.length;
        System.arraycopy(data, 0, command, 7, data.length);
        return command;
    }

    // answer the terminal data the card asked for in its PDOL
    private byte[] genAcCommand(byte[] cdol) {
        byte[] data = buildPdolData(cdol == null ? new byte[0] : cdol);
        byte[] command = new byte[6 + data.length];
        command[0] = (byte) 0x80;
        command[1] = (byte) 0xAE;
        command[2] = (byte) 0x80;   // 0x80 = ARQC, go online
        command[3] = 0x00;
        command[4] = (byte) data.length;
        System.arraycopy(data, 0, command, 5, data.length);
        command[command.length - 1] = 0x00;
        return command;
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
                        value[0] = (byte) (c.get(Calendar.YEAR) % 100);
                        value[1] = (byte) (c.get(Calendar.MONTH) + 1);
                        value[2] = (byte) c.get(Calendar.DAY_OF_MONTH);
                    }
                    break;
                }
                case 0x9C:
                    if (len >= 1) value[0] = 0x00;
                    break;
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
        int i = 0;
        while (i < data.length) {
            int tag = data[i++] & 0xFF;
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
            if ((tag & 0x20) != 0) collectTags(value, wanted, out);
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
        for (byte b : data) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
