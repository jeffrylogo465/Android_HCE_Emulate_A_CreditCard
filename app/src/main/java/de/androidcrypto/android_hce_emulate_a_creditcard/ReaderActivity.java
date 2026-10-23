package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.os.Vibrator;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ReaderActivity extends Activity implements NfcAdapter.ReaderCallback {

    // "2PAY.SYS.DDF01" - the contactless payment directory
    private static final byte[] PPSE_NAME = {
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31
    };

    // used only if the card does not expose the payment directory
    private static final String[] FALLBACK_AIDS = {
            "A0000000031010",   // Visa
            "A0000000041010",   // Mastercard
            "A0000000651010",   // JCB
            "A00000002501",     // American Express
            "F0010203040506"    // common HCE test application
    };

    private NfcAdapter nfcAdapter;
    private TextView resultText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reader);

        resultText = (TextView) findViewById(R.id.resultText);
        Button readButton = (Button) findViewById(R.id.readButton);
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        readButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                resultText.setText("Tap a card on the back of the phone");
            }
        });

        if (nfcAdapter == null) {
            resultText.setText("This phone has no NFC hardware");
        } else if (!nfcAdapter.isEnabled()) {
            resultText.setText("NFC is switched off. Turn it on in Settings.");
        } else {
            resultText.setText("Tap a card on the back of the phone");
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

    // runs on a background thread
    @Override
    public void onTagDiscovered(Tag tag) {
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            show("Found a tag, but it is not an ISO-DEP card.");
            return;
        }
        try {
            isoDep.connect();
            isoDep.setTimeout(5000);

            String source = null;
            byte[] answer = null;

            // 1. ask the card for its payment directory
            byte[] ppse = transceive(isoDep, selectByName(PPSE_NAME));
            if (ppse != null) {
                List<byte[]> aids = new ArrayList<>();
                collectTags(ppse, 0x4F, aids);
                for (byte[] aid : aids) {
                    byte[] fci = transceive(isoDep, selectByName(aid));
                    if (fci != null) {
                        source = "application " + bytesToHex(aid);
                        answer = fci;
                        break;
                    }
                }
                if (answer == null) {
                    source = "payment directory";
                    answer = ppse;
                }
            }

            // 2. fall back to well known application ids
            if (answer == null) {
                for (String aid : FALLBACK_AIDS) {
                    byte[] fci = transceive(isoDep, selectByName(hexToBytes(aid)));
                    if (fci != null) {
                        source = "application " + aid;
                        answer = fci;
                        break;
                    }
                }
            }

            vibrate();

            if (answer == null) {
                String uid = bytesToHex(tag.getId());
                copy(uid);
                show("Card found, but no application answered.\nUID: " + uid);
                return;
            }

            String data = bytesToHex(answer);
            copy(data);
            show("Read OK from " + source + "\n\n" + data);

        } catch (IOException e) {
            show("Card lost. Hold it still and try again.");
        } finally {
            try { isoDep.close(); } catch (IOException ignored) { }
        }
    }

    // ---------- APDU helpers ----------

    private byte[] transceive(IsoDep isoDep, byte[] command) throws IOException {
        byte[] response = isoDep.transceive(command);
        if (response.length < 2) return null;
        int sw1 = response[response.length - 2] & 0xFF;
        int sw2 = response[response.length - 1] & 0xFF;
        if (sw1 != 0x90 || sw2 != 0x00) return null;
        byte[] data = new byte[response.length - 2];
        System.arraycopy(response, 0, data, 0, data.length);
        return data;
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

    private void vibrate() {
        Vibrator vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        if (vibrator != null) {
            vibrator.vibrate(150);
        }
    }

    private void copy(String text) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("card data", text));
        }
    }

    private void show(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                resultText.setText(message);
                Toast.makeText(ReaderActivity.this, message, Toast.LENGTH_LONG).show();
            }
        });
    }
}
