package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
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

    public static final String EXTRA_PAN = "extra_pan";
    public static final String EXTRA_EXPIRY = "extra_expiry";
    public static final String EXTRA_SERVICE = "extra_service";
    public static final String EXTRA_DISC = "extra_disc";

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

    private String lastPan = "";
    private String lastExpiry = "";
    private String lastService = "";
    private String lastDisc = "";
    private String lastTrack2 = "";
    private String lastAid = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reader);

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

        btnCopyReader.setOnClickListener(new View.OnClickListener()
