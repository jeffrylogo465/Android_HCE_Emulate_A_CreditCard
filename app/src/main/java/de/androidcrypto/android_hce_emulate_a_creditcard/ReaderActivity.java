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
import android.os.Handler;
import android.os.Looper;
import android.os.Vibrator;
import android.view.View;
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

    private String rPan = "";
    private String rExpiry = "";
    private String rService = "";
    private String rDisc = "";
    private String rTrack2 = "";
    private String rAid = "";

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
            btnUseCard.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    useCard();
                }
            });
        }
        if (btnCopyReader != null) {
            btnCopyReader.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    copyAll();
                }
            });
        }
        if (btnCancelReader != null) {
            btnCancelReader.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    finish();
                }
            });
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
        super.onPause
