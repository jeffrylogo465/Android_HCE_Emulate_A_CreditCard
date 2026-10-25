package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class CaptureActivity extends Activity {

    private SharedPreferences prefs;
    private TextView txtInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_capture);
        prefs = getSharedPreferences("hce_card", MODE_PRIVATE);
        txtInfo = (TextView) findViewById(R.id.txtCapture);

        findViewById(R.id.btnCapBack).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { finish(); }
        });

        findViewById(R.id.btnCapCopy).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("capture", build()));
                Toast.makeText(CaptureActivity.this, "Copied", Toast.LENGTH_SHORT).show();
            }
        });

        findViewById(R.id.btnCapClear).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                SharedPreferences.Editor e = prefs.edit();
                for (String k : prefs.getAll().keySet()) {
                    if (k.startsWith("cap_")) e.remove(k);
                }
                e.apply();
                Toast.makeText(CaptureActivity.this, "Cleared", Toast.LENGTH_SHORT).show();
                txtInfo.setText(build());
            }
        });

        txtInfo.setText(build());
    }

    private static String dash(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    private String build() {
        String ppse  = prefs.getString("cap_rawppse", "");
        String fci   = prefs.getString("cap_rawfci", "");
        String gpo   = prefs.getString("cap_rawgpo", "");
        String genac = prefs.getString("cap_rawgenac", "");

        int records = 0;
        StringBuilder recKeys = new StringBuilder();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_rec")) {
                records++;
                recKeys.append(k.substring(4)).append(' ');
            }
        }

        if (ppse.isEmpty() && fci.isEmpty() && gpo.isEmpty()) {
            return "No capture stored.\n\nOpen READ CARD and read a card.\n\nThe capture lives under its own cap_ keys, "
                    + "so editing a wallet card can never break it.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("PAN: ").append(dash(prefs.getString("cap_pan", ""))).append('\n');
        sb.append("EXPIRY: ").append(dash(prefs.getString("cap_expiry", ""))).append('\n');
        sb.append("SERVICE CODE: ").append(dash(prefs.getString("cap_service", ""))).append('\n');
        sb.append("TRACK 2: ").append(dash(prefs.getString("cap_track2", ""))).append('\n');
        sb.append("DISCRETIONARY: ").append(dash(prefs.getString("cap_discretionary", ""))).append('\n');
        sb.append("AID: ").append(dash(prefs.getString("cap_aid", ""))).append('\n');
        sb.append("RECORDS STORED: ").append(records).append('\n');
        if (recKeys.length() > 0) sb.append("RECORD KEYS: ").append(recKeys).append('\n');
        sb.append("\n");
        sb.append("PPSE (").append(ppse.length() / 2).append(" bytes):\n").append(ppse).append("\n\n");
        sb.append("FCI (").append(fci.length() / 2).append(" bytes):\n").append(fci).append("\n\n");
        sb.append("GPO (").append(gpo.length() / 2).append(" bytes):\n").append(gpo).append("\n\n");
        sb.append("GENERATE AC (").append(genac.length() / 2).append(" bytes):\n").append(genac).append('\n');
        return sb.toString();
    }
}
