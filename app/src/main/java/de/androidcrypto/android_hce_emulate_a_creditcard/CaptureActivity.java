package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Debug view of the stored capture for one card slot.
 *
 * CHANGED. This used to read BARE cap_* keys. But MainActivity.copyStagingToCard()
 * moves bare cap_* into card<N>_cap_* and then DELETES the bare ones - so after
 * any successful clone this screen said "No capture stored" forever.
 *
 * It also asked for six keys the reader never writes: cap_rawppse, cap_pan,
 * cap_expiry, cap_service, cap_track2, cap_discretionary. Those lines were
 * permanently "-". They are now read from the card slot, where collect()
 * actually stores them.
 *
 * FIX: EXTRA_CARD_INDEX is defined here. MainActivity's launch hook passes it,
 * and without the constant the build failed with "cannot find symbol". It is
 * also USED - the slot shown is the card you long-pressed, not whatever happens
 * to be selected.
 *
 * Bare keys are still tried as a fallback, so opening this mid-read works.
 */
public class CaptureActivity extends Activity {

    public static final String EXTRA_CARD_INDEX = "card_index";

    private SharedPreferences prefs;
    private TextView txtInfo;
    private int cardIndex = 0;
    private String slot = "card0_";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_capture);
        prefs = getSharedPreferences("hce_card", MODE_PRIVATE);
        txtInfo = (TextView) findViewById(R.id.txtCapture);

        resolveSlot();

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
                clear();
                Toast.makeText(CaptureActivity.this, "Cleared", Toast.LENGTH_SHORT).show();
                txtInfo.setText(build());
            }
        });

        txtInfo.setText(build());
    }

    @Override
    protected void onResume() {
        super.onResume();
        resolveSlot();
        if (txtInfo != null) txtInfo.setText(build());
    }

    /** The card we were launched for, else whatever is selected. */
    private void resolveSlot() {
        Intent in = getIntent();
        int idx = (in == null) ? -1 : in.getIntExtra(EXTRA_CARD_INDEX, -1);
        if (idx < 0) idx = prefs.getInt("selected", 0);
        if (idx < 0) idx = 0;
        cardIndex = idx;
        slot = "card" + idx + "_";
    }

    /** Card-slot value, falling back to the bare staging key. */
    private String get(String k) {
        String v = prefs.getString(slot + k, "");
        if (v == null || v.isEmpty()) v = prefs.getString(k, "");
        return v == null ? "" : v;
    }

    private void clear() {
        SharedPreferences.Editor e = prefs.edit();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(slot + "cap_") || k.startsWith("cap_")) e.remove(k);
        }
        e.apply();
    }

    private static String dash(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    private String build() {
        resolveSlot();

        String fci   = get("cap_rawfci");
        String gpo   = get("cap_rawgpo");
        String genac = get("cap_rawgenac");

        int records = 0;
        StringBuilder recKeys = new StringBuilder();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(slot + "cap_rec")) {
                records++;
                recKeys.append(k.substring((slot + "cap_").length())).append(' ');
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SLOT: ").append(slot)
                .append("   (card ").append(cardIndex + 1)
                .append(" of ").append(prefs.getInt("card_count", 0)).append(")").append('\n');
        sb.append('\n');

        sb.append("LABEL: ").append(dash(get("label"))).append('\n');
        sb.append("PAN: ").append(dash(get("pan"))).append('\n');
        sb.append("EXPIRY: ").append(dash(get("expiry"))).append('\n');
        sb.append("SERVICE CODE: ").append(dash(get("service"))).append('\n');
        sb.append("AID: ").append(dash(get("cap_aid"))).append('\n');
        sb.append("AIP (editor): ").append(dash(get("aip"))).append('\n');
        sb.append("MSD: ").append(dash(get("msd"))).append('\n');
        sb.append("CID: ").append(get("cid").isEmpty()
                ? "(empty - logic decides)" : get("cid") + "  FORCED").append('\n');
        sb.append("MK-AC set: ").append(get("mkac").isEmpty() ? "no" : "yes").append('\n');
        sb.append('\n');

        sb.append("CAPTURED RECORDS: ").append(records).append('\n');
        if (recKeys.length() > 0) sb.append("RECORD KEYS: ").append(recKeys).append('\n');
        sb.append("GPO CAPTURED: ").append(gpo.isEmpty() ? "NO" : "yes (" + gpo.length() / 2 + "B)").append('\n');
        sb.append("FCI CAPTURED: ").append(fci.isEmpty() ? "NO" : "yes (" + fci.length() / 2 + "B)").append('\n');
        sb.append("GEN AC CAPTURED: ").append(genac.isEmpty() ? "NO" : "yes").append('\n');
        sb.append('\n');

        if (fci.isEmpty() && gpo.isEmpty()) {
            sb.append("No capture in this slot.\n\n");
            sb.append("Open READ CARD and read a card - the capture lands in the slot\n");
            sb.append("that is selected in the wallet.\n");
            return sb.toString();
        }

        sb.append("FCI (").append(fci.length() / 2).append(" bytes):\n").append(fci).append("\n\n");
        sb.append("GPO (").append(gpo.length() / 2).append(" bytes):\n").append(gpo).append("\n\n");
        sb.append("GENERATE AC (").append(genac.length() / 2).append(" bytes):\n").append(genac).append('\n');
        return sb.toString();
    }
}
