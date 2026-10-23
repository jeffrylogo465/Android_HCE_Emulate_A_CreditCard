package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final String[] KEYS = {
        "label", "pan", "expiry", "serviceCode", "disc", "aid",
        "aip", "afl", "cid", "atc", "arqc", "iad"
    };
    private static final String[] HINTS = {
        "Label  (e.g. VISA CREDIT)", "PAN", "Expiry YYMM  (e.g. 3112)",
        "Service code  (201)", "Discretionary  (track tail)", "AID",
        "AIP  (1C00)", "AFL  (08010100)", "CID  (80)", "ATC  (001B)",
        "ARQC / 9F26", "IAD / 9F10"
    };

    /** True only for non-empty, even-length hex strings. */
    private static boolean isHex(String s) {
        return !s.isEmpty() && s.matches("[0-9A-Fa-f]+") && s.length() % 2 == 0;
    }

    /** Fields that must be valid hex for the HCE service to parse them. */
    private static boolean mustBeHex(String key) {
        return key.equals("aid") || key.equals("aip") || key.equals("afl")
            || key.equals("cid") || key.equals("atc") || key.equals("arqc")
            || key.equals("iad");
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        final SharedPreferences prefs = getSharedPreferences("card", MODE_PRIVATE);
        final float d = getResources().getDisplayMetrics().density;

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding((int) (16 * d), (int) (16 * d), (int) (16 * d), (int) (16 * d));

        TextView title = new TextView(this);
        title.setText("EMV / MSD Card Emulator");
        title.setTextSize(18);
        root.addView(title);

        final EditText[] fields = new EditText[KEYS.length];
        for (int i = 0; i < KEYS.length; i++) {
            TextView lbl = new TextView(this);
            lbl.setText(HINTS[i]);
            lbl.setPadding(0, (int) (8 * d), 0, 0);
            root.addView(lbl);

            EditText e = new EditText(this);
            e.setSingleLine(true);
            e.setText(prefs.getString(KEYS[i], ""));
            root.addView(e);
            fields[i] = e;
        }

        Button save = new Button(this);
        save.setText("SAVE CARD");
        save.setOnClickListener(v -> {
            SharedPreferences.Editor ed = prefs.edit();
            for (int i = 0; i < KEYS.length; i++) {
                String val = fields[i].getText().toString().trim();
                if (mustBeHex(KEYS[i]) && !val.isEmpty() && !isHex(val)) {
                    Toast.makeText(this, KEYS[i] + " must be even-length hex",
                            Toast.LENGTH_LONG).show();
                    return;
                }
                ed.putString(KEYS[i], val);
            }
            boolean ok = ed.commit();   // synchronous so we can report the result
            Toast.makeText(this, ok ? "Card saved" : "Save failed",
                    Toast.LENGTH_SHORT).show();
        });

        // Scrollable form on top, SAVE button pinned at the bottom.
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        outer.addView(sv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        outer.addView(save);
        setContentView(outer);
    }
}
