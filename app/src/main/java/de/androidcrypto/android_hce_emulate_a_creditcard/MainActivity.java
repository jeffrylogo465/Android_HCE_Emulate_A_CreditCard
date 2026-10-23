package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

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
            e.setText(prefs.getString(KEYS[i], ""));
            root.addView(e);
            fields[i] = e;
        }

        Button save = new Button(this);
        save.setText("SAVE CARD");
        save.setOnClickListener(v -> {
            SharedPreferences.Editor ed = prefs.edit();
            for (int i = 0; i < KEYS.length; i++) {
                ed.putString(KEYS[i], fields[i].getText().toString().trim());
            }
            ed.apply();
        });
        root.addView(save);

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);
    }
}
