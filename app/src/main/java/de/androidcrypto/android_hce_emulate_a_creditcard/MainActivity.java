package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final String[] KEYS = {
        "label", "pan", "expiry", "serviceCode", "disc", "track2", "aid",
        "aip", "afl", "cid", "atc", "arqc", "iad", "mkac", "msd"
    };
    private static final String[] HINTS = {
        "Label  (e.g. DISCOVER CREDIT)", "PAN  (digits only)", "Expiry YYMM  (e.g. 3109)",
        "Service code  (201)", "Discretionary  (track tail)",
        "Track 2 raw hex  (tag 57 - paste from real card, optional)", "AID",
        "AIP  (3800)", "AFL  (08010100)", "CID  (80)", "ATC  (001B)",
        "ARQC / 9F26", "IAD / 9F10",
        "Issuer master key MK-AC  (hex, 16 bytes, optional)", "MSD mode  (1 = MSD, 0 = EMV)"
    };

    private static final int IDX_MSD = 14;

    private EditText[] fields;
    private TextView cardLabel, cardPan, cardExp;

    private static boolean isHex(String s) {
        return !s.isEmpty() && s.matches("[0-9A-Fa-f]+") && s.length() % 2 == 0;
    }

    private static boolean mustBeHex(String key) {
        return key.equals("aid") || key.equals("aip") || key.equals("afl")
            || key.equals("cid") || key.equals("atc") || key.equals("arqc")
            || key.equals("iad") || key.equals("track2") || key.equals("mkac");
    }

    private static boolean luhnOk(String digits) {
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
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

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        int cp = (int) (18 * d);
        card.setPadding(cp, cp, cp, cp);
        GradientDrawable bg = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                new int[]{0xFF1A237E, 0xFF4A148C});
        bg.setCornerRadius(20 * d);
        card.setBackground(bg);

        cardLabel = new TextView(this);
        cardLabel.setTextColor(Color.WHITE);
        cardLabel.setTextSize(13);
        cardLabel.setLetterSpacing(0.12f);

        cardPan = new TextView(this);
        cardPan.setTextColor(Color.WHITE);
        cardPan.setTextSize(20);
        cardPan.setTypeface(Typeface.MONOSPACE);
        cardPan.setPadding(0, (int) (16 * d), 0, (int) (12 * d));

        cardExp = new TextView(this);
        cardExp.setTextColor(0xFFD0D0D0);
        cardExp.setTextSize(12);

        card.addView(cardLabel);
        card.addView(cardPan);
        card.addView(cardExp);

        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        cardLp.setMargins(0, (int) (14 * d), 0, (int) (18 * d));
        root.addView(card, cardLp);

        fields = new EditText[KEYS.length];
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
        if (fields[IDX_MSD].getText().toString().trim().isEmpty()) {
            fields[IDX_MSD].setText("1");
        }

        TextWatcher w = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b2, int c) {}
            public void onTextChanged(CharSequence s, int a, int b2, int c) { updateCard(); }
            public void afterTextChanged(Editable s) {}
        };
        fields[0].addTextChangedListener(w);
        fields[1].addTextChangedListener(w);
        fields[2].addTextChangedListener(w);
        updateCard();

        Button save = new Button(this);
        save.setText("SAVE CARD");
        save.setOnClickListener(v -> {

            String pan = fields[1].getText().toString().replaceAll("[^0-9]", "");
            if (!pan.isEmpty()) {
                if (pan.length() < 12 || pan.length() > 19) {
                    Toast.makeText(this, "PAN must be 12-19 digits", Toast.LENGTH_LONG).show();
                    return;
                }
                if (!luhnOk(pan)) {
                    Toast.makeText(this, "PAN fails Luhn check - recheck the digits", Toast.LENGTH_LONG).show();
                    return;
                }
                fields[1].setText(pan);
            }

            String exp = fields[2].getText().toString().replaceAll("[^0-9]", "");
            if (!exp.isEmpty() && exp.length() != 4) {
                Toast.makeText(this, "Expiry must be 4 digits, YYMM", Toast.LENGTH_LONG).show();
                return;
            }
            fields[2].setText(exp);

            String msd = fields[IDX_MSD].getText().toString().trim();
            if (!msd.equals("0") && !msd.equals("1")) {
                Toast.makeText(this, "MSD mode must be 0 or 1", Toast.LENGTH_LONG).show();
                return;
            }

            SharedPreferences.Editor ed = prefs.edit();
            for (int i = 0; i < KEYS.length; i++) {
                String val = fields[i].getText().toString().trim();
                if (mustBeHex(KEYS[i]) && !val.isEmpty() && !isHex(val)) {
                    Toast.makeText(this, KEYS[i] + " must be even-length hex", Toast.LENGTH_LONG).show();
                    return;
                }
                ed.putString(KEYS[i], val);
            }
            boolean ok = ed.commit();
            Toast.makeText(this, ok ? "Card saved" : "Save failed", Toast.LENGTH_SHORT).show();
        });

        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        outer.addView(sv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        outer.addView(save);
        setContentView(outer);
    }

    private void updateCard() {
        if (cardLabel == null) return;

        String lbl = fields[0].getText().toString().trim();
        cardLabel.setText(lbl.isEmpty() ? "CARD" : lbl.toUpperCase());

        String pan = fields[1].getText().toString().replaceAll("[^0-9]", "");
        cardPan.setText(groupPan(pan));

        String exp = fields[2].getText().toString().trim();
        if (exp.length() == 4) {
            cardExp.setText("VALID THRU " + exp.substring(2, 4) + "/" + exp.substring(0, 2));
        } else {
            cardExp.setText("VALID THRU --/--");
        }
    }

    private static String groupPan(String pan) {
        if (pan.isEmpty()) return "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pan.length(); i++) {
            if (i > 0 && i % 4 == 0) sb.append(' ');
            sb.append(pan.charAt(i));
        }
        return sb.toString();
    }
}
