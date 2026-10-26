package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;

/**
 * Resolves a PAN to its issuer and a toll-free number, then places the call
 * so the issuer's IVR can be used as a liveness check without tapping.
 *
 * Issuer numbers verified October 2026. Matching is longest-prefix-first, so
 * if a BIN turns out to belong to a different issuer, add a longer entry for
 * it and it wins automatically.
 */
public final class BankDirectory {

    private BankDirectory() { }

    private static final int REQ_CALL = 4711;

    /** prefix, bank, toll-free digits, product note. Longest prefix wins. */
    private static final String[][] BINS = {
            {"372653", "American Express", "18005284800",
                    "Amex credit. Amex is its own issuer, so this line reaches them directly."},
            {"371243", "American Express", "18005284800",
                    "Amex credit. Amex is its own issuer, so this line reaches them directly."},
            {"528725", "Citadel Federal Credit Union", "18006660191",
                    "Debit Mastercard Enhanced. Ask for the balance option - that is your readback."},
            {"546213", "SchoolsFirst Federal Credit Union", "18004628328",
                    "Debit Mastercard Enhanced. Ask for the balance option - that is your readback."},
            {"546683", "Sutton Bank", "18004223641",
                    "Mastercard Prepaid, Workplace B2B. Program line is on the card back."},
            {"552433", "Bank of America", "18007329194",
                    "World Mastercard credit."},
    };

    /** Fallback by network when the BIN is not in the table above. */
    private static final String[][] NETWORKS = {
            {"34", "American Express", "18005284800"},
            {"37", "American Express", "18005284800"},
            {"4", "Visa", "18008472911"},
            {"5", "Mastercard", "18006278372"},
            {"2", "Mastercard", "18006278372"},
            {"6011", "Discover", "18003472683"},
            {"65", "Discover", "18003472683"},
            {"62", "Discover", "18003472683"},
    };

    // ------------------------------------------------------------------ resolve

    private static String[] resolve(String pan) {
        String d = digits(pan);
        if (d.length() < 6) return null;
        String[] best = null;
        for (String[] row : BINS) {
            if (d.startsWith(row[0]) && (best == null || row[0].length() > best[0].length())) {
                best = row;
            }
        }
        if (best != null) return best;
        for (String[] row : NETWORKS) {
            if (d.startsWith(row[0])) return row;
        }
        return null;
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("\\D", "");
    }

    private static String pretty(String d) {
        if (d.length() == 11 && d.startsWith("1")) {
            return "1-" + d.substring(1, 4) + "-" + d.substring(4, 7) + "-" + d.substring(7);
        }
        return d;
    }

    /**
     * Standard Luhn. The rightmost digit is NEVER doubled, so the toggle must
     * start false and flip AFTER the digit has been added to the sum.
     */
    private static boolean luhn(String raw) {
        String d = digits(raw);
        if (d.length() < 12 || d.length() > 19) return false;
        int sum = 0;
        boolean doubleIt = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int c = d.charAt(i) - '0';
            if (doubleIt) {
                c *= 2;
                if (c > 9) c -= 9;
            }
            sum += c;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    // ------------------------------------------------------------------ entry points

    /** Reads the PAN off the host screen, so no view ids have to be guessed. */
    public static void showCallSheet(Activity host) {
        showCallSheet(host, scanForPan(host));
    }

    public static void showCallSheet(Activity host, String pan) {
        if (host == null || host.isFinishing()) return;

        final EditText panBox = new EditText(host);
        panBox.setInputType(InputType.TYPE_CLASS_NUMBER);
        panBox.setHint("Card number");
        if (pan != null && !pan.isEmpty()) panBox.setText(pan);
        panBox.setSelection(panBox.getText().length());

        final TextView verdict = new TextView(host);
        verdict.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        verdict.setPadding(0, dp(host, 10), 0, 0);

        final TextView number = new TextView(host);
        number.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        number.setTypeface(Typeface.MONOSPACE);
        number.setPadding(0, dp(host, 6), 0, dp(host, 4));

        final TextView hint = new TextView(host);
        hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        hint.setAlpha(0.7f);

        LinearLayout box = new LinearLayout(host);
        box.setOrientation(LinearLayout.VERTICAL);
        int p = dp(host, 20);
        box.setPadding(p, dp(host, 8), p, 0);
        box.addView(label(host, "Card number"));
        box.addView(panBox);
        box.addView(verdict);
        box.addView(number);
        box.addView(hint);

        final Button call = new Button(host);
        call.setText("Call the bank");
        final Button copy = new Button(host);
        copy.setText("Copy card number");
        final Button online = new Button(host);
        online.setText("Look up this BIN online");

        for (Button b : new Button[]{call, copy, online}) {
            b.setAllCaps(false);
            box.addView(b);
        }

        ScrollView scroller = new ScrollView(host);
        scroller.addView(box);

        final AlertDialog dlg = new AlertDialog.Builder(host)
                .setTitle("Call issuer")
                .setView(scroller)
                .setNegativeButton("Close", null)
                .create();

        final Runnable refresh = new Runnable() {
            @Override public void run() {
                String pan = digits(panBox.getText().toString());
                String[] hit = resolve(pan);
                if (pan.isEmpty()) {
                    verdict.setText("Type or paste a card number.");
                    number.setText("");
                    hint.setText("");
                    return;
                }
                if (hit == null) {
                    verdict.setText("BIN " + pan.substring(0, Math.min(6, pan.length()))
                            + " not in the table. No number on file.");
                    number.setText("");
                    hint.setText("Add it to BINS in BankDirectory.java once you know the issuer.");
                    return;
                }
                verdict.setText(hit[1] + (luhn(pan) ? "" : "   (Luhn fails)"));
                number.setText(pretty(hit[2]));
                hint.setText(hit[3] + "\n\n"
                        + "The IVR will ask for the card number, then usually the last 4 of SSN, "
                        + "the billing ZIP, or the card PIN. A balance readback or \"card is active\" "
                        + "means the account is open. \"Card was replaced\" or \"cancelled\" means dead.");
            }
        };

        panBox.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { refresh.run(); }
            @Override public void afterTextChanged(Editable s) { }
        });

        call.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                dial(host, resolve(panBox.getText().toString()), digits(panBox.getText().toString()));
            }
        });
        copy.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String pan = digits(panBox.getText().toString());
                if (pan.isEmpty()) return;
                ClipboardManager cm = (ClipboardManager) host.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("card number", pan));
                Toast.makeText(host, "Card number copied", Toast.LENGTH_SHORT).show();
            }
        });
        online.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String pan = digits(panBox.getText().toString());
                if (pan.length() < 6) return;
                try {
                    host.startActivity(new Intent(Intent.ACTION_VIEW,
                            Uri.parse("https://lookup.binlist.net/" + pan.substring(0, 6))));
                } catch (Exception e) {
                    Toast.makeText(host, "No browser", Toast.LENGTH_SHORT).show();
                }
            }
        });

        refresh.run();
        dlg.show();
    }

    // ------------------------------------------------------------------ dialing

    private static void dial(Activity host, String[] hit, String pan) {
        if (hit == null) {
            Toast.makeText(host, "No number on file for that BIN", Toast.LENGTH_SHORT).show();
            return;
        }
        String number = hit[2];
        String uri = "tel:" + number;
        if (pan != null && !pan.isEmpty()) uri += "%2C" + pan + "%23";

        if (Build.VERSION.SDK_INT >= 23
                && host.checkSelfPermission(Manifest.permission.CALL_PHONE)
                   != PackageManager.PERMISSION_GRANTED) {
            host.requestPermissions(new String[]{Manifest.permission.CALL_PHONE}, REQ_CALL);
        }

        try {
            host.startActivity(new Intent(Intent.ACTION_CALL, Uri.parse(uri)));
        } catch (Exception e) {
            try {
                host.startActivity(new Intent(Intent.ACTION_DIAL, Uri.parse(uri)));
            } catch (Exception e2) {
                Toast.makeText(host, "No dialer found", Toast.LENGTH_SHORT).show();
            }
        }
    }

    // ------------------------------------------------------------------ view helpers

    private static TextView label(Activity a, String text) {
        TextView t = new TextView(a);
        t.setText(text);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setAlpha(0.7f);
        return t;
    }

    private static int dp(Activity a, int v) {
        return (int) (v * a.getResources().getDisplayMetrics().density + 0.5f);
    }

    private static String scanForPan(Activity host) {
        ArrayList<String> found = new ArrayList<>();
        collect(host.getWindow().getDecorView(), found);
        String best = null;
        for (String s : found) {
            String d = digits(s);
            if (d.length() < 12 || d.length() > 19) continue;
            if (best == null) { best = d; continue; }
            boolean a = luhn(d), b = luhn(best);
            if (a && !b) { best = d; continue; }
            if (a == b && d.length() > best.length()) best = d;
        }
        return best;
    }

    private static void collect(View v, ArrayList<String> out) {
        String s = null;
        if (v instanceof EditText) {
            s = ((EditText) v).getText().toString().trim();
        } else if (v instanceof TextView) {
            s = ((TextView) v).getText().toString().trim();
        }
        if (s != null && !s.isEmpty()) {
            if (s.matches("\\d{12,19}")) {
                out.add(s);
            } else if (s.contains("=")) {
                String head = s.substring(0, s.indexOf('=')).trim();
                if (head.matches("\\d{12,19}")) out.add(head);
            }
        }
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) collect(g.getChildAt(i), out);
        }
    }
}
