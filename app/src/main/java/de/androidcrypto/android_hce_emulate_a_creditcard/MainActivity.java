package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.PagerSnapHelper;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String PREF = "hce_card";
    private static final int MAX_CARDS = 12;
    private static final int REQ_CLONE = 4711;

    private static final String HINT =
            "Long-press AID to pick it - long-press TRACK 2 to preview";

    /** Brand -> AID. Stops anyone having to remember one, and stops the
     *  "empty AID silently becomes Visa" trap. */
    private static final String[][] AID_PRESETS = {
            {"Discover / Diners",      "A0000001523010"},
            {"Discover (legacy RID)",  "A0000000152001"},
            {"Mastercard",             "A0000000041010"},
            {"Maestro",                "A0000000043060"},
            {"Visa",                   "A0000000031010"},
            {"Visa Electron",          "A0000000032010"},
            {"American Express",       "A00000002501"},
            {"JCB",                    "A0000000651010"},
            {"UnionPay",               "A000000333010101"},
            {"Interac",                "A0000002771010"},
            {"Eftpos",                 "A00000038410"},
            {"Girocard",               "A0000003591010"},
    };

    private SharedPreferences prefs;
    private final List<CardAdapter.CardModel> cards = new ArrayList<>();
    private CardAdapter adapter;
    private RecyclerView pager;
    private LinearLayoutManager layoutManager;
    private PagerSnapHelper snapHelper;
    private TextView txtCount, txtStatus;

    private EditText etLabel, etPan, etExpiry, etService, etDiscretionary, etTrack2,
            etAid, etAip, etAfl, etCid, etAtc, etArqc, etIad, etMkac, etMsd;

    private int current = 0;
    private int cloneSource = 0;
    private boolean binding = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            String s = android.util.Log.getStackTraceString(e);
            try {
                android.content.ClipboardManager cm = (android.content.ClipboardManager)
                        getSystemService(CLIPBOARD_SERVICE);
                cm.setPrimaryClip(android.content.ClipData.newPlainText("crash", s));
            } catch (Exception ignored) { }
            try { Thread.sleep(400); } catch (Exception ignored) { }
            android.os.Process.killProcess(android.os.Process.myPid());
        });

        setContentView(R.layout.activity_main);

        if (getSupportActionBar() != null) getSupportActionBar().hide();

        prefs = getSharedPreferences(PREF, MODE_PRIVATE);

        pager = findViewById(R.id.pager);
        txtCount = findViewById(R.id.txtCount);
        txtStatus = findViewById(R.id.txtStatus);

        etLabel = findViewById(R.id.etLabel);
        etPan = findViewById(R.id.etPan);
        etExpiry = findViewById(R.id.etExpiry);
        etService = findViewById(R.id.etService);
        etDiscretionary = findViewById(R.id.etDiscretionary);
        etTrack2 = findViewById(R.id.etTrack2);
        etAid = findViewById(R.id.etAid);
        etAip = findViewById(R.id.etAip);
        etAfl = findViewById(R.id.etAfl);
        etCid = findViewById(R.id.etCid);
        etAtc = findViewById(R.id.etAtc);
        etArqc = findViewById(R.id.etArqc);
        etIad = findViewById(R.id.etIad);
        etMkac = findViewById(R.id.etMkac);
        etMsd = findViewById(R.id.etMsd);

        adapter = new CardAdapter();
        layoutManager = new LinearLayoutManager(this, RecyclerView.HORIZONTAL, false);
        snapHelper = new PagerSnapHelper();
        pager.setLayoutManager(layoutManager);
        pager.setAdapter(adapter);
        snapHelper.attachToRecyclerView(pager);

        loadAll();
        bindCard(Math.min(Math.max(prefs.getInt("selected", 0), 0), cards.size() - 1));
        pager.post(this::applyTransforms);

        pager.addOnScrollListener(new RecyclerView.OnScrollListener() {
            @Override
            public void onScrolled(@NonNull RecyclerView rv, int dx, int dy) {
                applyTransforms();
            }

            @Override
            public void onScrollStateChanged(@NonNull RecyclerView rv, int state) {
                if (state != RecyclerView.SCROLL_STATE_IDLE) return;
                View v = snapHelper.findSnapView(layoutManager);
                if (v == null) return;
                int pos = layoutManager.getPosition(v);
                if (pos >= 0 && pos != current) {
                    collect();
                    current = pos;
                    bindCard(pos);
                    prefs.edit().putInt("selected", pos).apply();
                }
            }
        });

        findViewById(R.id.btnSave).setOnClickListener(v -> onSave());
        findViewById(R.id.btnSave).setOnLongClickListener(v -> { showPreview(); return true; });
        findViewById(R.id.btnAdd).setOnClickListener(v -> onAdd());
        findViewById(R.id.btnClone).setOnClickListener(v -> startReader());
        findViewById(R.id.btnAdd).setOnLongClickListener(v -> {
            startReader();
            return true;
        });

        // long-press helpers - no layout changes needed
        etAid.setOnLongClickListener(v -> { showAidPicker(); return true; });
        etTrack2.setOnLongClickListener(v -> { showPreview(); return true; });

        TextWatcher watcher = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            public void onTextChanged(CharSequence s, int a, int b, int c) { }
            public void afterTextChanged(Editable s) {
                if (!binding) {
                    collect();
                    adapter.notifyItemChanged(current);
                }
            }
        };
        EditText[] fields = { etLabel, etPan, etExpiry, etService, etDiscretionary, etTrack2,
                etAid, etAip, etAfl, etCid, etAtc, etArqc, etIad, etMkac, etMsd };
        for (EditText f : fields) f.addTextChangedListener(watcher);
    }

    private void applyTransforms() {
        int centre = pager.getWidth() / 2;
        if (centre == 0) return;
        for (int i = 0; i < pager.getChildCount(); i++) {
            View child = pager.getChildAt(i);
            float mid = (child.getLeft() + child.getRight()) / 2f;
            float dist = Math.min(Math.abs(mid - centre) / (float) centre, 1f);
            child.setScaleY(1f - dist * 0.12f);
            child.setAlpha(0.55f + (1f - dist) * 0.45f);
        }
    }

    // ---------- storage ----------

    private static String key(int i, String name) {
        return "card" + i + "_" + name;
    }

    private static String t(EditText e) {
        return e.getText().toString().trim();
    }

    private static String digits(String s) {
        return s.replaceAll("[^0-9]", "");
    }

    private void loadAll() {
        cards.clear();
        int n = Math.min(prefs.getInt("card_count", 0), MAX_CARDS);
        for (int i = 0; i < n; i++) {
            CardAdapter.CardModel c = new CardAdapter.CardModel();
            c.label = prefs.getString(key(i, "label"), "");
            c.pan = prefs.getString(key(i, "pan"), "");
            c.expiry = prefs.getString(key(i, "expiry"), "");
            c.aid = prefs.getString(key(i, "aid"), "");
            c.msd = prefs.getInt(key(i, "msd"), 1);
            cards.add(c);
        }
        if (cards.isEmpty()) cards.add(new CardAdapter.CardModel());
        adapter.setCards(cards);
        updateCount();
    }

    private void collect() {
        int i = current;
        SharedPreferences.Editor e = prefs.edit();
        e.putString(key(i, "label"), t(etLabel));
        e.putString(key(i, "pan"), digits(t(etPan)));
        e.putString(key(i, "expiry"), t(etExpiry));
        e.putString(key(i, "service"), t(etService));
        e.putString(key(i, "discretionary"), t(etDiscretionary).toUpperCase());
        // normalise on the way in - '=' is not hex and would be stripped later
        e.putString(key(i, "track2"), normaliseTrack2(t(etTrack2)));
        e.putString(key(i, "aid"), t(etAid).toUpperCase());
        e.putString(key(i, "aip"), t(etAip).toUpperCase());
        e.putString(key(i, "afl"), t(etAfl).toUpperCase());
        e.putString(key(i, "cid"), t(etCid).toUpperCase());
        e.putString(key(i, "atc"), t(etAtc).toUpperCase());
        e.putString(key(i, "arqc"), t(etArqc).toUpperCase());
        e.putString(key(i, "iad"), t(etIad).toUpperCase());
        e.putString(key(i, "mkac"), t(etMkac).toUpperCase());
        e.putInt(key(i, "msd"), "0".equals(t(etMsd)) ? 0 : 1);
        e.putInt("card_count", cards.size());
        e.putInt("selected", i);
        e.apply();

        if (i < cards.size()) {
            CardAdapter.CardModel c = cards.get(i);
            c.label = t(etLabel);
            c.pan = t(etPan);
            c.expiry = t(etExpiry);
            c.aid = t(etAid);
            c.msd = "0".equals(t(etMsd)) ? 0 : 1;
        }
    }

    private void bindCard(int i) {
        binding = true;
        current = i;
        etLabel.setText(prefs.getString(key(i, "label"), ""));
        etPan.setText(prefs.getString(key(i, "pan"), ""));
        etExpiry.setText(prefs.getString(key(i, "expiry"), ""));
        etService.setText(prefs.getString(key(i, "service"), "201"));
        etDiscretionary.setText(prefs.getString(key(i, "discretionary"), ""));
        etTrack2.setText(prefs.getString(key(i, "track2"), ""));
        etAid.setText(prefs.getString(key(i, "aid"), ""));
        etAip.setText(prefs.getString(key(i, "aip"), "1880"));
        etAfl.setText(prefs.getString(key(i, "afl"), "08010100"));
        etCid.setText(prefs.getString(key(i, "cid"), "80"));
        etAtc.setText(prefs.getString(key(i, "atc"), "001B"));
        etArqc.setText(prefs.getString(key(i, "arqc"), ""));
        etIad.setText(prefs.getString(key(i, "iad"), ""));
        etMkac.setText(prefs.getString(key(i, "mkac"), ""));
        etMsd.setText(String.valueOf(prefs.getInt(key(i, "msd"), 1)));
        binding = false;
        updateCount();
        txtStatus.setText("");
    }

    private void updateCount() {
        txtCount.setText(cards.size() == 1 ? "1 card" : cards.size() + " cards");
    }

    // ---------- AID presets ----------

    private void showAidPicker() {
        String[] labels = new String[AID_PRESETS.length];
        for (int i = 0; i < AID_PRESETS.length; i++) {
            labels[i] = AID_PRESETS[i][0] + "  (" + AID_PRESETS[i][1] + ")";
        }
        new AlertDialog.Builder(this)
                .setTitle("Which brand is this card?")
                .setItems(labels, (d, which) -> {
                    etAid.setText(AID_PRESETS[which][1]);
                    collect();
                    txtStatus.setText("AID set to " + AID_PRESETS[which][0]);
                    Toast.makeText(this, AID_PRESETS[which][0] + " AID set", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // ---------- preview ----------

    /** Everything the terminal will actually receive, plus the traps we keep
     *  falling into. Long-press TRACK 2 or SAVE to see it. */
    private String previewText() {
        String pan = digits(t(etPan));
        String exp = digits(t(etExpiry));
        String sc = digits(t(etService));
        String disc = t(etDiscretionary).toUpperCase();
        String aid = t(etAid).toUpperCase();
        String msd = t(etMsd).isEmpty() ? "1" : t(etMsd);

        String track2 = normaliseTrack2(t(etTrack2));
        if (track2.isEmpty() && !pan.isEmpty()) {
            track2 = pan + "D" + exp + sc + disc;
        }

        StringBuilder sb = new StringBuilder();

        sb.append("AID  (4F)  : ")
                .append(aid.isEmpty() ? "(EMPTY - PPSE falls back to VISA!)" : aid).append('\n');
        sb.append("AIP  (82)  : ")
                .append(t(etAip).isEmpty() ? "1880" : t(etAip).toUpperCase()).append('\n');
        sb.append("MSD        : ").append("0".equals(msd)
                ? "0  EMV mode - ARQC gets judged" : "1  magstripe - no crypto").append('\n');
        sb.append('\n');

        sb.append("5A  PAN    : ")
                .append(pan.isEmpty() ? "4111111111111111  <-- DEFAULT, fill the PAN" : pan)
                .append('\n');
        sb.append("5F24 expiry: ")
                .append(exp.isEmpty() ? "3112  <-- DEFAULT" : exp).append("00").append('\n');
        sb.append("57  track2 : ")
                .append(track2.isEmpty() ? "(empty)" : hexOf(track2)).append('\n');

        // ---- traps ----
        String trackPan = track2.contains("D")
                ? track2.substring(0, track2.indexOf('D')) : track2;

        if (!pan.isEmpty() && !trackPan.isEmpty() && !trackPan.equals(pan)) {
            sb.append('\n').append("!! PAN and TRACK 2 are DIFFERENT cards\n");
            sb.append("   PAN    : ").append(pan).append('\n');
            sb.append("   track 2: ").append(trackPan).append('\n');
        }
        if (aid.isEmpty()) {
            sb.append('\n').append("!! AID empty - terminal will pick Visa\n");
        }
        if (!"0".equals(msd) && !track2.isEmpty()) {
            sb.append('\n').append("note: MSD=0 means EMV mode, so the ARQC matters\n");
        }
        if (track2.length() % 2 != 0) {
            sb.append('\n').append("track 2 is odd length - gets an F pad (normal)\n");
        }
        if (pan.isEmpty() && track2.isEmpty()) {
            sb.append('\n').append("nothing filled in yet\n");
        }
        return sb.toString();
    }

    private void showPreview() {
        new AlertDialog.Builder(this)
                .setTitle("What the terminal will see")
                .setMessage(previewText())
                .setPositiveButton("Close", null)
                .show();
    }

    private static String hexOf(String s) {
        String h = s.toUpperCase().replaceAll("[^0-9A-F]", "");
        if (h.length() % 2 != 0) h = h + "F";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length(); i += 2) {
            if (i > 0) sb.append(' ');
            sb.append(h, i, i + 2);
        }
        return sb.toString();
    }

    // ---------- actions ----------

    private void startReader() {
        collect();
        cloneSource = current;
        startActivityForResult(new Intent(this, ReaderActivity.class), REQ_CLONE);
    }

    private void onSave() {
        String pan = digits(t(etPan));
        if (pan.length() < 12 || pan.length() > 19 || !luhn(pan)) {
            Toast.makeText(this, "PAN must be 12-19 digits and pass Luhn", Toast.LENGTH_LONG).show();
            return;
        }
        if (t(etExpiry).length() != 4) {
            Toast.makeText(this, "Expiry must be YYMM, e.g. 2803", Toast.LENGTH_LONG).show();
            return;
        }
        if (t(etService).length() != 3) {
            Toast.makeText(this, "Service code must be 3 digits", Toast.LENGTH_LONG).show();
            return;
        }
        etPan.setText(pan);
        collect();
        adapter.notifyItemChanged(current);

        String track2 = normaliseTrack2(t(etTrack2));
        String trackPan = track2.contains("D")
                ? track2.substring(0, track2.indexOf('D')) : track2;
        if (!trackPan.isEmpty() && !trackPan.equals(pan)) {
            txtStatus.setText("Saved - but PAN and TRACK 2 are different cards");
            Toast.makeText(this, "PAN and TRACK 2 disagree - long-press SAVE", Toast.LENGTH_LONG).show();
            return;
        }
        if (t(etAid).isEmpty()) {
            txtStatus.setText("Saved - but AID is empty, terminal will pick Visa");
            Toast.makeText(this, "AID is empty - long-press the AID field", Toast.LENGTH_LONG).show();
            return;
        }

        txtStatus.setText("Saved card " + (current + 1) + " of " + cards.size());
        Toast.makeText(this, "Card saved", Toast.LENGTH_SHORT).show();
    }

    private void onAdd() {
        collect();
        if (cards.size() >= MAX_CARDS) {
            Toast.makeText(this, "Max " + MAX_CARDS + " cards", Toast.LENGTH_SHORT).show();
            return;
        }
        cards.add(new CardAdapter.CardModel());
        prefs.edit().putInt("card_count", cards.size()).apply();
        adapter.setCards(cards);
        current = cards.size() - 1;
        pager.smoothScrollToPosition(current);
        bindCard(current);
        prefs.edit().putInt("selected", current).apply();
    }

    private static boolean luhn(String s) {
        int sum = 0;
        boolean dbl = false;
        for (int i = s.length() - 1; i >= 0; i--) {
            int d = s.charAt(i) - '0';
            if (dbl) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    @Override
    protected void onPause() {
        super.onPause();
        collect();
    }

    @Override
    protected void onResume() {
        super.onResume();
        String v = prefs.getString("lastverdict", "");
        txtStatus.setText(v.isEmpty() ? HINT : v);
    }

    // ---------- clone from reader ----------

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_CLONE || resultCode != RESULT_OK || data == null) return;

        String pan = digits(nz(data.getStringExtra(ReaderActivity.EXTRA_PAN)));
        String expiry = digits(nz(data.getStringExtra(ReaderActivity.EXTRA_EXPIRY)));
        String service = digits(nz(data.getStringExtra(ReaderActivity.EXTRA_SERVICE)));
        String disc = nz(data.getStringExtra(ReaderActivity.EXTRA_DISC));
        String aid = nz(data.getStringExtra(ReaderActivity.EXTRA_AID)).toUpperCase();
        String track2 = normaliseTrack2(data.getStringExtra(ReaderActivity.EXTRA_TRACK2));
        String psn = digits(nz(data.getStringExtra(ReaderActivity.EXTRA_PSN)));
        String iad = nz(data.getStringExtra(ReaderActivity.EXTRA_IAD)).toUpperCase();
        String atc = nz(data.getStringExtra(ReaderActivity.EXTRA_ATC)).toUpperCase();
        String aip = nz(data.getStringExtra(ReaderActivity.EXTRA_AIP)).toUpperCase();

        if (expiry.length() > 4) expiry = expiry.substring(0, 4);
        if (psn.length() > 2) psn = psn.substring(0, 2);

        if (pan.isEmpty() && !track2.isEmpty()) {
            int d = track2.indexOf('D');
            pan = digits(d > 0 ? track2.substring(0, d) : track2);
        }
        if (track2.isEmpty() && !pan.isEmpty()) {
            track2 = pan + "D" + expiry + service + disc;
        }
        if (pan.isEmpty() && track2.isEmpty()) {
            Toast.makeText(this, "Nothing read from the card", Toast.LENGTH_SHORT).show();
            return;
        }
        if (expiry.isEmpty() && !track2.isEmpty()) {
            int d = track2.indexOf('D');
            if (d >= 0 && track2.length() >= d + 5) expiry = track2.substring(d + 1, d + 5);
        }
        if (service.length() != 3) {
            int d = track2.indexOf('D');
            if (d >= 0 && track2.length() >= d + 8) service = track2.substring(d + 5, d + 8);
        }
        if (service.length() != 3) service = "201";

        boolean reuse = t(etPan).isEmpty() && t(etTrack2).isEmpty();
        if (!reuse) {
            if (cards.size() >= MAX_CARDS) {
                Toast.makeText(this, "Max " + MAX_CARDS + " cards", Toast.LENGTH_SHORT).show();
                return;
            }
            collect();
            cards.add(new CardAdapter.CardModel());
            prefs.edit().putInt("card_count", cards.size()).apply();
            adapter.setCards(cards);
            current = cards.size() - 1;
        }

        binding = true;
        etLabel.setText(pan.length() >= 4 ? "CLONE " + pan.substring(pan.length() - 4) : "CLONE");
        etPan.setText(pan);
        etExpiry.setText(expiry);
        etService.setText(service);
        etTrack2.setText(track2);
        etAid.setText(aid);
        etMsd.setText("1");
        etDiscretionary.setText(track2.isEmpty() ? disc : "");
        if (!iad.isEmpty()) etIad.setText(iad);
        if (!aip.isEmpty()) etAip.setText(aip);
        if (!atc.isEmpty()) etAtc.setText(nextAtc(atc));
        binding = false;

        collect();
        prefs.edit().putString(key(current, "psn"), psn.isEmpty() ? "00" : psn).apply();
        copyStagingToCard(current);

        adapter.notifyItemChanged(current);
        pager.smoothScrollToPosition(current);
        prefs.edit().putInt("selected", current).apply();
        txtStatus.setText("Cloned - check it, then SAVE");
        Toast.makeText(this, "Card cloned - review, then hit SAVE", Toast.LENGTH_LONG).show();
    }

    /** Start the clone's ATC just above the value the real card last used. */
    private static String nextAtc(String hexAtc) {
        try {
            int v = Integer.parseInt(hexAtc.replaceAll("[^0-9A-Fa-f]", ""), 16);
            return String.format("%04X", (v + 1) & 0xFFFF);
        } catch (Exception e) {
            return "001B";
        }
    }

    /**
     * The reader writes its capture into a staging area under "cap_". Move it
     * onto the wallet card that was just written, so two cloned cards cannot
     * overwrite each other and the emulator always MACs the right PAN.
     */
    private void copyStagingToCard(int index) {
        SharedPreferences.Editor e = prefs.edit();
        String dst = key(index, "cap_");
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_")) {
                e.putString(dst + k.substring(4), prefs.getString(k, ""));
            }
        }
        e.apply();
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }

    private static String normaliseTrack2(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toUpperCase().replace('=', 'D');
        while (s.endsWith("F")) s = s.substring(0, s.length() - 1);
        return s;
    }
}
