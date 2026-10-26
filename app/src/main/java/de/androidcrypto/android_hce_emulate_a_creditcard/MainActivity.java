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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String PREF = "hce_card";
    private static final int MAX_CARDS = 12;
    private static final int REQ_CLONE = 4711;

    private static final String HINT =
            "Paste a dump anywhere - it fills itself in. Long-press AID to pick it.";

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
            {"Eftpos",                 "A0000003841010"},
            {"Girocard",               "A0000003591010"},
    };

    /**
     * FIX: every <aid-filter> in apduservice.xml, mirrored here.
     *
     * Android matches AID filters by PREFIX, so startsWith() below reproduces
     * exactly what the platform will route. An AID the PPSE advertises but this
     * list does not cover is the nastiest failure in the whole app: the terminal
     * SELECTs, Android never delivers the APDU to the service, and you get NO log
     * line at all - indistinguishable from a dead reader.
     *
     * Keep in sync with apduservice.xml. Drift is silent.
     */
    private static final String[] ROUTABLE = {
            "325041592E5359532E4444463031",
            // Visa
            "A0000000031010", "A0000000031020", "A0000000032010",
            "A0000000032020", "A0000000038010",
            // Mastercard / Maestro / Cirrus
            "A0000000041010", "A0000000041000", "A0000000043060",
            "A0000000046000", "A0000000048002", "A0000000050001",
            // American Express
            "A00000002501", "A0000000250104", "A0000000250001",
            // Discover / Diners
            "A0000001523010", "A0000001524010", "A0000001521010",
            "A0000001522010", "A0000001522001", "A0000001522300",
            "A0000001522400", "A0000000152001", "A0000000152010",
            "A0000000152020", "A0000000152200", "A0000000152300",
            "A0000000152400", "A0000000010101",
            // JCB
            "A0000000651010", "A0000000650000",
            // UnionPay
            "A0000003330101", "A000000333010101", "A000000333010102",
            "A000000333010103",
            // Interac / Eftpos / Girocard / others
            "A0000002771010", "A0000003845010", "A0000003841010",
            "A00000038410", "F0010203040506",
            "A0000003591010", "A0000003591010028001", "A00000000386980701",
            "A0000000410100", "A0000000422035",
    };

    /** Lazy defaults and common test keys for the issuer-key hunt. The user's
     *  own list, typed into the key editor, is added on top of these. */
    private static final String[] SEED_KEYS = {
            "0123456789ABCDEF0123456789ABCDEF",
            "FEDCBA9876543210FEDCBA9876543210",
            "0123456789ABCDEFFEDCBA9876543210",
            "00000000000000000000000000000000",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566770011223344556677",
            "404142434445464748494A4B4C4D4E4F",
            "ABCDEF0123456789ABCDEF0123456789",
            "12345678901234561234567890123456",
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
    };

    private SharedPreferences prefs;
    private final List<CardAdapter.CardModel> cards = new ArrayList<>();
    private CardAdapter adapter;
    private RecyclerView pager;
    private LinearLayoutManager layoutManager;
    private PagerSnapHelper snapHelper;
    private TextView txtCount, txtStatus;

    private EditText etLabel, etName, etPan, etExpiry, etService, etDiscretionary,
            etTrack2, etAid, etAip, etAfl, etCid, etAtc, etArqc, etIad, etMkac,
            etMsd, etScript;

    // the two pages and the two nav items
    private View pageWallet, pageEdit;
    private TextView navWallet, navEdit;

    private int current = 0;
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
        etName = findViewById(R.id.etName);
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
        etScript = findViewById(R.id.etScript);

        // ---- pages ----
        pageWallet = findViewById(R.id.pageWallet);
        pageEdit   = findViewById(R.id.pageEdit);
        navWallet  = findViewById(R.id.navWallet);
        navEdit    = findViewById(R.id.navEdit);

        navWallet.setOnClickListener(v -> showPage(0));
        navEdit.setOnClickListener(v -> showPage(1));

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
        findViewById(R.id.btnAdd).setOnClickListener(v -> { onAdd(); showPage(1); });
        findViewById(R.id.btnClone).setOnClickListener(v -> startReader());
        findViewById(R.id.btnAdd).setOnLongClickListener(v -> {
            startReader();
            return true;
        });

        // long-press helpers - no layout changes needed
        etAid.setOnLongClickListener(v -> { showAidPicker(); return true; });
        etTrack2.setOnLongClickListener(v -> { showPreview(); return true; });
        etMkac.setOnLongClickListener(v -> { showKeyTools(); return true; });

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
        EditText[] fields = { etLabel, etName, etPan, etExpiry, etService, etDiscretionary,
                etTrack2, etAid, etAip, etAfl, etCid, etAtc, etArqc, etIad, etMkac,
                etMsd, etScript };
        for (EditText f : fields) f.addTextChangedListener(watcher);

        // paste a dump into either of these and the card fills itself in
        TextWatcher filler = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            public void onTextChanged(CharSequence s, int a, int b, int c) { }
            public void afterTextChanged(Editable s) {
                if (!binding) autoFill();
            }
        };
        etTrack2.addTextChangedListener(filler);
        etPan.addTextChangedListener(filler);

        showPage(0);
    }

    // ---------- pages ----------

    private void showPage(int page) {
        pageWallet.setVisibility(page == 0 ? View.VISIBLE : View.GONE);
        pageEdit.setVisibility(page == 1 ? View.VISIBLE : View.GONE);
        navWallet.setTextColor(page == 0 ? 0xFF14B8A6 : 0xFF4B5563);
        navEdit.setTextColor(page == 1 ? 0xFF14B8A6 : 0xFF4B5563);
        if (page == 0) hideKeyboard();
    }

    private void hideKeyboard() {
        View v = getCurrentFocus();
        if (v == null) return;
        android.view.inputmethod.InputMethodManager im =
                (android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        if (im != null) im.hideSoftInputFromWindow(v.getWindowToken(), 0);
        v.clearFocus();
    }

    /**
     * Paste "5287250556251985=310420113264855" into the track 2 field or the PAN
     * field and the rest of the card is filled in from it. The separator is the
     * only reliable split point - everything after it is read positionally,
     * which is how a real card lays it out: 4 expiry, 3 service code, rest
     * discretionary (that tail holds the CVC, so it is never truncated).
     */
    private void autoFill() {
        if (binding) return;

        // A track 1 paste carries the name between the two '^' marks. Track 2
        // has no name at all, which is why pasting one never fills it in.
        if (t(etName).isEmpty()) {
            String n = nameFromTrack1(t(etTrack2));
            if (n.isEmpty()) n = nameFromTrack1(t(etPan));
            if (!n.isEmpty()) {
                binding = true;
                etName.setText(n);
                binding = false;
                collect();
            }
        }

        String fromTrack = normaliseTrack2(t(etTrack2));
        String fromPan = normaliseTrack2(t(etPan));

        String src = null;
        if (fromTrack.indexOf('D') > 0) {
            src = fromTrack;
        } else if (fromPan.indexOf('D') > 0) {
            src = fromPan;
        } else {
            // the PAN field is inputType=number, so a pasted dump arrives with the
            // separator already stripped. Rebuild it from the BIN length instead.
            String p = digits(t(etPan));
            if (p.length() > 20) {
                int panLen = (p.startsWith("34") || p.startsWith("37")) ? 15 : 16;
                if (p.length() > panLen + 7) {
                    src = p.substring(0, panLen) + "D" + p.substring(panLen);
                }
            }
        }
        if (src == null) return;

        int sep = src.indexOf('D');
        if (sep < 12 || sep > 19) return;                 // not a usable PAN length

        String pan = src.substring(0, sep);
        if (!pan.matches("[0-9]+")) return;               // still being typed

        String rest = src.substring(sep + 1);
        if (rest.length() < 7) return;                    // need expiry + service

        String expiry = rest.substring(0, 4);
        String service = rest.substring(4, 7);
        String disc = rest.substring(7);
        if (!expiry.matches("[0-9]{4}")) return;
        if (!service.matches("[0-9]{3}")) return;

        binding = true;
        etTrack2.setText(src);
        etPan.setText(pan);
        etExpiry.setText(expiry);
        etService.setText(service);
        etDiscretionary.setText(disc);
        binding = false;

        collect();
        adapter.notifyItemChanged(current);
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

    /**
     * FIX: AID routability. Prefix match, mirroring how Android routes, against
     * the filters in apduservice.xml. An AID outside this list is advertised in
     * the PPSE but never delivered to the service - the terminal SELECTs into a
     * void and the tap dies with nothing in the log.
     */
    private static boolean routable(String aid) {
        if (aid == null || aid.isEmpty()) return false;
        for (String f : ROUTABLE) if (aid.startsWith(f)) return true;
        return false;
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
            c.msd = prefs.getInt(key(i, "msd"), 0);
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
        e.putString(key(i, "name"), t(etName).toUpperCase());
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
        // script keeps its own case - '#' comments read better in lower case
        e.putString(key(i, "script"), t(etScript));
        // FIX: was "0".equals(t(etMsd)) ? 0 : 1 - so a blank or a typo silently
        // meant magstripe. Parse it, and default to 0 (EMV) like the service now does.
        e.putInt(key(i, "msd"), t(etMsd).startsWith("1") ? 1 : 0);
        e.putInt("card_count", cards.size());
        e.putInt("selected", i);
        e.apply();

        if (i < cards.size()) {
            CardAdapter.CardModel c = cards.get(i);
            c.label = t(etLabel);
            c.pan = t(etPan);
            c.expiry = t(etExpiry);
            c.aid = t(etAid);
            // FIX: same coercion, same fix
            c.msd = t(etMsd).startsWith("1") ? 1 : 0;
        }
    }

    private void bindCard(int i) {
        binding = true;
        current = i;
        etLabel.setText(prefs.getString(key(i, "label"), ""));
        etName.setText(prefs.getString(key(i, "name"), ""));
        etPan.setText(prefs.getString(key(i, "pan"), ""));
        etExpiry.setText(prefs.getString(key(i, "expiry"), ""));
        etService.setText(prefs.getString(key(i, "service"), "201"));
        etDiscretionary.setText(prefs.getString(key(i, "discretionary"), ""));
        etTrack2.setText(prefs.getString(key(i, "track2"), ""));
        etAid.setText(prefs.getString(key(i, "aid"), ""));
        etAip.setText(prefs.getString(key(i, "aip"), "3080"));
        // FIX: default is now EMPTY, not "08010100". The service reads this field,
        // and an empty value means "derive the AFL from the records we hold".
        etAfl.setText(prefs.getString(key(i, "afl"), ""));
        etCid.setText(prefs.getString(key(i, "cid"), "80"));
        etAtc.setText(prefs.getString(key(i, "atc"), "001B"));
        etArqc.setText(prefs.getString(key(i, "arqc"), ""));
        etIad.setText(prefs.getString(key(i, "iad"), ""));
        etMkac.setText(prefs.getString(key(i, "mkac"), ""));
        // 0 = EMV. The right default for a hand-typed card, because EMV is the
        // only mode that can reach a cryptogram. A cloned card overrides this
        // from the capture, so a real magstripe card still lands on 1.
        etMsd.setText(String.valueOf(prefs.getInt(key(i, "msd"), 0)));
        etScript.setText(prefs.getString(key(i, "script"), ""));
        binding = false;
        updateCount();
        txtStatus.setText("");
        autoFill();
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
        String msd = t(etMsd).isEmpty() ? "0" : t(etMsd);

        String track2 = normaliseTrack2(t(etTrack2));
        if (track2.isEmpty() && !pan.isEmpty()) {
            track2 = pan + "D" + exp + sc + disc;
        }

        StringBuilder sb = new StringBuilder();

        sb.append("AID  (4F)  : ")
                .append(aid.isEmpty() ? "(EMPTY - PPSE falls back to VISA!)" : aid).append('\n');
        sb.append("AIP  (82)  : ")
                .append(t(etAip).isEmpty() ? "3080" : t(etAip).toUpperCase()).append('\n');
        sb.append("MSD        : ").append("0".equals(msd)
                ? "0  EMV mode - ARQC gets judged" : "1  magstripe - no crypto").append('\n');
        sb.append('\n');

        sb.append("5A  PAN    : ")
                .append(pan.isEmpty() ? "4111111111111111  <-- DEFAULT, fill the PAN" : pan)
                .append('\n');
        // the emulator pads YYMM to YYMM01 - show what actually goes on the wire
        String expOut = exp.isEmpty() ? "3112  <-- DEFAULT" : exp;
        if (exp.length() == 4) expOut = exp + "01";
        sb.append("5F24 expiry: ").append(expOut).append('\n');
        sb.append("5F20 name  : ")
                .append(t(etName).isEmpty() ? "(empty - slip shows no name)" : t(etName).toUpperCase())
                .append('\n');
        sb.append("57  track2 : ")
                .append(track2.isEmpty() ? "(empty)" : hexOf(track2)).append('\n');

        String script = t(etScript);
        int scriptLines = 0;
        for (String line : script.split("\\R")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            if (line.indexOf('=') > 0) scriptLines++;
        }
        sb.append("script     : ").append(scriptLines == 0
                ? "(none - service constant is used)" : scriptLines + " line(s) armed").append('\n');

        // ---- traps ----
        String trackPan = track2.contains("D")
                ? track2.substring(0, track2.indexOf('D')) : "";

        if (!pan.isEmpty() && !trackPan.isEmpty() && !trackPan.equals(pan)) {
            sb.append('\n').append("!! PAN and TRACK 2 are DIFFERENT cards\n");
            sb.append("   PAN    : ").append(pan).append('\n');
            sb.append("   track 2: ").append(trackPan).append('\n');
        }
        if (aid.isEmpty()) {
            sb.append('\n').append("!! AID empty - terminal will pick Visa\n");
        }
        // FIX: the silent-death trap. Advertised but not routable.
        if (!aid.isEmpty() && !routable(aid)) {
            sb.append('\n').append("!! AID has no <aid-filter> in apduservice.xml\n");
            sb.append("   Android will not route the SELECT - tap dies with NO log line\n");
            sb.append("   add: <aid-filter android:name=\"").append(aid).append("\" />\n");
        }
        // FIX: was !"0".equals(msd) - it fired on magstripe but talked about EMV
        if ("0".equals(msd)) {
            sb.append('\n').append("note: MSD=0 is EMV mode - terminal walks the AFL, ARQC matters\n");
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

    // ---------- issuer key search ----------

    private void showKeyTools() {
        new AlertDialog.Builder(this)
                .setTitle("Issuer master key")
                .setItems(new String[]{"Scan for the key", "Edit candidate list"}, (d, w) -> {
                    if (w == 0) scanForKey(); else editKeyList();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void editKeyList() {
        final EditText e = new EditText(this);
        e.setText(prefs.getString("keylist", ""));
        e.setHint("32 hex chars per key, one per line");
        new AlertDialog.Builder(this)
                .setTitle("Candidate keys")
                .setView(e)
                .setPositiveButton("Save", (d, w) ->
                        prefs.edit().putString("keylist", e.getText().toString().toUpperCase()).apply())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private List<String> candidateKeys() {
        List<String> out = new ArrayList<>();
        for (String k : SEED_KEYS) out.add(k);
        for (String k : prefs.getString("keylist", "").split("[^0-9A-Fa-f]+")) {
            String h = k.toUpperCase();
            if (h.length() == 32) out.add(h);
        }
        String pan = digits(t(etPan));
        if (pan.length() >= 8) {
            String b8 = pan.substring(0, 8);
            String b6 = pan.substring(0, 6);
            out.add((b8 + b8 + "0000000000000000").substring(0, 32));
            out.add((b8 + "000000000000000000000000").substring(0, 32));
            out.add((b6 + "00000000000000000000000000").substring(0, 32));
            StringBuilder asc = new StringBuilder();
            for (char c : b8.toCharArray()) asc.append(String.format("%02X", (int) c));
            out.add((asc + "00000000000000000000").substring(0, 32));
        }
        return out;
    }

    private void scanForKey() { scanForKey(true); }

    /**
     * Try every candidate key against the ARQC the real card produced, sweeping
     * the MAC input order and the diversification option too - a correct key
     * tests as wrong if either of those is wrong.
     */
    private void scanForKey(boolean announce) {
        String cmdHex = prefs.getString(key(current, "cap_genaccmd"), "");
        String rspHex = prefs.getString(key(current, "cap_rawgenac"), "");
        String pan = digits(t(etPan));
        String aipHex = t(etAip).toUpperCase();

        if (cmdHex.isEmpty() || rspHex.isEmpty()) {
            if (announce) {
                Toast.makeText(this, "No reference - read the physical card with READ CARD first",
                        Toast.LENGTH_LONG).show();
            }
            return;
        }
        if (pan.isEmpty() || aipHex.length() < 4) {
            if (announce) {
                Toast.makeText(this, "Need PAN and AIP set on the card", Toast.LENGTH_LONG).show();
            }
            return;
        }

        byte[] cmd = hexToBytes(cmdHex);
        byte[] rsp = hexToBytes(rspHex);
        if (cmd.length < 6) return;
        int lc = cmd[4] & 0xFF;
        if (5 + lc > cmd.length) return;

        final byte[] cdol = Arrays.copyOfRange(cmd, 5, 5 + lc);
        final byte[] arqcRef = tagOf(rsp, 0x9F26);
        final byte[] atcRef = tagOf(rsp, 0x9F36);
        if (arqcRef == null || atcRef == null) {
            if (announce) {
                Toast.makeText(this, "Reference ARQC/ATC missing from the capture",
                        Toast.LENGTH_LONG).show();
            }
            return;
        }
        final byte[] aip = hexToBytes(aipHex);
        final String atc = bytesToHex(atcRef);
        final String psn = prefs.getString(key(current, "psn"), "00");
        final List<String> keys = candidateKeys();

        txtStatus.setText("Scanning " + keys.size() + " keys x 4 variants...");

        new Thread(() -> {
            int tried = 0;
            for (String k : keys) {
                for (int variant = 0; variant < 4; variant++) {
                    tried++;
                    try {
                        byte[] macIn = ((variant & 2) != 0)
                                ? cat(aip, hexToBytes(atc), cdol)
                                : cat(cdol, aip, hexToBytes(atc));
                        byte[] ac = EmvCrypto.arqc(k, pan, psn, atc, macIn, variant & 1);
                        if (Arrays.equals(ac, arqcRef)) {
                            final String fk = k;
                            final int fv = variant;
                            runOnUiThread(() -> {
                                etMkac.setText(fk);
                                prefs.edit().putString(key(current, "keyvar"),
                                        String.valueOf(fv)).apply();
                                collect();
                                txtStatus.setText("KEY FOUND " + fk + "  (variant " + fv + ")");
                                Toast.makeText(this, "Issuer key found", Toast.LENGTH_LONG).show();
                            });
                            return;
                        }
                    } catch (Exception ignored) { }
                }
            }
            final int total = tried;
            runOnUiThread(() -> {
                txtStatus.setText("Read OK - no key matched (" + total
                        + " tries). Long-press MK-AC to add candidates.");
                if (announce) {
                    Toast.makeText(this, "No match - " + total + " tries", Toast.LENGTH_LONG).show();
                }
            });
        }).start();
    }

    // ---------- small helpers for the scan ----------

    private static byte[] cat(byte[]... arrs) {
        int n = 0;
        for (byte[] a : arrs) n += a.length;
        byte[] out = new byte[n];
        int p = 0;
        for (byte[] a : arrs) { System.arraycopy(a, 0, out, p, a.length); p += a.length; }
        return out;
    }

    private static byte[] hexToBytes(String h) {
        h = h.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        if (h.length() % 2 != 0) h = h + "F";
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    /** Recursive TLV search - first value found for a tag, at any depth. */
    private static byte[] tagOf(byte[] d, int want) {
        int i = 0;
        while (i < d.length) {
            int tag = d[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                if (i >= d.length) return null;
                tag = (tag << 8) | (d[i++] & 0xFF);
            }
            if (i >= d.length) return null;
            int len = d[i++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int k = 0; k < n && i < d.length; k++) len = (len << 8) | (d[i++] & 0xFF);
            }
            if (i + len > d.length) return null;
            if (tag == want) return Arrays.copyOfRange(d, i, i + len);
            if ((tag & 0x20) != 0) {
                byte[] inner = tagOf(Arrays.copyOfRange(d, i, i + len), want);
                if (inner != null) return inner;
            }
            i += len;
        }
        return null;
    }

    // ---------- actions ----------

    private void startReader() {
        collect();
        Intent i = new Intent(this, ReaderActivity.class);
        i.putExtra(ReaderActivity.EXTRA_CARD_INDEX, current);
        startActivityForResult(i, REQ_CLONE);
    }

    private void onSave() {
        syncFieldsFromTrack2();                   // SAVE puts everything in its place
        if (t(etLabel).isEmpty()) {
            String b = brandFromPan(digits(t(etPan)));
            if (!b.isEmpty()) etLabel.setText(b);
        }
        if (t(etAid).isEmpty()) {
            String a = aidFromPan(digits(t(etPan)));
            if (!a.isEmpty()) etAid.setText(a);
        }
        collect();

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
        if (track2.contains("D") && !trackPan.isEmpty() && !trackPan.equals(pan)) {
            txtStatus.setText("Saved - but PAN and TRACK 2 are different cards");
            Toast.makeText(this, "PAN and TRACK 2 disagree - long-press SAVE", Toast.LENGTH_LONG).show();
            return;
        }
        if (t(etAid).isEmpty()) {
            txtStatus.setText("Saved - but AID is empty, terminal will pick Visa");
            Toast.makeText(this, "AID is empty - long-press the AID field", Toast.LENGTH_LONG).show();
            return;
        }

        // FIX: the silent-death check. Everything above validates the DATA; this
        // validates whether the terminal can reach us at all.
        String aidNow = t(etAid).toUpperCase();
        if (!routable(aidNow)) {
            txtStatus.setText("Saved - AID " + aidNow + " is not in apduservice.xml, tap will die silently");
            Toast.makeText(this, "AID not routable - add an <aid-filter>", Toast.LENGTH_LONG).show();
            showPage(0);
            return;
        }

        txtStatus.setText("Saved card " + (current + 1) + " of " + cards.size());
        Toast.makeText(this, "Card saved", Toast.LENGTH_SHORT).show();
        showPage(0);                              // back to the wallet where the status lives
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
        etDiscretionary.setText(track2.isEmpty() ? disc : "");
        if (!iad.isEmpty()) etIad.setText(iad);
        if (!aip.isEmpty()) etAip.setText(aip);
        if (!atc.isEmpty()) etAtc.setText(nextAtc(atc));
        // FIX: leave the AFL empty on a clone so the service derives it from the
        // records that actually landed. A leftover "08010100" would advertise
        // SFI 1 record 1 only and silently ignore every captured record.
        etAfl.setText("");
        binding = false;

        collect();
        prefs.edit().putString(key(current, "psn"), psn.isEmpty() ? "00" : psn).apply();

        // Move the capture onto the card FIRST, so msdFromCapture can read it off
        // the card itself rather than depending on the staging area still being
        // there. Staging is burned by this call.
        copyStagingToCard(current);

        binding = true;
        etMsd.setText(String.valueOf(msdFromCapture(current)));
        binding = false;
        collect();

        adapter.notifyItemChanged(current);
        pager.smoothScrollToPosition(current);
        prefs.edit().putInt("selected", current).apply();

        int recs = recordCountOnCard();
        String st = recs == 0
                ? "Cloned - no records captured, terminal will get a synthetic one"
                : "Cloned " + recs + " records - check it, then SAVE";

        // The PAN has no name in it - the name only exists on the card, as 5F20
        // inside a record. Report which way it went, so a miss is never silent.
        if (t(etName).isEmpty()) {
            String h = holderFromCapture(current);
            if (!h.isEmpty()) {
                binding = true;
                etName.setText(h);
                binding = false;
                collect();
                st = st + " | name: " + h;
                Toast.makeText(this, "Name read off the card: " + h, Toast.LENGTH_LONG).show();
            } else {
                st = st + " | no 5F20 in those " + recs + " records";
                Toast.makeText(this, "No 5F20 name in the " + recs
                        + " captured records - type it", Toast.LENGTH_LONG).show();
            }
        }
        txtStatus.setText(st);

        Toast.makeText(this, "Card cloned - review, then hit SAVE", Toast.LENGTH_LONG).show();
        showPage(1);                              // straight into the editor to review

        // the reader just captured a real cryptogram - hunt for the issuer key
        if (!prefs.getString(key(current, "cap_genaccmd"), "").isEmpty()
                && !prefs.getString(key(current, "cap_rawgenac"), "").isEmpty()) {
            scanForKey(false);
        }
    }

    /**
     * 1 = magstripe framing, 0 = EMV framing. Read off the captured GPO.
     * Reads the card's own key, so it must be called after copyStagingToCard.
     */
    private int msdFromCapture(int index) {
        String gpo = prefs.getString(key(index, "cap_rawgpo"), "");
        if (gpo.isEmpty()) gpo = prefs.getString("cap_rawgpo", "");   // staging fallback
        if (gpo.length() < 2) return 1;
        try {
            return (Integer.parseInt(gpo.substring(0, 2), 16) == 0x80) ? 1 : 0;
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    /** How many records actually landed on the card we just wrote. */
    private int recordCountOnCard() {
        int n = 0;
        String p = key(current, "cap_rec");
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(p)) n++;
        }
        return n;
    }

    /**
     * Lift the cardholder name out of whatever the reader captured. 5F20 sits
     * inside a record, so scan every captured record for it and take the first
     * usable one. A card whose records carry no 5F20 returns nothing.
     */
    private String holderFromCapture(int index) {
        String prefix = key(index, "cap_rec");
        for (String k : prefs.getAll().keySet()) {
            if (!k.startsWith(prefix)) continue;
            String hex = prefs.getString(k, "");
            if (hex == null || hex.isEmpty()) continue;
            try {
                byte[] v = tagOf(hexToBytes(hex), 0x5F20);
                if (v == null || v.length < 2) continue;
                String n = new String(v, StandardCharsets.ISO_8859_1);
                n = n.toUpperCase().replaceAll("[^A-Z0-9 ./'-]", "").trim();
                if (n.length() >= 2) return n.length() > 26 ? n.substring(0, 26) : n;
            } catch (Exception ignored) { }
        }
        return "";
    }

    /**
     * Track 1 carries the name between the two '^' marks:
     *   B<PAN>^SURNAME/FIRSTNAME^<expiry><service><discretionary>
     * Track 2 has no name at all, which is why pasting one never fills this in.
     */
    private static String nameFromTrack1(String raw) {
        if (raw == null) return "";
        int a = raw.indexOf('^');
        if (a < 0) return "";
        int b = raw.indexOf('^', a + 1);
        if (b < 0) return "";
        String n = raw.substring(a + 1, b).toUpperCase()
                .replaceAll("[^A-Z0-9 ./'-]", "")
                .replaceAll("\\s+", " ")
                .trim();
        if (n.length() < 2) return "";
        return n.length() > 26 ? n.substring(0, 26) : n;
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
     *
     * Both ends are cleared. The destination, because cloning into the same slot
     * twice merges two captures - and since the emulator derives its AFL from
     * these keys, a leftover rec1_1 gets advertised and served, card A's data
     * answering for card B. The staging area, because otherwise a record this
     * read missed survives from the previous card and gets copied across too.
     */
    private void copyStagingToCard(int index) {
        SharedPreferences.Editor e = prefs.edit();
        String dst = key(index, "cap_");

        // 1. drop whatever the destination already had
        List<String> stale = new ArrayList<>();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(dst)) stale.add(k);
        }
        for (String k : stale) e.remove(k);

        // 2. staging -> destination
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_")) {
                e.putString(dst + k.substring(4), prefs.getString(k, ""));
            }
        }

        // 3. burn the staging area so the next clone starts from nothing
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_")) e.remove(k);
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

    /**
     * SAVE syncs the plain fields out of the track 2, so a pasted dump cannot
     * end up contradicting itself. The separator is the split point; everything
     * after it is positional, and the tail (which holds the CVC) is kept whole.
     */
    private void syncFieldsFromTrack2() {
        String track2 = normaliseTrack2(t(etTrack2));
        int d = track2.indexOf('D');
        if (d <= 0) return;

        String pan  = digits(track2.substring(0, d));
        String tail = track2.substring(d + 1);
        String exp  = tail.length() >= 4 ? tail.substring(0, 4) : "";
        String sc   = tail.length() >= 7 ? tail.substring(4, 7) : "";
        String disc = tail.length() > 7 ? tail.substring(7) : "";

        binding = true;
        if (!pan.isEmpty() && !pan.equals(digits(t(etPan)))) etPan.setText(pan);
        if (!exp.isEmpty() && !exp.equals(t(etExpiry))) etExpiry.setText(exp);
        if (!sc.isEmpty() && !sc.equals(t(etService))) etService.setText(sc);
        if (!disc.equals(t(etDiscretionary))) etDiscretionary.setText(disc);
        binding = false;
    }

    private static String brandFromPan(String pan) {
        if (pan.startsWith("34") || pan.startsWith("37")) return "AMEX";
        if (pan.startsWith("6011") || pan.startsWith("65")) return "DISCOVER";
        if (pan.startsWith("35")) return "JCB";
        if (pan.startsWith("62")) return "UNIONPAY";
        if (pan.startsWith("4")) return "VISA";
        if (pan.startsWith("5") || pan.startsWith("2")) return "MASTERCARD";
        return "CARD";
    }

    private static String aidFromPan(String pan) {
        if (pan.startsWith("34") || pan.startsWith("37")) return "A00000002501";
        if (pan.startsWith("6011") || pan.startsWith("65")) return "A0000001523010";
        if (pan.startsWith("35")) return "A0000000651010";
        if (pan.startsWith("62")) return "A000000333010101";
        if (pan.startsWith("4")) return "A0000000031010";
        if (pan.startsWith("5") || pan.startsWith("2")) return "A0000000041010";
        return "";
    }
}
