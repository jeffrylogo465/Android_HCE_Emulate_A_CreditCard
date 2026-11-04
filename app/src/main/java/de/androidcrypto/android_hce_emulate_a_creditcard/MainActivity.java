package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.cardemulation.CardEmulation;
import android.os.Bundle;
import android.provider.Settings;
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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private static final String PREF = "hce_card";
    private static final int MAX_CARDS = 20;
    private static final int REQ_CLONE = 4711;

    private static final long FRESH_MS = 3 * 60 * 1000L;
    private static final long WARM_MS = 60 * 60 * 1000L;

    private static final int COL_NEUTRAL = 0xFF9CA3AF;
    private static final int COL_FRESH   = 0xFF9AE6B4;
    private static final int COL_WARM    = 0xFFF6C177;
    private static final int COL_STALE   = 0xFF6B7280;

    private static final String CDOL1   = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL2   = "9F02069F03069F1A0295055F2A029A039C019F37049F3403";

    /**
     * Only used to render the preview line when the CVM box is empty. The bytes
     * on the wire come from the same value in ShadowApduService; this copy has
     * to agree with it or the preview lies.
     */
    private static final String CVMLIST = "00000000000000001F031E03";

    /** The one dump that matches the reference log. */
    private static final String KNOWN_PAN = "5287250568943496";

    /**
     * Per-network field defaults: 0 label, 1 AID, 2 AIP, 3 IAD, 4 ATC.
     *
     * Only the fields are here. The bytes the terminal actually sees live in
     * ProfileMastercard, ProfileVisa and ProfileAmex, one file each.
     *
     * THE IADs ARE THE CARDS' OWN. The IAD goes into the MAC input, so a
     * placeholder here makes a correct key produce a wrong ARQC. Byte 2 is the
     * CVN in both - 10 for the Mastercard, 12 for the Visa VIS shape.
     *
     * THE AIPs DIFFER and must: Mastercard numbers byte 1 by classic EMV, where
     * 0x40 is SDA and byte 2 b8 is "EMV mode supported" - 1880 turns EMV mode
     * on and leaves SDA off, because a clone cannot sign. Visa numbers byte 1
     * differently, where 0x40 is qVSDC - 5800 is right there.
     *
     * THE AMEX IAD IS EMPTY on purpose. Amex does not use the M/Chip CVN shape,
     * so an invented IAD would be worse than none.
     *
     * THE AMEX AIP IS 1880: byte 1 0x18 is CV + TRM, byte 2 0x80 is the MSD
     * bit. Byte 1 b8 is RFU under Visa and ExpressPay both - it is not a rung
     * on the ladder. If 1880 is refused the only live bits left to vary are
     * 0x10 and 0x08: 1080, then 0080.
     */
    private static final String[] PROFILE_MASTERCARD = {
            "MASTERCARD", "A0000000041010", "1880",
            "0110A000092400000102000000000000FF", "001C" };
    private static final String[] PROFILE_VISA = {
            "VISA", "A0000000031010", "5800",
            "06011200000000", "001C" };
    private static final String[] PROFILE_AMEX = {
            "AMEX", "A00000002501", "1880", "", "001C" };

    private static final String ASKED_DEFAULT = "asked_default";

    private static final String[][] VARIANTS = {
            {"0", "CDOL, AIP, ATC, IAD  -  option 0"},
            {"1", "CDOL, AIP, ATC, IAD  -  option 1"},
            {"2", "AIP, ATC, IAD, CDOL  -  option 0"},
            {"3", "AIP, ATC, IAD, CDOL  -  option 1"},
    };

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

    private static final String[] ROUTABLE = {
            "325041592E5359532E4444463031",
            "A0000000031010", "A0000000031020", "A0000000032010",
            "A0000000032020", "A0000000038010",
            "A0000000041010", "A0000000041000", "A0000000043060",
            "A0000000046000", "A0000000048002", "A0000000050001",
            "A00000002501", "A0000000250104", "A0000000250001",
            "A0000001523010", "A0000001524010", "A0000001521010",
            "A0000001522010", "A0000001522001", "A0000001522300",
            "A0000001522400", "A0000000152001", "A0000000152010",
            "A0000000152020", "A0000000152200", "A0000000152300",
            "A0000000152400", "A0000000010101",
            "A0000000651010", "A0000000650000",
            "A0000003330101", "A000000333010101", "A000000333010102",
            "A000000333010103",
            "A0000002771010", "A0000003845010", "A0000003841010",
            "A00000038410", "F0010203040506",
            "A0000003591010", "A0000003591010028001", "A00000000386980701",
            "A0000000410100", "A0000000422035",
    };

    private SharedPreferences prefs;
    private final List<CardAdapter.CardModel> cards = new ArrayList<>();
    private CardAdapter adapter;
    private RecyclerView pager;
    private LinearLayoutManager layoutManager;
    private PagerSnapHelper snapHelper;
    private TextView txtCount, txtStatus, banner;

    private EditText etLabel, etName, etPan, etExpiry, etService, etDiscretionary,
            etTrack2, etAid, etAip, etAfl, etCid, etAtc, etArqc, etIad, etMkac,
            etMsd, etScript, etCvmlist, etCvmres, etPdol, etCdol1, etCdol2;

    private View pageWallet, pageEdit;
    private TextView navWallet, navEdit;

    private int current = 0;
    private boolean binding = false;
    private boolean dumping = false;
    private boolean suppressResumeStatus = false;

    private String appliedProfile = "";

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
        banner = findViewById(R.id.banner);

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
        etCvmlist = findViewById(R.id.etCvmlist);
        etCvmres = findViewById(R.id.etCvmres);
        etPdol = findViewById(R.id.etPdol);
        etCdol1 = findViewById(R.id.etCdol1);
        etCdol2 = findViewById(R.id.etCdol2);

        pageWallet = findViewById(R.id.pageWallet);
        pageEdit = findViewById(R.id.pageEdit);
        navWallet = findViewById(R.id.navWallet);
        navEdit = findViewById(R.id.navEdit);

        navWallet.setOnClickListener(v -> showPage(0));
        navEdit.setOnClickListener(v -> showPage(1));

        if (banner != null) banner.setOnClickListener(v -> promptDefault());

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
        findViewById(R.id.btnCallBank).setOnClickListener(v -> callIssuer());
        findViewById(R.id.btnDelete).setOnClickListener(v -> onDelete());
        findViewById(R.id.btnAdd).setOnLongClickListener(v -> { startReader(); return true; });

        etAid.setOnLongClickListener(v -> { showAidPicker(); return true; });
        etLabel.setOnLongClickListener(v -> { showProfilePicker(); return true; });
        etTrack2.setOnLongClickListener(v -> { promptDump(); return true; });
        etMkac.setOnLongClickListener(v -> { showKeyTools(); return true; });
        navWallet.setOnLongClickListener(v -> { showRoutingCheck(); return true; });
        txtCount.setOnLongClickListener(v -> { startCapture(); return true; });
        txtStatus.setOnLongClickListener(v -> { clearVerdict(); return true; });

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
                etMsd, etScript, etCvmlist, etCvmres, etPdol, etCdol1, etCdol2 };
        for (EditText f : fields) f.addTextChangedListener(watcher);

        TextWatcher filler = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            public void onTextChanged(CharSequence s, int a, int b, int c) { }
            public void afterTextChanged(Editable s) {
                if (binding || dumping) return;
                autoFill();
                maybeProfile();

                String t2 = t(etTrack2);
                if (looksLikeFullDump(t2)) applyDump(t2);
            }
        };
        etTrack2.addTextChangedListener(filler);
        etPan.addTextChangedListener(filler);

        showPage(0);
    }

    /** A track 2 long enough to carry a CSC and an ATC. */
    private static boolean looksLikeFullDump(String t2) {
        String s = normaliseTrack2(t2);
        int d = s.indexOf('D');
        if (d < 12 || d > 19) return false;
        return s.length() >= d + 8;          // separator + expiry + service + 1
    }

    // ---------- status line ----------

    private void status(String s) { status(s, COL_NEUTRAL); }

    private void status(String s, int colour) {
        txtStatus.setText(s == null ? "" : s);
        txtStatus.setTextColor(colour);
    }

    private void clearVerdict() {
        prefs.edit().remove("lastverdict").remove("lastverdict_at").apply();
        status("Verdict cleared - tap a till to make a new one");
    }

    private void showLastVerdict() {
        String v = prefs.getString("lastverdict", "");
        if (v.isEmpty()) {
            status("");
            return;
        }

        long at = prefs.getLong("lastverdict_at", 0L);
        if (at == 0L) {
            status("(undated) " + v, COL_STALE);
            return;
        }

        long age = System.currentTimeMillis() - at;
        if (age < 0) age = 0;

        if (age < FRESH_MS) {
            status(v, COL_FRESH);
        } else if (age < WARM_MS) {
            status(ago(age) + " ago: " + v, COL_WARM);
        } else {
            status(ago(age) + " ago: " + v, COL_STALE);
        }
    }

    private static String ago(long ms) {
        long m = ms / 60000L;
        if (m < 1) return "seconds";
        if (m < 60) return m + " min";
        long h = m / 60;
        if (h < 24) return h + " h";
        return (h / 24) + " d";
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

    // ---------- profiles ----------

    /**
     * 34/37 is tested first: it is the longest prefix of the three and nothing
     * else starts with 3, so the order is cosmetic but reads better specific
     * before broad.
     */
    private static String profileFor(String pan) {
        if (pan == null || pan.length() < 4) return "";
        if (pan.startsWith("34") || pan.startsWith("37")) return "AMEX";
        if (pan.startsWith("4")) return "VISA";
        if (pan.startsWith("5") || pan.startsWith("2")) return "MASTERCARD";
        return "";
    }

    private static String[] profileFields(String net) {
        if ("AMEX".equals(net)) return PROFILE_AMEX;
        if ("VISA".equals(net)) return PROFILE_VISA;
        if ("MASTERCARD".equals(net)) return PROFILE_MASTERCARD;
        return null;
    }

    /** Whether the selector has been pinned away from AUTOMATICO. */
    private boolean profilePinned() {
        return prefs.getBoolean(key(current, "profilepin"), false);
    }

    /** AUTOMATICO unless the selector is pinned, in which case the pinned name. */
    private String profilePref() {
        if (!profilePinned()) return Profiles.AUTO;
        String v = prefs.getString(key(current, "profile"), Profiles.AUTO);
        return v == null || v.isEmpty() ? Profiles.AUTO : v;
    }

    /** What the tap will actually run, resolved the same way the service does. */
    private String effectiveProfile() {
        String p = profilePref();
        if (!Profiles.AUTO.equalsIgnoreCase(p)) return p.toUpperCase();
        String net = profileFor(digits(t(etPan)));
        return net.isEmpty() ? "MASTERCARD" : net;
    }

    /**
     * The profile selector. AUTOMATICO is the default and reads the network off
     * the PAN; picking a network pins it until you pick AUTOMATICO again.
     */
    private void showProfilePicker() {
        final String[] names = Profiles.names();
        final String[] labels = new String[names.length];
        for (int i = 0; i < names.length; i++) {
            labels[i] = Profiles.AUTO.equals(names[i])
                    ? "AUTOMATICO  (follow the card number)"
                    : names[i];
        }

        new AlertDialog.Builder(this)
                .setTitle("Script")
                .setItems(labels, (d, which) -> {
                    boolean auto = Profiles.AUTO.equals(names[which]);
                    prefs.edit()
                            .putString(key(current, "profile"), names[which])
                            .putBoolean(key(current, "profilepin"), !auto)
                            .apply();
                    appliedProfile = "";
                    if (auto) {
                        status("Script AUTOMATICO - the card number picks the network");
                        maybeProfile();
                    } else {
                        appliedProfile = names[which];
                        applyProfile(digits(t(etPan)), names[which]);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void maybeProfile() {
        if (binding) return;
        if (profilePinned()) return;
        String pan = digits(t(etPan));
        if (pan.length() < 4) {
            appliedProfile = "";
            return;
        }
        String net = profileFor(pan);
        if (net.isEmpty() || net.equals(appliedProfile)) return;
        applyProfile(pan, net);
    }

    /**
     * Put the card in place from the number.
     *
     * Only the FIELDS are written here. The directory, the FCI and the GPO come
     * from the profile file the service picks off the same number.
     *
     * The capture is wiped so an old PPSE or GPO cannot get in front of the
     * profile.
     *
     * The script box is only blanked when nothing is armed, so a card that the
     * dump loader has set up keeps its replay through a SAVE or a rebind.
     *
     * The ATC is only written when the box is empty - the service climbs it once
     * per tap and owns it after that.
     *
     * MSD follows the network: 1 for Amex and Mastercard, both of which have a
     * mag-stripe mode worth walking, 0 for Visa where the profile AIP has no
     * byte-2 bit. It is set here rather than only in the dump loader because
     * bindCard re-applies the profile on every rebind, so a flag set once is
     * wiped the next time the screen comes back - bindCard puts it back.
     */
    private void applyProfile(String pan, String net) {
        String[] f = profileFields(net);
        if (f == null) return;

        appliedProfile = net;
        // no pref write - profilePref() derives from the PAN while unpinned

        binding = true;
        etLabel.setText(f[0]);
        etAid.setText(f[1]);
        etAip.setText(f[2]);
        etIad.setText(f[3]);
        if (t(etAtc).isEmpty()) etAtc.setText(f[4]);
        etMsd.setText("AMEX".equals(net) || "MASTERCARD".equals(net) ? "1" : "0");
        etAfl.setText("");
        etCid.setText("");
        if (prefs.getString(key(current, "script"), "").trim().isEmpty()) etScript.setText("");

        if (KNOWN_PAN.equals(pan)) {
            etExpiry.setText("3105");
            etService.setText("201");
            etDiscretionary.setText("14129745");
            etTrack2.setText(pan + "D310520114129745");
        } else if (t(etExpiry).isEmpty()) {
            etExpiry.setText("3112");
            etService.setText("201");
        }
        binding = false;

        wipeCapture(current);

        collect();
        adapter.notifyItemChanged(current);
        status("Script " + net + " - directory, FCI and GPO come from Profile" + net
                + ", script box blank");
        Toast.makeText(this, net + " profile loaded", Toast.LENGTH_SHORT).show();
    }

    // ---------- track 2 dump ----------

    /**
     * Parse and validate a track 2 dump. Returns {pan, expiry, service, dd}.
     *
     * Lives here rather than in its own class so there is no second file to get
     * wrong. Throws with a short reason, which the caller shows on the status
     * line - the parse finishes before any field is written.
     */
    private static String[] parseDump(String raw) {
        if (raw == null) throw new IllegalArgumentException("empty");
        String s = raw.trim().toUpperCase(java.util.Locale.US);
        s = s.replace("\n", "").replace("\r", "");

        // A full dump arrives as "track2;track1;country;state;city;zip". Only
        // track 2 is ours - cut at the first separator rather than deleting
        // them, or track 1 runs into the DD and trips the length check.
        int semi = s.indexOf(';');
        if (semi >= 0) s = s.substring(0, semi);

        s = s.replace(";", "").replace("?", "").replace(" ", "");
        if (s.startsWith("B")) s = s.substring(1);

        int eq = s.indexOf('=');
        if (eq < 0) {
            int dsep = s.indexOf('D');                 // some dumps use D as the separator
            if (dsep < 0) throw new IllegalArgumentException("no separator");
            s = s.substring(0, dsep) + "=" + s.substring(dsep + 1);
            eq = dsep;
        }
        if (s.indexOf('=', eq + 1) >= 0) throw new IllegalArgumentException("two separators");

        String pan = s.substring(0, eq);
        String rest = s.substring(eq + 1);

        if (pan.length() < 13 || pan.length() > 19) throw new IllegalArgumentException("PAN length");
        if (!pan.matches("[0-9]+")) throw new IllegalArgumentException("PAN not digits");
        if (!luhn(pan)) throw new IllegalArgumentException("PAN Luhn");

        if (rest.length() < 7) throw new IllegalArgumentException("truncated");
        String expiry = rest.substring(0, 4);
        String sc = rest.substring(4, 7);
        String dd = rest.substring(7);

        if (!expiry.matches("[0-9]{4}")) throw new IllegalArgumentException("expiry not digits");
        int mm = Integer.parseInt(expiry.substring(2, 4));
        if (mm < 1 || mm > 12) throw new IllegalArgumentException("expiry month");

        if (!sc.matches("[0-9]{3}")) throw new IllegalArgumentException("service code");
        char a = sc.charAt(0);
        if (a != '1' && a != '2' && a != '5' && a != '6' && a != '7')
            throw new IllegalArgumentException("service code");

        if (dd.length() > 14) throw new IllegalArgumentException("DD too long");
        if (!dd.matches("[0-9A-F]*")) throw new IllegalArgumentException("DD not hex");

        return new String[]{pan, expiry, sc, dd};
    }

    /**
     * One-shot loader: paste a track 2 dump and everything downstream derives.
     *
     * The network comes off the PAN, so the profile fields go on unconditionally
     * - a dump is authoritative about which network it is.
     *
     * MSD is switched on for all three because the reason to paste a dump is to
     * replay the card's own CSC, and only the mag-stripe path serves it.
     *
     * The AFL and CID are blanked so the AFL follows msdloc instead of whatever
     * a previous card left behind - a stale AFL passes afl()'s length test and
     * points the terminal at a record the skeleton is not in.
     *
     * The record, the location, the ATC and the script are all armed by
     * armMsdCard() below, so nothing has to be typed by hand after the paste.
     */
    private void applyDump(String raw) {
        String[] d;
        try {
            d = parseDump(raw);
        } catch (IllegalArgumentException e) {
            status("dump: " + e.getMessage(), COL_STALE);
            return;
        }

        String net = profileFor(d[0]);
        if (net.isEmpty()) {
            status("dump: " + d[0] + " is not a network this app serves", COL_STALE);
            return;
        }

        dumping = true;
        String rawName = nameFromTrack1(raw);

        binding = true;
        etPan.setText(d[0]);
        etExpiry.setText(d[1]);
        etService.setText(d[2]);
        etDiscretionary.setText(d[3]);
        etTrack2.setText(d[0] + "=" + d[1] + d[2] + d[3]);
        if (!rawName.isEmpty()) etName.setText(rawName);
        binding = false;
        collect();

        // The PAN decides the network, so the profile fields go on unconditionally.
        applyProfile(d[0], net);

        binding = true;
        etAfl.setText("");
        etCid.setText("");
        binding = false;
        collect();

        boolean armed = armMsdCard(d[0], d[1], d[2], d[3]);
        dumping = false;

        if (!armed) return;
        status("dump loaded " + d[0] + " " + net
                + " - record, ATC and script armed. Tap it.", COL_WARM);
    }

    /**
     * Arm the whole card from a parsed dump.
     *
     * One paste, one setup. The record keeps the dump's own DD - CSC and ATC
     * carved exactly where they were - the served ATC is pinned to the CSC's
     * mint point so the track and 9F36 agree, and the script replays the GPO
     * and the CCC so neither has to be typed.
     *
     * THREE SHAPES, because the networks disagree:
     *
     *   AMEX      bare 57, CSC 4 digits. Fixed position, no bitmaps, no UDOL.
     *   VISA      bare 57, CSC 3 digits (dCVV). Fixed position. AIP comes from
     *             msdAip() because the mask would clear the MSD bit.
     *   MASTERCARD 9F6B not 57, CSC 4 digits, plus 9F65/9F66/9F67 and a 9F69
     *             UDOL naming 9F6A. Kernel 2 will not place the CSC without them.
     *
     * The CCC line is what makes this work with no key: the script path returns
     * before ccc(), so the card's own CSC goes out instead of the 0000 that a
     * missing IMKCVC3 would produce.
     *
     * The ATC is written as atc - 1 because nextAtc() adds one before serving.
     * A dump with no ATC in it (a Visa dCVV is 3 digits and nothing more) pads
     * to 0000, so the served ATC starts at 0001 rather than wrapping to FFFF.
     */
    private boolean armMsdCard(String pan, String exp, String svc, String ddRaw) {
        if (pan == null || pan.length() < 12) {
            status("PAN too short to arm the card", COL_STALE);
            return false;
        }
        if (exp == null || exp.length() < 4) exp = "3112";
        if (svc == null) svc = "";
        while (svc.length() < 3) svc = "0" + svc;

        String net = profileFor(pan);
        boolean mc = "MASTERCARD".equals(net);
        int cscLen = "VISA".equals(net) ? 3 : 4;

        String dd = (ddRaw == null ? "" : ddRaw).toUpperCase().replaceAll("[^0-9A-F]", "");
        while (dd.length() < cscLen + 4) dd = dd + "0";

        String csc = dd.substring(0, cscLen);
        String atc = dd.substring(cscLen, cscLen + 4);
        while (csc.length() % 2 != 0) csc = csc + "F";

        int atcVal;
        try {
            atcVal = Integer.parseInt(atc, 16);
        } catch (NumberFormatException e) {
            atcVal = 0;
        }
        if (atcVal == 0) atcVal = 1;             // no ATC in the dump: start at 1
        int atcPrev = (atcVal - 1) & 0xFFFF;
        String atcServed = String.format("%04X", atcVal);

        StringBuilder t = new StringBuilder(pan)
                .append('D').append(exp, 0, 4).append(svc, 0, 3).append(dd);
        if (t.length() % 2 != 0) t.append('F');

        byte[] track = hexToBytes(t.toString());
        byte[] rec;

        if (mc) {
            int ddOff = pan.length() + 1 + 4 + 3;
            rec = Tlv.t(0x70, Tlv.cat(
                    Tlv.t(0x9F6B, track),
                    Tlv.t(0x9F65, bits(0, pan.length())),
                    Tlv.t(0x9F66, bits(ddOff, cscLen)),
                    Tlv.t(0x9F67, new byte[]{0x02}),
                    Tlv.t(0x9F69, Tlv.t(0x9F6A, new byte[]{0x04}))));
        } else {
            rec = Tlv.t(0x70, Tlv.t(0x57, track));
        }

        String script = "80A80000=80061880080101009000" + "\n"
                + "80AE8000=770A9F61" + String.format("%02X", csc.length() / 2) + csc
                + "9F3602" + atcServed + "9000";

        binding = true;
        etAtc.setText(String.format("%04X", atcPrev));
        etScript.setText(script);
        etMsd.setText("1");
        binding = false;
        collect();

        prefs.edit()
                .putString(key(current, "msdrec"), Hex.toHex(rec))
                .putString(key(current, "msdloc"), "0101")
                .apply();

        return true;
    }

    /** Paste a dump into a dialog, pre-filled with whatever the box holds. */
    private void promptDump() {
        final EditText in = new EditText(this);
        in.setText(t(etTrack2));
        in.setHint("PAN=YYMM<svc><DD>  or  PAN D YYMM<svc><DD>");
        in.setTextSize(12f);
        new AlertDialog.Builder(this)
                .setTitle("Track 2 dump")
                .setView(in)
                .setPositiveButton("Load", (dlg, w) -> applyDump(in.getText().toString()))
                .setNegativeButton("Cancel", null)
                .show();
    }

    // ---------- BIN hints ----------

    private void applyHints(String pan) {
        if (pan == null || pan.length() < 6) return;
        String[] h = BankDirectory.hintsFor(pan);
        if (h == null) return;

        boolean changed = false;
        binding = true;
        if (t(etAid).isEmpty()) { etAid.setText(h[0]); changed = true; }
        if (t(etLabel).isEmpty()) { etLabel.setText(h[1]); changed = true; }
        if (t(etService).length() != 3) { etService.setText(h[2]); changed = true; }
        binding = false;

        if (changed) {
            collect();
            adapter.notifyItemChanged(current);
            status((BankDirectory.knownBin(pan) ? h[4] : h[4] + " (network only)")
                    + " - AID " + h[0] + " filled from the BIN");
        }
    }

    private void autoFill() {
        if (binding) return;

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
        if (sep < 12 || sep > 19) return;
        String pan = src.substring(0, sep);
        if (!pan.matches("[0-9]+")) return;

        String rest = src.substring(sep + 1);
        if (rest.length() < 7) return;
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
        applyHints(pan);
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

    private String panFromTrack2() {
        String track2 = normaliseTrack2(t(etTrack2));
        int d = track2.indexOf('D');
        if (d < 12 || d > 19) return "";
        String p = digits(track2.substring(0, d));
        return p.matches("[0-9]+") ? p : "";
    }

    private static int expectedCheckDigit(String pan) {
        if (pan.length() < 2) return -1;
        String body = pan.substring(0, pan.length() - 1);
        int sum = 0;
        boolean dbl = true;
        for (int i = body.length() - 1; i >= 0; i--) {
            int d = body.charAt(i) - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return (10 - (sum % 10)) % 10;
    }

    private String boxDiff(String pan) {
        if (pan.isEmpty()) return null;
        String ref = panFromTrack2();
        if (ref.isEmpty() || ref.equals(pan)) return null;
        if (ref.length() != pan.length()) {
            return "PAN is " + pan.length() + " digits, TRACK 2 has " + ref.length()
                    + " - different cards";
        }
        for (int i = 0; i < pan.length(); i++) {
            if (pan.charAt(i) != ref.charAt(i)) {
                return "Digit " + (i + 1) + " is " + pan.charAt(i)
                        + ", TRACK 2 has " + ref.charAt(i) + " - use the TRACK 2 value";
            }
        }
        return null;
    }

    private static boolean routable(String aid) {
        if (aid == null || aid.isEmpty()) return false;
        for (String f : ROUTABLE) if (aid.startsWith(f)) return true;
        return false;
    }

    private static int kernelOf(String aid) {
        String a = aid == null ? "" : aid.toUpperCase();
        if (a.startsWith("A000000152")) return 6;
        if (a.startsWith("A000000015")) return 6;
        if (a.startsWith("A000000004")) return 2;
        if (a.startsWith("A000000065")) return 5;
        if (a.startsWith("A000000025")) return 4;
        if (a.startsWith("A000000333")) return 7;
        return 3;
    }

    private void loadAll() {
        cards.clear();
        int n = Math.min(prefs.getInt("card_count", 0), MAX_CARDS);
        SharedPreferences.Editor e = prefs.edit();
        for (int i = 0; i < n; i++) {
            CardAdapter.CardModel c = new CardAdapter.CardModel();
            c.label = prefs.getString(key(i, "label"), "");
            c.pan = prefs.getString(key(i, "pan"), "");
            c.expiry = prefs.getString(key(i, "expiry"), "");
            c.aid = prefs.getString(key(i, "aid"), "");
            c.msd = prefs.getInt(key(i, "msd"), 0);
            cards.add(c);

            e.putInt(key(i, "usescript"),
                    armedLines(prefs.getString(key(i, "script"), "")) > 0 ? 1 : 0);
        }
        e.apply();
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
        e.putString(key(i, "track2"), normaliseTrack2(t(etTrack2)));
        e.putString(key(i, "aid"), t(etAid).toUpperCase());
        e.putString(key(i, "aip"), t(etAip).toUpperCase());
        e.putString(key(i, "afl"), t(etAfl).toUpperCase());
        e.putString(key(i, "cid"), t(etCid).toUpperCase());
        e.putString(key(i, "atc"), t(etAtc).toUpperCase());
        e.putString(key(i, "arqc"), t(etArqc).toUpperCase());
        e.putString(key(i, "iad"), t(etIad).toUpperCase());
        e.putString(key(i, "cvmlist"), t(etCvmlist).toUpperCase());
        e.putString(key(i, "cvmres"), t(etCvmres).toUpperCase());
        e.putString(key(i, "pdol"), t(etPdol).toUpperCase());
        e.putString(key(i, "cdol1"), t(etCdol1).toUpperCase());
        e.putString(key(i, "cdol2"), t(etCdol2).toUpperCase());
        e.putString(key(i, "mkac"), t(etMkac).toUpperCase());
        e.putString(key(i, "script"), t(etScript));
        e.putInt(key(i, "msd"), t(etMsd).startsWith("1") ? 1 : 0);
        e.putInt(key(i, "usescript"), armedLines(t(etScript)) > 0 ? 1 : 0);
        e.putInt("card_count", cards.size());
        e.putInt("selected", i);
        e.apply();

        if (i < cards.size()) {
            CardAdapter.CardModel c = cards.get(i);
            c.label = t(etLabel);
            c.pan = t(etPan);
            c.expiry = t(etExpiry);
            c.aid = t(etAid);
            c.msd = t(etMsd).startsWith("1") ? 1 : 0;
        }
    }

    private void bindCard(int i) {
        binding = true;
        current = i;
        appliedProfile = "";
        etLabel.setText(prefs.getString(key(i, "label"), ""));
        etName.setText(prefs.getString(key(i, "name"), ""));
        etPan.setText(prefs.getString(key(i, "pan"), ""));
        etExpiry.setText(prefs.getString(key(i, "expiry"), ""));
        etService.setText(prefs.getString(key(i, "service"), "201"));
        etDiscretionary.setText(prefs.getString(key(i, "discretionary"), ""));
        etTrack2.setText(prefs.getString(key(i, "track2"), ""));
        etAid.setText(prefs.getString(key(i, "aid"), ""));
        etAip.setText(prefs.getString(key(i, "aip"), "1880"));
        etAfl.setText(prefs.getString(key(i, "afl"), ""));
        etCid.setText(prefs.getString(key(i, "cid"), ""));
        etAtc.setText(prefs.getString(key(i, "atc"), "001B"));
        etArqc.setText(prefs.getString(key(i, "arqc"), ""));
        etIad.setText(prefs.getString(key(i, "iad"), ""));
        etCvmlist.setText(prefs.getString(key(i, "cvmlist"), ""));
        etCvmres.setText(prefs.getString(key(i, "cvmres"), ""));
        etPdol.setText(prefs.getString(key(i, "pdol"), ""));
        etCdol1.setText(prefs.getString(key(i, "cdol1"), ""));
        etCdol2.setText(prefs.getString(key(i, "cdol2"), ""));
        etMkac.setText(prefs.getString(key(i, "mkac"), ""));

        if (t(etMkac).isEmpty()) {
            String b6 = digits(prefs.getString(key(i, "pan"), ""));
            if (b6.length() >= 6) {
                String kk = prefs.getString("keyfor_" + b6.substring(0, 6), "");
                if (kk.length() == 32) etMkac.setText(kk);
            }
        }

        etMsd.setText(String.valueOf(prefs.getInt(key(i, "msd"), 0)));
        etScript.setText(prefs.getString(key(i, "script"), ""));
        binding = false;
        updateCount();
        status("");
        autoFill();
        maybeProfile();

        // maybeProfile -> applyProfile can blank the script and reset msd; put the
        // armed values back so a rebind does not disarm the card.
        binding = true;
        etScript.setText(prefs.getString(key(i, "script"), ""));
        etMsd.setText(String.valueOf(prefs.getInt(key(i, "msd"), 0)));
        binding = false;
        collect();
    }

    private void updateCount() {
        txtCount.setText(cards.size() == 1 ? "1 card" : cards.size() + " cards");
    }

    private static int armedLines(String script) {
        if (script == null) return 0;
        int n = 0;
        for (String line : script.split("\\R")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            if (line.indexOf('=') > 0) n++;
        }
        return n;
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
                    status("AID set to " + AID_PRESETS[which][0]);
                    Toast.makeText(this, AID_PRESETS[which][0] + " AID set", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // ---------- preview ----------

    private String previewText() {
        String pan = digits(t(etPan));
        String exp = digits(t(etExpiry));
        String sc = digits(t(etService));
        String disc = t(etDiscretionary).toUpperCase();
        String aid = t(etAid).toUpperCase();
        String msd = t(etMsd).isEmpty() ? "0" : t(etMsd);
        String prof = effectiveProfile();

        String track2 = normaliseTrack2(t(etTrack2));
        if (track2.isEmpty() && !pan.isEmpty()) {
            track2 = pan + "D" + exp + sc + disc;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SCRIPT     : ").append(prof)
                .append(profilePinned() ? "  (PINNED)" : "  (AUTOMATICO)")
                .append('\n');
        sb.append("AID  (4F)  : ")
                .append(aid.isEmpty() ? "(EMPTY - profile default is used)" : aid).append('\n');
        sb.append("AIP  (82)  : ")
                .append(t(etAip).isEmpty() ? "1880" : t(etAip).toUpperCase()).append('\n');
        sb.append("IAD  (9F10): ")
                .append(t(etIad).isEmpty() ? "(empty - CVN unreadable, CSK assumed)"
                        : t(etIad).toUpperCase() + "  CVN " + cvnFromIad(t(etIad)))
                .append('\n');
        sb.append("CID        : ")
                .append(t(etCid).isEmpty() ? "40 from the profile - TC, approve offline"
                        : t(etCid).toUpperCase() + "  (FORCED)").append('\n');
        sb.append("ATC        : live - climbs once per tap, script carries it\n");
        sb.append("MSD        : ").append("0".equals(msd)
                ? "0  EMV mode - ARQC gets judged" : "1  magstripe - no crypto").append('\n');
        sb.append('\n');

        sb.append("5A  PAN    : ")
                .append(pan.isEmpty() ? "4111111111111111  <-- DEFAULT, fill the PAN" : pan)
                .append('\n');
        if (!pan.isEmpty()) {
            sb.append("   check digit : ")
                    .append(luhn(pan) ? "ok" : "FAILS - last digit should be "
                            + expectedCheckDigit(pan)).append('\n');
            String diff = boxDiff(pan);
            if (diff != null) sb.append("   !! ").append(diff).append('\n');

            String[] h = BankDirectory.hintsFor(pan);
            if (h != null) {
                sb.append("   issuer : ").append(h[4]).append("  (").append(h[3]).append(')').append('\n');
            }
        }
        String expOut = exp.isEmpty() ? "3112  <-- DEFAULT" : exp;
        if (exp.length() == 4) expOut = exp + "01";
        sb.append("5F24 expiry: ").append(expOut).append('\n');
        sb.append("5F20 name  : ")
                .append(t(etName).isEmpty() ? "(empty - slip shows no name)" : t(etName).toUpperCase())
                .append('\n');
        sb.append("57  track2 : ")
                .append(track2.isEmpty() ? "(empty)" : hexOf(track2)).append('\n');

        sb.append("CVM list   : ")
                .append(t(etCvmlist).isEmpty() ? "service constant (" + CVMLIST + ")"
                        : t(etCvmlist).toUpperCase())
                .append('\n');
        sb.append("record     : synthetic SFI 1 rec 1, built from these fields\n");

        String script = t(etScript);
        int scriptLines = armedLines(script);
        sb.append("script box : ").append(scriptLines == 0
                ? "blank - the " + prof + " profile runs"
                : scriptLines + " line(s) - these OVERRIDE the profile").append('\n');

        if (aid.isEmpty()) {
            sb.append('\n').append("AID empty - the profile default is used, that is fine\n");
        } else if (!routable(aid)) {
            sb.append('\n').append("!! AID has no <aid-filter> in apduservice.xml\n");
            sb.append("   Android will not route the SELECT - tap dies with NO log line\n");
        }
        return sb.toString();
    }

    private void showPreview() {
        new AlertDialog.Builder(this)
                .setTitle("What the terminal will see")
                .setMessage(previewText())
                .setPositiveButton("CLEAR CAPTURE", (d, w) -> clearCapture())
                .setNegativeButton("Close", null)
                .show();
    }

    // ---------- capture: clear ----------

    private void clearCapture() {
        final int i = current;
        new AlertDialog.Builder(this)
                .setTitle("Clear the capture for card " + (i + 1) + "?")
                .setMessage("Removes any captured PPSE, FCI, GPO and records. The profile"
                        + " still serves the directory, FCI and GPO, so the card keeps working.")
                .setPositiveButton("Clear", (d, w) -> {
                    wipeCapture(i);
                    binding = true;
                    etMsd.setText("0");
                    binding = false;
                    collect();
                    status("Capture cleared - the profile still runs");
                    Toast.makeText(this, "Capture cleared", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void wipeCapture(int i) {
        SharedPreferences.Editor e = prefs.edit();
        String p = key(i, "cap_");
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(p)) e.remove(k);
        }
        e.putInt(key(i, "msd"), 0);
        e.apply();
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

    // ---------- routing self-check ----------

    private void showRoutingCheck() {
        ComponentName me = new ComponentName(this, ShadowApduService.class);
        StringBuilder sb = new StringBuilder();

        NfcManager mgr = (NfcManager) getSystemService(NFC_SERVICE);
        NfcAdapter nfc = mgr == null ? null : mgr.getDefaultAdapter();

        if (nfc == null) {
            sb.append("NFC: no adapter - this device cannot do HCE at all\n");
        } else {
            sb.append("NFC radio: ")
              .append(nfc.isEnabled() ? "on" : "OFF - enable it first").append('\n');
        }
        sb.append('\n');

        CardEmulation ce = null;
        if (nfc != null) {
            try { ce = CardEmulation.getInstance(nfc); } catch (Throwable ignored) { }
        }
        if (ce == null) {
            sb.append("CardEmulation unavailable - HCE not supported on this device\n");
            dialog("Can the terminal reach us?", sb.toString());
            return;
        }

        boolean isDefault = ce.isDefaultServiceForCategory(me, CardEmulation.CATEGORY_PAYMENT);
        sb.append("default payment app: ").append(isDefault ? "YES" : "NO").append('\n');

        String aid = t(etAid).toUpperCase();
        List<String> check = new ArrayList<>();
        check.add("325041592E5359532E4444463031");
        if (!aid.isEmpty()) check.add(aid);
        if (!"A0000000031010".equals(aid)) check.add("A0000000031010");
        if (!"A0000000041010".equals(aid)) check.add("A0000000041010");

        int blocked = 0;
        for (String a : check) {
            if (!routable(a)) { blocked++; continue; }
            boolean routed;
            try {
                routed = ce.isDefaultServiceForAid(me, a);
            } catch (Throwable ignored) {
                routed = false;
            }
            if (!routed) blocked++;
        }

        sb.append('\n').append(blocked == 0
                ? "Verdict: a tap should reach the emulator."
                : "Verdict: " + blocked + " of " + check.size() + " AIDs are blocked.");

        dialog("Can the terminal reach us?", sb.toString());
    }

    private void dialog(String title, String body) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(body)
                .setPositiveButton("Close", null)
                .show();
    }

    // ---------- issuer key search ----------

    private void showKeyTools() {
        String v = prefs.getString(key(current, "keyvar"), "0");
        String label = "MAC variant (" + v + ")";

        new AlertDialog.Builder(this)
                .setTitle("Issuer master key")
                .setItems(new String[]{"Scan for the key", "Edit candidate list", label,
                                "Show KCV", "Run SKD vector", "Run CSK vector",
                                "Run CVC3 vector",
                                "Seed vector card", "Run CVC3 harness",
                                "MSD: set IMKCVC3", "MSD: set IVCVC3", "MSD: build record",
                                "MSD: set record", "MSD: set location",
                                "Check profile constants"},
                        (d, w) -> {
                            if (w == 0) scanForKey();
                            else if (w == 1) editKeyList();
                            else if (w == 3) showKcv();
                            else if (w == 4) runSkdVector();
                            else if (w == 5) runCskVector();
                            else if (w == 6) runCvc3Vector();
                            else if (w == 7) status(VectorSeed.apply(this));
                            else if (w == 8) status(Cvc3Vector.run());
                            else if (w == 9) setHexPref("imkcvc3", "IMKCVC3",
                                    "32 or 48 hex. A different key from IMK-AC.", 32);
                            else if (w == 10) setHexPref("ivcvc3", "IVCVC3",
                                    "4 hex. From the dump, usually tag DD.", 4);
                            else if (w == 11) buildMsdRecord();
                            else if (w == 12) setHexPref("msdrec", "MSD record",
                                    "The personalised 57 record, verbatim, no status word.", 8);
                            else if (w == 13) setHexPref("msdloc", "MSD record location",
                                    "ssrr hex, e.g. 0201 = SFI 2 record 1.", 4);
                            else if (w == 14) checkProfiles();
                            else pickKeyVariant();
                        })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /**
     * One hex value into a card-scoped pref, with the length checked.
     *
     * These four are the MSD inputs and none of them has a box: IMKCVC3 is a
     * second master key that the MK-AC box does not hold, IVCVC3 is a
     * personalisation value, the record has to be the dump's skeleton verbatim,
     * and the location says which record carries it. Putting them here rather
     * than in the layout keeps activity_main.xml untouched.
     */
    private void setHexPref(String name, String title, String hint, int minLen) {
        final EditText e = new EditText(this);
        e.setText(prefs.getString(key(current, name), ""));
        e.setHint(hint);
        e.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);

        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(e)
                .setPositiveButton("Save", (d, w) -> {
                    String h = e.getText().toString()
                            .replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
                    if (h.length() < minLen) {
                        Toast.makeText(this, title + " needs at least " + minLen + " hex",
                                Toast.LENGTH_SHORT).show();
                        return;
                    }
                    prefs.edit().putString(key(current, name), h).apply();
                    status(title + " set, " + (h.length() / 2) + " bytes");
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /** Bitmap of `len` bits starting at `from`, MSB first. */
    private static byte[] bits(int from, int len) {
        byte[] b = new byte[(from + len + 7) / 8];
        for (int i = 0; i < len; i++) {
            int p = from + i;
            b[p / 8] |= (byte) (0x80 >> (p % 8));
        }
        return b;
    }

    /**
     * Validate every hardcoded profile constant.
     *
     * The directory and FCI are the only hand-written lengths in the app, and
     * the only things that can fail with no compiler complaint. ProfileAmex had
     * all of them wrong; ProfileMastercard is the clean baseline, so if MC comes
     * back bad the validator itself is suspect rather than the bytes.
     */
    private void checkProfiles() {
        StringBuilder sb = new StringBuilder();
        int bad = 0;
        bad += reportConstants(sb, "AMEX", ProfileAmex.scriptConstants());
        bad += reportConstants(sb, "MASTERCARD", ProfileMastercard.scriptConstants());
        sb.append('\n').append(bad == 0
                ? "All constants balanced."
                : bad + " constant(s) malformed.");
        dialog("Profile constants", sb.toString());
    }

    /** Validates one profile's constants into sb. Returns the failure count. */
    private int reportConstants(StringBuilder sb, String name, String[] hexes) {
        int bad = 0;
        for (String hex : hexes) {
            String p = TlvValidator.firstProblem(hex);
            if (p == null) {
                sb.append(name).append(" ok\n");
            } else {
                bad++;
                sb.append(name).append(" BAD: ").append(p).append('\n');
            }
        }
        return bad;
    }

    /**
     * Build the MSD skeleton, at SFI 1 rec 1.
     *
     * TWO SHAPES. Mastercard Kernel 2 marks where the terminal patches CSC, ATC
     * and nUN with bitmaps: 9F65 over the PAN, 9F66 over the DD region, 9F67 for
     * nUN, and a 9F69 UDOL naming 9F6A. Visa and ExpressPay define none of that
     * - the CSC position is fixed by the spec - so they get a bare 57.
     *
     * The DD is eight zeros in both: CSC 2, ATC 2, nUN 2, two spare.
     *
     * armMsdCard() supersedes this for the dump path, because it keeps the
     * dump's own DD instead of zeroing it. This stays for the menu.
     */
    private void buildMsdRecord() {
        String pan = prefs.getString(key(current, "pan"), "").replaceAll("[^0-9]", "");
        if (pan.length() < 12) { status("PAN too short for a skeleton"); return; }
        String exp = prefs.getString(key(current, "expiry"), "").replaceAll("[^0-9]", "");
        if (exp.length() < 4) exp = "3112";
        String svc = prefs.getString(key(current, "service"), "").replaceAll("[^0-9]", "");
        while (svc.length() < 3) svc = "0" + svc;

        byte[] track = EmvCrypto.msdTrack2(pan, exp.substring(0, 4),
                svc.substring(0, 3), 8);

        byte[] rec;
        if ("MASTERCARD".equals(profileFor(pan))) {
            int ddOff = pan.length() + 1 + 4 + 3;
            rec = Tlv.t(0x70, Tlv.cat(
                    Tlv.t(0x9F6B, track),
                    Tlv.t(0x9F65, bits(0, pan.length())),
                    Tlv.t(0x9F66, bits(ddOff, 4)),
                    Tlv.t(0x9F67, new byte[]{0x02}),
                    Tlv.t(0x9F69, Tlv.t(0x9F6A, new byte[]{0x04}))));
        } else {
            rec = Tlv.t(0x70, Tlv.t(0x57, track));
        }

        prefs.edit()
                .putString(key(current, "msdrec"), Hex.toHex(rec))
                .putString(key(current, "msdloc"), "0101")
                .apply();
        status("skeleton built, " + rec.length + "B - "
                + ("MASTERCARD".equals(profileFor(pan)) ? "bitmaps + UDOL" : "bare 57"));
    }

    private void pickKeyVariant() {
        String[] labels = new String[VARIANTS.length];
        for (int i = 0; i < VARIANTS.length; i++) labels[i] = VARIANTS[i][0] + " - " + VARIANTS[i][1];

        new AlertDialog.Builder(this)
                .setTitle("MAC input variant")
                .setItems(labels, (d, w) -> {
                    prefs.edit().putString(key(current, "keyvar"), VARIANTS[w][0]).apply();
                    status("MAC variant " + VARIANTS[w][0] + " - " + VARIANTS[w][1]);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /**
     * Show the KCV of whatever is in the MK-AC box, so a seller's quoted value
     * can be compared before the key is trusted. Six hex characters.
     */
    private void showKcv() {
        String k = t(etMkac).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        if (k.length() != 32 && k.length() != 48) {
            Toast.makeText(this, "MK-AC box needs 32 or 48 hex", Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            status("KCV " + EmvCrypto.kcv(k) + "  (compare with the seller's)");
        } catch (Exception e) {
            status("KCV failed - " + e);
        }
    }

    /**
     * Three-stage vector, so a failure names its own cause.
     *
     * Stage 0 is a DES known-answer test: key 133457799BBCDFF1 over the block
     * 0123456789ABCDEF must give 85E813540F0AB405.
     *
     * Stage 1 pins the ICC master key derivation: MKiss 0123456789ABCDEFFEDCB
     * A9876543210 with PAN 5287250568943496 and PSN 01 must give MK_L
     * 57B3F7D3DC526123 and MK_R 4C75D998135DCD0B.
     *
     * Stage 2 pins the SK layout: ATC 0001, UN 12345678 must give
     * AB8373B63D1FFD9EE3F8EFA71A2F61FD.
     */
    private void runSkdVector() {
        try {
            String kat = bytesToHex(EmvCrypto.des(hexToBytes("133457799BBCDFF1"),
                    hexToBytes("0123456789ABCDEF")));
            if (!"85E813540F0AB405".equals(kat)) {
                status("stage 0 DES KAT MISMATCH  " + kat + "  want 85E813540F0AB405");
                return;
            }

            byte[][] k = EmvCrypto.iccMasterKeys(
                    "0123456789ABCDEFFEDCBA9876543210", "5287250568943496", "01");
            String l = bytesToHex(k[0]);
            String r = bytesToHex(k[1]);
            if (!"57B3F7D3DC526123".equals(l) || !"4C75D998135DCD0B".equals(r)) {
                status("stage 1 ICC MK MISMATCH  L " + l + " R " + r
                        + "  want L 57B3F7D3DC526123 R 4C75D998135DCD0B");
                return;
            }

            String sk = bytesToHex(EmvCrypto.sessionKeySkdRaw(k[0], k[1], "0001",
                    hexToBytes("12345678")));
            String want = "AB8373B63D1FFD9EE3F8EFA71A2F61FD";
            status((want.equals(sk) ? "stage 2 SKD vector OK " : "stage 2 SKD vector MISMATCH ")
                    + sk + (want.equals(sk) ? "" : "  want " + want));
        } catch (Exception e) {
            status("SKD vector failed - " + e);
        }
    }

    /**
     * CSK vector, CVN 20/21. Stage 1 is the same ICC derivation as SKD, so it is
     * not repeated here - run the SKD vector first.
     *
     * Stage 2: ATC 0001, UN ignored, must give DF20453BB5E5D946BAC2C7E645B5405E.
     */
    private void runCskVector() {
        try {
            byte[][] k = EmvCrypto.iccMasterKeys(
                    "0123456789ABCDEFFEDCBA9876543210", "5287250568943496", "01");
            String sk = bytesToHex(EmvCrypto.sessionKeyCskRaw(k[0], k[1], "0001"));
            String want = "DF20453BB5E5D946BAC2C7E645B5405E";
            status((want.equals(sk) ? "CSK vector OK " : "CSK vector MISMATCH ")
                    + sk + (want.equals(sk) ? "" : "  want " + want));
        } catch (Exception e) {
            status("CSK vector failed - " + e);
        }
    }

    /**
     * CVC3 vector. Staged, so a failure names its own cause.
     *
     * Stage 0 DES KAT. Stage 1 pins KDCVC3 from IMKCVC3 over PAN and PSN - the
     * same Option A derivation the ARQC path uses. Stage 2 pins block order and
     * truncation. Stage 3 is the negative, changing only the IV. Stage 4 runs
     * the integer 26 through the production ATC encoder, because at 0001 binary
     * and BCD are the same two bytes and the encoding goes untested.
     */
    private void runCvc3Vector() {
        try {
            String kat = bytesToHex(EmvCrypto.des(hexToBytes("133457799BBCDFF1"),
                    hexToBytes("0123456789ABCDEF")));
            if (!"85E813540F0AB405".equals(kat)) {
                status("stage 0 DES KAT MISMATCH  " + kat + "  want 85E813540F0AB405");
                return;
            }

            String imk = "0123456789ABCDEFFEDCBA9876543210";
            byte[][] k = EmvCrypto.iccMasterKeys(imk, "5413330089600010", "01");
            String kd = bytesToHex(k[0]) + bytesToHex(k[1]);
            String wantKd = "438F4A976EC80DB3F4D31C0DCB32A226";
            if (!wantKd.equals(kd)) {
                status("stage 1 KDCVC3 MISMATCH  " + kd + "  want " + wantKd);
                return;
            }

            byte[] key = hexToBytes(kd);

            String c2 = cipherOf(key, "3E01", "12345678", "0001");
            if (!"979B5DBF35CFCF70".equals(c2) || !"CF70".equals(tail2(c2))) {
                status("stage 2 MISMATCH  " + c2 + "  want 979B5DBF35CFCF70 / CF70");
                return;
            }

            String c3 = cipherOf(key, "3E02", "12345678", "0001");
            if (!"95CB55DAAAFE0275".equals(c3) || !"0275".equals(tail2(c3))) {
                status("stage 3 negative MISMATCH  " + c3 + "  want 95CB55DAAAFE0275 / 0275");
                return;
            }

            String atcHex = bytesToHex(EmvCrypto.atcField(26));
            if ("0026".equals(atcHex)) {
                status("stage 4 ATC encoded as BCD (0026), want binary 001A");
                return;
            }
            if (!"001A".equals(atcHex)) {
                status("stage 4 ATC field " + atcHex + "  want 001A");
                return;
            }
            String c4 = cipherOf(key, "3E01", "12345678", atcHex);
            if (!"47E6367D1F95533A".equals(c4) || !"533A".equals(tail2(c4))) {
                status("stage 4 MISMATCH  " + c4 + "  want 47E6367D1F95533A / 533A"
                        + " (E03B = BCD)");
                return;
            }

            status("CVC3 vector OK - CF70, neg 0275, atc 26 -> 001A -> 533A");
        } catch (Exception e) {
            status("CVC3 vector failed - " + e);
        }
    }

    /** Whole 3DES output for IV || UN || ATC. */
    private String cipherOf(byte[] kd, String iv, String un, String atc) throws Exception {
        return bytesToHex(EmvCrypto.des3(kd, hexToBytes(iv + un + atc)));
    }

    private static String tail2(String cipherHex) {
        return cipherHex.substring(cipherHex.length() - 4);
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

    /**
     * Candidates for the scan.
     *
     * A remembered key for this BIN comes first. When a supplied list exists it
     * is used ALONE: generated families cannot match a production IMK, so
     * merging them only spends hundreds of thousands of MACs on keys that are
     * known not to work. Generation is the fallback for an empty list.
     */
    private List<String> candidateKeys() {
        String bin = digits(t(etPan));
        List<String> out = new ArrayList<>();

        if (bin.length() >= 6) {
            String remembered = prefs.getString("keyfor_" + bin.substring(0, 6), "");
            if (remembered.length() == 32 && !out.contains(remembered)) out.add(0, remembered);
        }

        List<String> supplied = new ArrayList<>();
        for (String line : prefs.getString("keylist", "").split("\\R")) {
            String k = line.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            if (k.length() == 32 && !supplied.contains(k)) supplied.add(k);
        }

        if (!supplied.isEmpty()) {
            for (String k : supplied) if (!out.contains(k)) out.add(k);
            return out;
        }

        for (String k : KeyFinder.candidates(bin, "")) {
            if (!out.contains(k)) out.add(k);
        }
        return out;
    }

    private void scanForKey() { scanForKey(true); }

    /** CVN from the IAD: byte 2 of a DKI||CVN IAD, low nibble for CCD. -1 if none. */
    private static int cvnFromIad(String iadHex) {
        String h = (iadHex == null ? "" : iadHex).replaceAll("[^0-9A-Fa-f]", "");
        if (h.length() < 4) return -1;
        try {
            int b1 = Integer.parseInt(h.substring(0, 2), 16);
            int b2 = Integer.parseInt(h.substring(2, 4), 16);
            if (b1 == 0x0F) return b2 & 0x0F;
            return b2;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Search the candidate list for the issuer key.
     *
     * Two sources of reference: a real capture from READ CARD, or - for a card
     * that was never read, i.e. a dump - the ARQC, CDOL data, AIP and ATC typed
     * into the boxes. The typed route uses the REFERENCE card's AIP, not ours:
     * the reference ARQC was MACed over that AIP, so 1880 can never match.
     *
     * The MAC input is cdol || AIP || ATC || IAD. The session key scheme follows
     * the CVN: 16/17 are SKD with the UN, 20/21 are CSK.
     */
    private void scanForKey(boolean announce) {
        String cmdHex = prefs.getString(key(current, "cap_genaccmd"), "");
        String rspHex = prefs.getString(key(current, "cap_rawgenac"), "");
        String pan = digits(t(etPan));

        String typedArqc = t(etArqc).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        String typedCdol = t(etCdol1).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        String typedAip  = t(etPdol).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        String typedAtc  = t(etAtc).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        boolean typedRef = cmdHex.isEmpty() && rspHex.isEmpty()
                && typedArqc.length() == 16 && typedCdol.length() >= 16
                && typedAip.length() == 4 && typedAtc.length() == 4;

        String aipHex = aipFromGpo(prefs.getString(key(current, "cap_rawgpo"), ""));
        if (typedRef) aipHex = typedAip;
        else if (aipHex.isEmpty()) aipHex = t(etAip).toUpperCase();

        if (!typedRef && (cmdHex.isEmpty() || rspHex.isEmpty())) {
            if (announce) {
                Toast.makeText(this, "No reference - fill the ARQC, CDOL1, PDOL and ATC boxes",
                        Toast.LENGTH_LONG).show();
            }
            return;
        }
        if (pan.isEmpty() || aipHex.length() < 4) {
            if (announce) {
                Toast.makeText(this, "Need PAN and reference AIP set on the card",
                        Toast.LENGTH_LONG).show();
            }
            return;
        }

        final byte[] cdol;
        final byte[] arqcRef;
        final String atc;

        if (typedRef) {
            cdol = hexToBytes(typedCdol);
            arqcRef = hexToBytes(typedArqc);
            atc = typedAtc;
        } else {
            byte[] cmd = hexToBytes(cmdHex);
            byte[] rsp = hexToBytes(rspHex);
            if (cmd.length < 6) return;
            int lc = cmd[4] & 0xFF;
            int off = 5;
            if (lc == 0x00) {
                if (cmd.length < 7) return;
                lc = ((cmd[5] & 0xFF) << 8) | (cmd[6] & 0xFF);
                off = 7;
            }
            if (off + lc > cmd.length) return;

            cdol = Arrays.copyOfRange(cmd, off, off + lc);
            arqcRef = tagOf(rsp, 0x9F26);
            byte[] atcRef = tagOf(rsp, 0x9F36);
            if (arqcRef == null || atcRef == null) {
                if (announce) {
                    Toast.makeText(this, "Reference ARQC/ATC missing from the capture",
                            Toast.LENGTH_LONG).show();
                }
                return;
            }
            atc = bytesToHex(atcRef);
        }

        final byte[] aip = hexToBytes(aipHex);
        final byte[] iadRef = hexToBytes(t(etIad));
        final String psn = prefs.getString(key(current, "psn"), "01");
        final List<String> keys = candidateKeys();

        if (keys.isEmpty()) {
            status("No candidate keys - use 'Edit candidate list' first");
            if (announce) {
                Toast.makeText(this, "No candidate keys", Toast.LENGTH_LONG).show();
            }
            return;
        }

        final int cvn = cvnFromIad(t(etIad));
        final boolean csk = (cvn == 20 || cvn == 21);

        status("Scanning " + keys.size() + " keys x 4 variants...");

        new Thread(() -> {
            int tried = 0;
            for (String k : keys) {
                for (int variant = 0; variant < 4; variant++) {
                    tried++;
                    try {
                        byte[] macIn = ((variant & 2) != 0)
                                ? cat(aip, hexToBytes(atc), iadRef, cdol)
                                : cat(cdol, aip, hexToBytes(atc), iadRef);
                        byte[] un = cdol.length < 4
                                ? new byte[4]
                                : Arrays.copyOfRange(cdol, cdol.length - 4, cdol.length);

                        byte[] ac = csk
                                ? EmvCrypto.arqc(k, pan, psn, atc, macIn, variant & 1)
                                : EmvCrypto.arqcSkd(k, pan, psn, atc, un, macIn, variant & 1);

                        if (Arrays.equals(ac, arqcRef)) {
                            final String fk = k;
                            final int fv = variant;
                            runOnUiThread(() -> {
                                etMkac.setText(fk);
                                prefs.edit().putString(key(current, "keyvar"),
                                        String.valueOf(fv)).apply();

                                String bin6 = digits(t(etPan));
                                if (bin6.length() >= 6) {
                                    prefs.edit().putString("keyfor_" + bin6.substring(0, 6),
                                            fk).apply();
                                }

                                collect();
                                status("KEY FOUND " + fk + "  (variant " + fv + ")");
                                Toast.makeText(this, "Issuer key found", Toast.LENGTH_LONG).show();
                            });
                            return;
                        }
                    } catch (Exception ignored) { }
                }
            }
            final int total = tried;
            runOnUiThread(() -> {
                status("Read OK - no key matched (" + total + " tries).");
                if (announce) {
                    Toast.makeText(this, "No match - " + total + " tries", Toast.LENGTH_LONG).show();
                }
            });
        }).start();
    }

    // ---------- small helpers ----------

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

    private static String aipFromGpo(String gpo) {
        if (gpo == null || gpo.isEmpty()) return "";
        byte[] d = hexToBytes(gpo);
        if (d.length < 4) return "";
        int i = 0;
        int tag = d[i++] & 0xFF;
        int len = d[i++] & 0xFF;
        if ((len & 0x80) != 0) {
            int n = len & 0x7F;
            len = 0;
            for (int k = 0; k < n && i < d.length; k++) len = (len << 8) | (d[i++] & 0xFF);
        }
        if (i + len > d.length) len = d.length - i;
        if (tag == 0x80) {
            return len < 2 ? "" : bytesToHex(Arrays.copyOfRange(d, i, i + 2));
        }
        byte[] aip = tagOf(Arrays.copyOfRange(d, i, i + len), 0x82);
        return aip == null ? "" : bytesToHex(aip);
    }

    // ---------- actions ----------

    private void startReader() {
        collect();
        Intent i = new Intent(this, ReaderActivity.class);
        i.putExtra(ReaderActivity.EXTRA_CARD_INDEX, current);
        startActivityForResult(i, REQ_CLONE);
    }

    private void startCapture() {
        collect();
        Intent i = new Intent(this, CaptureActivity.class);
        i.putExtra(CaptureActivity.EXTRA_CARD_INDEX, current);
        startActivity(i);
    }

    private void callIssuer() {
        String pan = digits(t(etPan));
        if (pan.length() < 12 || pan.length() > 19) pan = panFromTrack2();
        if (pan.isEmpty()) {
            Toast.makeText(this, "Fill the PAN first", Toast.LENGTH_SHORT).show();
            return;
        }
        BankDirectory.showCallSheet(this, pan);
    }

    private void onSave() {
        String diff = boxDiff(digits(t(etPan)));

        syncFieldsFromTrack2();

        if (diff != null) {
            String trackPan = panFromTrack2();
            if (!trackPan.isEmpty()) {
                binding = true;
                etPan.setText(trackPan);
                binding = false;
            }
        }

        maybeProfile();

        String[] hints = BankDirectory.hintsFor(digits(t(etPan)));
        if (hints != null) {
            if (t(etLabel).isEmpty()) etLabel.setText(hints[1]);
            if (t(etAid).isEmpty()) etAid.setText(hints[0]);
            if (t(etService).length() != 3) etService.setText(hints[2]);
        }
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
        if (pan.length() < 12 || pan.length() > 19) {
            Toast.makeText(this, "PAN must be 12-19 digits, this is " + pan.length(),
                    Toast.LENGTH_LONG).show();
            return;
        }
        if (!luhn(pan)) {
            String want = String.valueOf(expectedCheckDigit(pan));
            String msg = "PAN fails its check digit - the last digit should be " + want + ".";
            status(msg);
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
            showPage(0);
            return;
        }
        if (t(etExpiry).length() != 4) {
            Toast.makeText(this, "Expiry must be YYMM, e.g. 2803", Toast.LENGTH_LONG).show();
            return;
        }
        etPan.setText(pan);
        collect();
        adapter.notifyItemChanged(current);

        status("Saved card " + (current + 1) + " of " + cards.size()
                + " - script " + effectiveProfile());
        Toast.makeText(this, "Card saved", Toast.LENGTH_SHORT).show();
        showPage(0);
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

    private void onDelete() {
        if (cards.isEmpty()) return;
        final int victim = current;
        new AlertDialog.Builder(this)
                .setTitle("Delete card " + (victim + 1) + "?")
                .setMessage("This cannot be undone.")
                .setPositiveButton("Delete", (d, w) -> doDelete(victim))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void doDelete(int index) {
        SharedPreferences.Editor e = prefs.edit();
        int n = Math.min(prefs.getInt("card_count", 0), MAX_CARDS);
        if (n <= 0) return;

        String victim = key(index, "");
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(victim)) e.remove(k);
        }

        for (int i = index; i < n - 1; i++) {
            String from = key(i + 1, "");
            String to = key(i, "");
            for (String k : prefs.getAll().keySet()) {
                if (k.startsWith(to)) e.remove(k);
            }
            copyBlock(e, from, to);
        }

        String last = key(n - 1, "");
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(last)) e.remove(k);
        }

        e.putInt("card_count", n - 1);
        e.putInt("selected", Math.max(0, Math.min(index, n - 2)));
        e.apply();

        cards.clear();
        loadAll();
        current = Math.max(0, Math.min(index, cards.size() - 1));
        bindCard(current);
        status("Card deleted - " + cards.size() + " left");
        showPage(0);
    }

    private void copyBlock(SharedPreferences.Editor e, String from, String to) {
        for (Map.Entry<String, ?> en : prefs.getAll().entrySet()) {
            String k = en.getKey();
            if (!k.startsWith(from)) continue;
            String nk = to + k.substring(from.length());
            Object v = en.getValue();
            if (v instanceof Integer) e.putInt(nk, (Integer) v);
            else if (v instanceof Boolean) e.putBoolean(nk, (Boolean) v);
            else if (v instanceof Long) e.putLong(nk, (Long) v);
            else if (v instanceof Float) e.putFloat(nk, (Float) v);
            else if (v != null) e.putString(nk, v.toString());
        }
    }

    private static boolean luhn(String s) {
        return Luhn.valid(s);
    }

    // ---------- payment role ----------

    private void claimPaymentRole() {
        try {
            NfcManager mgr = (NfcManager) getSystemService(NFC_SERVICE);
            NfcAdapter nfc = mgr == null ? null : mgr.getDefaultAdapter();
            if (nfc == null) return;
            CardEmulation ce = CardEmulation.getInstance(nfc);
            ce.setPreferredService(this, new ComponentName(this, ShadowApduService.class));
        } catch (Throwable ignored) { }
    }

    private void releasePaymentRole() {
        try {
            NfcManager mgr = (NfcManager) getSystemService(NFC_SERVICE);
            NfcAdapter nfc = mgr == null ? null : mgr.getDefaultAdapter();
            if (nfc == null) return;
            CardEmulation ce = CardEmulation.getInstance(nfc);
            ce.unsetPreferredService(this);
        } catch (Throwable ignored) { }
    }

    private boolean isDefaultPayment() {
        try {
            NfcManager mgr = (NfcManager) getSystemService(NFC_SERVICE);
            NfcAdapter nfc = mgr == null ? null : mgr.getDefaultAdapter();
            if (nfc == null) return false;
            CardEmulation ce = CardEmulation.getInstance(nfc);
            return ce.isDefaultServiceForCategory(
                    new ComponentName(this, ShadowApduService.class),
                    CardEmulation.CATEGORY_PAYMENT);
        } catch (Throwable e) {
            return false;
        }
    }

    private void promptDefault() {
        try {
            Intent i = new Intent(CardEmulation.ACTION_CHANGE_DEFAULT);
            i.putExtra(CardEmulation.EXTRA_SERVICE_COMPONENT,
                    new ComponentName(this, ShadowApduService.class));
            i.putExtra(CardEmulation.EXTRA_CATEGORY, CardEmulation.CATEGORY_PAYMENT);
            startActivity(i);
        } catch (ActivityNotFoundException e) {
            try {
                startActivity(new Intent(Settings.ACTION_NFC_PAYMENT_SETTINGS));
            } catch (ActivityNotFoundException ignored) { }
        }
    }

    private void maybeAskDefault() {
        boolean isDefault = isDefaultPayment();

        if (banner != null) {
            boolean nfcOff = false;
            try {
                NfcManager mgr = (NfcManager) getSystemService(NFC_SERVICE);
                NfcAdapter nfc = mgr == null ? null : mgr.getDefaultAdapter();
                nfcOff = (nfc == null || !nfc.isEnabled());
            } catch (Throwable ignored) { }

            banner.setText(nfcOff ? R.string.nfc_off : R.string.become_default);
            banner.setVisibility(isDefault ? View.GONE : View.VISIBLE);
        }

        if (isDefault) return;
        if (prefs.getBoolean(ASKED_DEFAULT, false)) return;
        prefs.edit().putBoolean(ASKED_DEFAULT, true).apply();
        promptDefault();
    }

    @Override
    protected void onPause() {
        releasePaymentRole();
        super.onPause();
        collect();
    }

    @Override
    protected void onResume() {
        super.onResume();
        claimPaymentRole();
        maybeAskDefault();
        if (suppressResumeStatus) {
            suppressResumeStatus = false;
            return;
        }
        showLastVerdict();
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
        etAfl.setText("");
        etCid.setText("");
        etScript.setText("");
        appliedProfile = profileFor(pan);
        binding = false;

        collect();
        prefs.edit().putString(key(current, "psn"), psn.isEmpty() ? "01" : psn).apply();

        copyStagingToCard(current);

        // A read that captured no records still has the DD: arm the card from it
        // rather than leaving something the terminal will 6A83 on.
        if (recordCountOnCard() == 0 && !track2.isEmpty()) {
            armMsdCard(pan, expiry, service, disc);
        }

        binding = true;
        etMsd.setText(String.valueOf(msdFromCapture(current)));
        binding = false;
        collect();

        adapter.notifyItemChanged(current);
        pager.smoothScrollToPosition(current);
        prefs.edit().putInt("selected", current).apply();

        int recs = recordCountOnCard();
        status(recs == 0
                ? "Cloned - no records, terminal will get a synthetic one"
                : "Cloned " + recs + " records - check it, then SAVE");
        suppressResumeStatus = true;

        Toast.makeText(this, "Card cloned - review, then hit SAVE", Toast.LENGTH_LONG).show();
        showPage(1);

        if (!prefs.getString(key(current, "cap_genaccmd"), "").isEmpty()
                && !prefs.getString(key(current, "cap_rawgenac"), "").isEmpty()) {
            scanForKey(false);
        }
    }

    private int msdFromCapture(int index) {
        String gpo = prefs.getString(key(index, "cap_rawgpo"), "");
        if (gpo.isEmpty()) gpo = prefs.getString("cap_rawgpo", "");
        if (gpo.length() < 2) return 1;
        try {
            return (Integer.parseInt(gpo.substring(0, 2), 16) == 0x80) ? 1 : 0;
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    private int recordCountOnCard() {
        int n = 0;
        String p = key(current, "cap_rec");
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(p)) n++;
        }
        return n;
    }

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

    private static String nextAtc(String hexAtc) {
        try {
            int v = Integer.parseInt(hexAtc.replaceAll("[^0-9A-Fa-f]", ""), 16);
            return String.format("%04X", (v + 1) & 0xFFFF);
        } catch (Exception e) {
            return "001B";
        }
    }

    private void copyStagingToCard(int index) {
        SharedPreferences.Editor e = prefs.edit();
        String dst = key(index, "cap_");

        List<String> stale = new ArrayList<>();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(dst)) stale.add(k);
        }
        for (String k : stale) e.remove(k);

        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith("cap_")) {
                e.putString(dst + k.substring(4), prefs.getString(k, ""));
            }
        }

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
        while (s.startsWith("B")) s = s.substring(1);
        while (s.endsWith("F")) s = s.substring(0, s.length() - 1);
        return s;
    }

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
