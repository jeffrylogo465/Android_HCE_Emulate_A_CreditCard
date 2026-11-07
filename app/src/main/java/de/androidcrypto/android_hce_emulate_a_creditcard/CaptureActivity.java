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
 * Reads card<N>_cap_* - MainActivity.copyStagingToCard() moves bare cap_* into
 * the slot and deletes the bare ones, so bare keys are only a mid-read fallback.
 *
 * NEW in this revision: a READINESS block at the top. The screen used to list
 * the capture and leave you to work out whether it was usable. Every one of the
 * following silently costs you a tap, and none of them were visible:
 *
 *   - no captured PPSE (service generates a one-entry directory instead)
 *   - cap_aid not matching the card's own AID (terminal picks an applet we
 *     cannot serve, FCI falls to the generated branch)
 *   - GPO framing disagreeing with the MSD flag (the capture is thrown away and
 *     the built path runs)
 *   - no records at all (terminal gets one synthetic and 6A83 after it)
 *
 * The MSD line also used to throw: 'msd' is written with putInt and this screen
 * read it with getString, which SharedPreferences does not coerce.
 */
public class CaptureActivity extends Activity {

    public static final String EXTRA_CARD_INDEX = "card_index";

    /** Must match HceCcEmulationServiceVisa.TERM_LOG. */
    private static final String TERM_LOG = "term_log.txt";

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
                Toast.makeText(CaptureActivity.this, "Cleared capture and tap log", Toast.LENGTH_SHORT).show();
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

    /** Typed read. 'msd' is an int and getString on it throws. */
    private int getInt(String k, int def) {
        try {
            return prefs.getInt(slot + k, def);
        } catch (ClassCastException e) {
            return def;
        }
    }

    private void clear() {
        SharedPreferences.Editor e = prefs.edit();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(slot + "cap_") || k.startsWith("cap_")) e.remove(k);
        }
        e.apply();
        try {
            java.io.File f = new java.io.File(getExternalFilesDir(null), TERM_LOG);
            if (f.exists()) f.delete();
        } catch (Exception ignored) { }
    }

    private static String dash(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    private static String hexOnly(String s) {
        return s == null ? "" : s.toUpperCase().replaceAll("[^0-9A-F]", "");
    }

    private int countRecords() {
        int n = 0;
        String p = slot + "cap_rec";
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(p)) n++;
        }
        return n;
    }

    /** 61 entries in a directory FCI, i.e. how many applets it advertises. */
    private static int countApps(String ppse) {
        String h = hexOnly(ppse);
        if (h.length() < 8) return 0;
        byte[] d = new byte[h.length() / 2];
        for (int i = 0; i < d.length; i++) {
            d[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        // crude but adequate: count 61 tags that are followed by a plausible length
        int n = 0;
        for (int i = 0; i + 1 < d.length; i++) {
            if ((d[i] & 0xFF) == 0x61) {
                int l = d[i + 1] & 0xFF;
                if (l > 0 && l < 0x7F && i + 2 + l <= d.length) n++;
            }
        }
        return n;
    }

    /**
     * NEW. Every dependency the tap needs, with the missing ones counted.
     * Nothing here is guessed: it is read straight out of the slot.
     */
    private String readiness() {
        String ppse = hexOnly(get("cap_rawppse"));
        String gpo = hexOnly(get("cap_rawgpo"));
        String fci = hexOnly(get("cap_rawfci"));
        String capAid = get("cap_aid").toUpperCase();
        String cardAid = get("aid").toUpperCase();
        int msd = getInt("msd", 0);
        int recs = countRecords();

        StringBuilder sb = new StringBuilder();
        int bad = 0;

        if (ppse.isEmpty()) {
            sb.append("PPSE      : NONE - a one-entry directory will be GENERATED\n");
            bad++;
        } else {
            int n = countApps(ppse);
            sb.append("PPSE      : captured ").append(ppse.length() / 2)
              .append("B advertising ").append(n).append(" applet(s)\n");
            if (n == 0) bad++;
        }

        if (capAid.isEmpty()) {
            sb.append("CAP AID   : NONE - no captured applet, FCI will be generated\n");
            bad++;
        } else if (!cardAid.isEmpty() && !capAid.equalsIgnoreCase(cardAid)) {
            sb.append("CAP AID   : ").append(capAid).append("  but card AID is ")
              .append(cardAid).append("  <- MISMATCH\n");
            bad++;
        } else {
            sb.append("CAP AID   : ").append(capAid).append("  (matches the card)\n");
        }

        if (fci.isEmpty()) {
            sb.append("FCI       : NONE - generated fallback\n");
            bad++;
        } else {
            sb.append("FCI       : captured ").append(fci.length() / 2).append("B\n");
        }

        if (gpo.isEmpty()) {
            sb.append("GPO       : NONE - built path, so records are mandatory\n");
            bad++;
        } else {
            boolean capMsd = gpo.startsWith("80");
            sb.append("GPO       : captured ").append(gpo.length() / 2).append("B, framing ")
              .append(capMsd ? "80 (format 1 / MSD)" : gpo.startsWith("77")
                      ? "77 (format 2 / EMV)" : "?").append('\n');
            if (capMsd != (msd == 1)) {
                sb.append("MSD FIELD : ").append(msd)
                  .append("  <- MISMATCH, the capture will be THROWN AWAY and rebuilt\n");
                bad++;
            } else {
                sb.append("MSD FIELD : ").append(msd).append("  (agrees with the framing)\n");
            }
        }

        if (recs == 0) {
            sb.append("RECORDS   : NONE - terminal gets one synthetic and 6A83 after it\n");
            bad++;
        } else {
            sb.append("RECORDS   : ").append(recs).append(" captured\n");
        }

        String cid = get("cid").toUpperCase();
        if (cid.isEmpty()) {
            sb.append("CID       : empty - logic decides (")
              .append(get("mkac").isEmpty() ? "no key, so TC offline" : "key set, so ARQC online")
              .append(")\n");
        } else {
            sb.append("CID       : ").append(cid).append("  FORCED - overrides the logic\n");
        }

        sb.append('\n');
        sb.append(bad == 0
                ? "READY: nothing obvious missing.\n"
                : "NOT READY: " + bad + " problem(s) above.\n");
        return sb.toString();
    }

    /** Everything: readiness, the capture, then the terminal tap log. */
    private String build() {
        return readiness() + "\n---- raw capture ----\n" + buildCapture() + termLogSection();
    }

    private String buildCapture() {
        resolveSlot();

        String fci   = get("cap_rawfci");
        String gpo   = get("cap_rawgpo");
        String genac = get("cap_rawgenac");
        String ppse  = get("cap_rawppse");

        StringBuilder recKeys = new StringBuilder();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(slot + "cap_rec")) {
                recKeys.append(k.substring((slot + "cap_").length())).append(' ');
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SLOT: ").append(slot)
                .append("   (card ").append(cardIndex + 1)
                .append(" of ").append(prefs.getInt("card_count", 0)).append(')').append('\n');
        sb.append('\n');

        sb.append("LABEL: ").append(dash(get("label"))).append('\n');
        sb.append("PAN: ").append(dash(get("pan"))).append('\n');
        sb.append("EXPIRY: ").append(dash(get("expiry"))).append('\n');
        sb.append("SERVICE CODE: ").append(dash(get("service"))).append('\n');
        sb.append("NAME: ").append(dash(get("name"))).append('\n');
        sb.append("AID (editor): ").append(dash(get("aid"))).append('\n');
        sb.append("AIP (editor): ").append(dash(get("aip"))).append('\n');
        sb.append("MSD: ").append(getInt("msd", 0)).append('\n');
        sb.append("AFL: ").append(get("afl").isEmpty()
                ? "(empty - derived from the records)" : get("afl")).append('\n');
        sb.append("MK-AC set: ").append(get("mkac").isEmpty() ? "no" : "yes").append('\n');
        sb.append('\n');

        if (recKeys.length() > 0) sb.append("RECORD KEYS: ").append(recKeys).append('\n');
        sb.append("PPSE CAPTURED: ").append(ppse.isEmpty() ? "NO" : "yes (" + ppse.length() / 2 + "B)").append('\n');
        sb.append("GPO CAPTURED: ").append(gpo.isEmpty() ? "NO" : "yes (" + gpo.length() / 2 + "B)").append('\n');
        sb.append("FCI CAPTURED: ").append(fci.isEmpty() ? "NO" : "yes (" + fci.length() / 2 + "B)").append('\n');
        sb.append("GEN AC CAPTURED: ").append(genac.isEmpty() ? "NO" : "yes").append('\n');
        sb.append('\n');

        if (fci.isEmpty() && gpo.isEmpty() && ppse.isEmpty()) {
            sb.append("No capture in this slot.\n\n");
            sb.append("Open READ CARD and read a card - the capture lands in the slot\n");
            sb.append("that is selected in the wallet.\n");
            return sb.toString();
        }

        if (!ppse.isEmpty()) {
            sb.append("PPSE (").append(ppse.length() / 2).append(" bytes):\n").append(ppse).append("\n\n");
        }
        if (!fci.isEmpty()) {
            sb.append("FCI (").append(fci.length() / 2).append(" bytes):\n").append(fci).append("\n\n");
        }
        if (!gpo.isEmpty()) {
            sb.append("GPO (").append(gpo.length() / 2).append(" bytes):\n").append(gpo).append("\n\n");
        }
        if (!genac.isEmpty()) {
            sb.append("GENERATE AC (").append(genac.length() / 2).append(" bytes):\n").append(genac).append('\n');
        }
        return sb.toString();
    }

    /**
     * The tail of the terminal tap log - what a real till sent us and what we
     * answered. Capped at the last 8 KB so the TextView stays usable.
     */
    private String termLogSection() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n\n========================================\n");
        sb.append("TERMINAL TAP LOG  (last 8 KB)\n");
        sb.append(">> 80A8 = GPO    >> 00B2 = READ RECORD    >> 80AE = GENERATE AC\n");
        sb.append("If it stops after 80A8 there is no READ RECORD.\n");
        sb.append("The !! verdict line names where it quit.\n");
        sb.append("========================================\n\n");

        java.io.File f = new java.io.File(getExternalFilesDir(null), TERM_LOG);
        if (!f.exists() || f.length() == 0) {
            sb.append("(empty - tap a real terminal, then come back here)\n");
            return sb.toString();
        }

        try {
            long keep = Math.min(f.length(), 8192);
            byte[] buf = new byte[(int) keep];
            java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r");
            raf.seek(f.length() - keep);
            raf.readFully(buf);
            raf.close();

            if (f.length() > keep) sb.append("...(").append(f.length() - keep).append(" bytes trimmed)\n");
            sb.append(new String(buf, "UTF-8"));
        } catch (Exception e) {
            sb.append("could not read the log: ").append(e).append('\n');
        }
        return sb.toString();
    }
}
