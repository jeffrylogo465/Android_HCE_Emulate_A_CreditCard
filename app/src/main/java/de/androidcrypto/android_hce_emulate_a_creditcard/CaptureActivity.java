package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Arrays;
import java.util.TreeSet;

/**
 * Shows what the SELECTED card will serve a terminal, and what was captured
 * for it.
 *
 * FIX: this screen used to read BARE cap_* keys. But MainActivity's
 * copyStagingToCard() moves the reader's bare cap_* into card<N>_cap_* and then
 * DELETES the bare ones - so the moment a clone succeeded, this screen said
 * "No capture stored". It also asked for cap_rawppse / cap_pan / cap_expiry /
 * cap_service / cap_track2 / cap_discretionary, none of which the reader ever
 * stages. It now reads the card-prefixed keys, and shows the six card fields
 * from the card record instead of six phantom cap_ fields.
 */
public class CaptureActivity extends Activity {

    private SharedPreferences prefs;
    private TextView txtInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_capture);
        prefs = getSharedPreferences("hce_card", MODE_PRIVATE);
        txtInfo = (TextView) findViewById(R.id.txtCapture);

        findViewById(R.id.btnCapBack).setOnClickListener(v -> finish());

        findViewById(R.id.btnCapCopy).setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("capture", build()));
            Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
        });

        findViewById(R.id.btnCapClear).setOnClickListener(v -> {
            String p = prefix();
            SharedPreferences.Editor e = prefs.edit();
            for (String k : prefs.getAll().keySet()) {
                if (k.startsWith(p)) e.remove(k);
            }
            e.apply();
            Toast.makeText(this, "Cleared this card's capture", Toast.LENGTH_SHORT).show();
            txtInfo.setText(build());
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (txtInfo != null) txtInfo.setText(build());
    }

    /** The capture lives under card<N>_cap_*, matching what the service reads. */
    private String prefix() {
        return "card" + prefs.getInt("selected", 0) + "_cap_";
    }

    private String cap(String key) {
        return prefs.getString(prefix() + key, "");
    }

    private String card(String key, String def) {
        String v = prefs.getString("card" + prefs.getInt("selected", 0) + "_" + key, def);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static String dash(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    private static String bytes(String hex) {
        return hex.length() / 2 + " bytes";
    }

    private String build() {
        int idx = prefs.getInt("selected", 0);
        String p = prefix();

        String fci    = cap("rawfci");
        String gpo    = cap("rawgpo");
        String genac  = cap("rawgenac");
        String gcmd   = cap("genaccmd");
        String aid    = cap("aid");
        String label  = cap("label");
        String holder = cap("holder");

        TreeSet<String> recKeys = new TreeSet<>();
        for (String k : prefs.getAll().keySet()) {
            if (k.startsWith(p + "rec")) recKeys.add(k.substring(p.length()));
        }

        StringBuilder sb = new StringBuilder();

        sb.append("CARD ").append(idx + 1)
          .append(" of ").append(Math.max(1, prefs.getInt("card_count", 1)))
          .append("   (the selected one)\n\n");

        if (fci.isEmpty() && gpo.isEmpty() && recKeys.isEmpty()) {
            sb.append("No capture on this card.\n\n")
              .append("Open READ CARD and read a physical card. The capture lands on\n")
              .append("whichever card is selected, and this screen then shows exactly\n")
              .append("what a terminal would get from it.\n\n")
              .append("A hand-typed card with no capture still works - the service\n")
              .append("falls back to a synthetic record and a built GPO.\n");
        }

        sb.append("-- what the service will serve --\n");
        sb.append("AID     : ").append(dash(aid.isEmpty() ? card("aid", "") : aid)).append('\n');
        sb.append("LABEL   : ").append(dash(label.isEmpty() ? card("label", "") : label)).append('\n');
        sb.append("HOLDER  : ").append(dash(holder.isEmpty() ? card("name", "") : holder)).append('\n');
        sb.append("PAN     : ").append(dash(card("pan", ""))).append('\n');
        sb.append("EXPIRY  : ").append(dash(card("expiry", ""))).append('\n');
        sb.append("SERVICE : ").append(dash(card("service", ""))).append('\n');
        sb.append("TRACK2  : ").append(dash(card("track2", ""))).append('\n');
        sb.append("PSN     : ").append(dash(card("psn", ""))).append('\n');
        sb.append("MSD     : ").append(card("msd", "0"))
          .append("0".equals(card("msd", "0")) ? "  EMV mode - records + cryptogram" : "  magstripe - track 2 only")
          .append('\n');
        sb.append("CID     : ").append(card("cid", "").isEmpty()
                ? "(empty - logic decides: TC offline, ARQC if a key is set)"
                : card("cid", "") + "  (FORCED)").append('\n');
        sb.append("MK-AC   : ").append(card("mkac", "").isEmpty() ? "-  cryptogram will be zeros" : "set").append('\n');

        sb.append("\n-- capture on this card --\n");
        if (fci.isEmpty() && gpo.isEmpty() && recKeys.isEmpty()) {
            sb.append("(nothing captured)\n");
            return sb.toString();
        }

        sb.append("FCI          ").append(fci.isEmpty() ? "(none - FCI is generated)" : "(" + bytes(fci) + ")").append('\n');
        if (!fci.isEmpty()) sb.append(fci).append("\n\n");

        sb.append("GPO          ").append(gpo.isEmpty() ? "(none - GPO is built)" : "(" + bytes(gpo) + ")").append('\n');
        String aip = aipFromGpo(gpo);
        if (!aip.isEmpty()) {
            sb.append("  AIP in that GPO: ").append(aip)
              .append("   (CDA bit is dropped on the wire)\n");
        }
        if (!gpo.isEmpty()) sb.append(gpo).append("\n\n");

        sb.append("GEN AC CMD   ").append(gcmd.isEmpty() ? "-" : "(" + bytes(gcmd) + ")").append('\n');
        if (!gcmd.isEmpty()) sb.append(gcmd).append("\n\n");

        sb.append("GEN AC RSP   ").append(genac.isEmpty() ? "-" : "(" + bytes(genac) + ")").append('\n');
        if (!genac.isEmpty()) sb.append(genac).append("\n\n");

        sb.append("RECORDS STORED: ").append(recKeys.size()).append('\n');
        if (recKeys.isEmpty()) {
            sb.append("  none - the service will serve a synthetic SFI 1 record\n");
        } else {
            sb.append("  keys: ");
            for (String k : recKeys) sb.append(k).append(' ');
            sb.append('\n');
            if (recKeys.size() < 3) {
                sb.append("  only ").append(recKeys.size())
                  .append(" - a short AFL means the terminal reads little\n");
            }
        }
        return sb.toString();
    }

    // ---------- tiny TLV walk, just for the AIP display ----------

    private static int readTag(byte[] b, int[] pos) {
        if (pos[0] >= b.length) return 0;
        int t = b[pos[0]++] & 0xFF;
        if ((t & 0x1F) == 0x1F) {
            if (pos[0] >= b.length) return t;
            t = (t << 8) | (b[pos[0]++] & 0xFF);
        }
        return t;
    }

    private static int readLen(byte[] b, int[] pos) {
        if (pos[0] >= b.length) return 0;
        int l = b[pos[0]++] & 0xFF;
        if ((l & 0x80) != 0) {
            int n = l & 0x7F, v = 0;
            for (int k = 0; k < n && pos[0] < b.length; k++) v = (v << 8) | (b[pos[0]++] & 0xFF);
            return v;
        }
        return l;
    }

    /** Format 1 (0x80) carries the AIP bare; format 2 (0x77) as tag 82. */
    private static String aipFromGpo(String gpoHex) {
        if (gpoHex == null || gpoHex.isEmpty()) return "";
        byte[] d = Hex.hex(gpoHex);
        if (d.length < 4) return "";
        int[] pos = new int[1];
        int outer = readTag(d, pos);
        if (outer == 0x80) {
            readLen(d, pos);
            return pos[0] + 2 <= d.length
                    ? Hex.toHex(Arrays.copyOfRange(d, pos[0], pos[0] + 2)) : "";
        }
        int len = readLen(d, pos);
        int end = Math.min(d.length, pos[0] + len);
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(d, q);
            int l = readLen(d, q);
            if (q[0] + l > d.length) break;
            if (t == 0x82 && l >= 2) return Hex.toHex(Arrays.copyOfRange(d, q[0], q[0] + 2));
            i = q[0] + l;
        }
        return "";
    }
}
