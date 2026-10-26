package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Resolves an unknown BIN to its issuing bank. Free, no key.
 *
 * The free tier is rate limited, so each BIN is fetched at most once per
 * install and the result - including "not found" - is written to
 * SharedPreferences. Offline or rate limited just means it fills in later.
 */
public final class BinLookup {

    public static final class Info {
        public final String name;    // "JPMORGAN CHASE BANK, N.A."
        public final String domain;  // "chase.com" or null
        Info(String name, String domain) { this.name = name; this.domain = domain; }
    }

    public interface Callback { void onResult(String bin, Info info); }

    private static final String PREFS = "bin_cache";
    private static final String BINLIST = "https://lookup.binlist.net/%s";
    private static final String HANDY = "https://data.handyapi.com/bin/%s";

    private static final Set<String> IN_FLIGHT = Collections.synchronizedSet(new HashSet<String>());
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private BinLookup() {
    }

    /** Cached hit, or null. Does not touch the network. */
    public static Info cached(Context ctx, String pan) {
        String bin = bin(pan);
        if (bin == null) return null;
        String raw = prefs(ctx).getString(bin, null);
        if (raw == null || raw.isEmpty()) return null;
        String[] p = raw.split("\\|", 2);
        return new Info(p[0], p.length > 1 && !p[1].isEmpty() ? p[1] : null);
    }

    /** True once a lookup has been attempted, hit or miss. */
    public static boolean seen(Context ctx, String pan) {
        String bin = bin(pan);
        return bin != null && prefs(ctx).contains(bin);
    }

    public static void fetch(final Context ctx, final String pan, final Callback cb) {
        final String bin = bin(pan);
        if (bin == null || seen(ctx, pan) || !IN_FLIGHT.add(bin)) return;

        final Context app = ctx.getApplicationContext();
        new Thread(new Runnable() {
            @Override
            public void run() {
                Info info = query(String.format(BINLIST, bin));
                if (info == null) info = queryHandy(String.format(HANDY, bin));

                prefs(app).edit().putString(bin, info == null ? ""
                        : info.name + "|" + (info.domain == null ? "" : info.domain)).apply();
                IN_FLIGHT.remove(bin);

                final Info result = info;
                MAIN.post(new Runnable() {
                    @Override
                    public void run() { if (cb != null) cb.onResult(bin, result); }
                });
            }
        }, "bin-" + bin).start();
    }

    // ---------------------------------------------------------------- parsing

    private static Info query(String url) {
        try {
            JSONObject o = get(url);
            if (o == null) return null;
            JSONObject bank = o.optJSONObject("bank");
            if (bank == null) return null;
            String name = bank.optString("name", "").trim();
            if (name.isEmpty()) return null;
            return new Info(name.toUpperCase(Locale.US), cleanDomain(bank.optString("url", "")));
        } catch (Exception e) {
            return null;
        }
    }

    private static Info queryHandy(String url) {
        try {
            JSONObject o = get(url);
            if (o == null) return null;
            String name = o.optString("Issuer", "").trim();
            if (name.isEmpty()) name = o.optString("issuer", "").trim();
            if (name.isEmpty()) return null;
            return new Info(name.toUpperCase(Locale.US), null);
        } catch (Exception e) {
            return null;
        }
    }

    private static JSONObject get(String url) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(6000);
            conn.setReadTimeout(6000);
            conn.setRequestProperty("Accept", "application/json");
            conn.setInstanceFollowRedirects(true);
            if (conn.getResponseCode() != 200) return null;

            StringBuilder sb = new StringBuilder();
            try (InputStream in = conn.getInputStream();
                 BufferedReader r = new BufferedReader(new InputStreamReader(in))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line);
            }
            return new JSONObject(sb.toString());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String cleanDomain(String raw) {
        if (raw == null) return null;
        String d = raw.trim().replaceFirst("^https?://", "").replaceFirst("^www\\.", "");
        int slash = d.indexOf('/');
        if (slash > 0) d = d.substring(0, slash);
        return d.isEmpty() ? null : d;
    }

    private static String bin(String pan) {
        if (pan == null) return null;
        String d = pan.replaceAll("[^0-9]", "");
        return d.length() >= 6 ? d.substring(0, 6) : null;
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
