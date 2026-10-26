package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Handler;
import android.os.Looper;
import android.util.LruCache;
import android.widget.ImageView;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Loads a real brand logo into an ImageView.
 *
 * Icons come from the Iconify API, which serves the Simple Icons artwork
 * (CC0 licence, free for commercial use) rasterised to PNG on the fly.
 *
 * icon        = "prefix/slug", e.g. "simple-icons/visa", "logos/capital-one"
 * heightPx    = rendered pixel height, width follows the aspect ratio
 * tintHexOrNull = 6 hex chars with no '#', e.g. "FFFFFF" for a white logo.
 *                 Pass null to keep the brand's own colours.
 *
 * Nothing is bundled: if the phone is offline the view is left blank and the
 * bank name text still carries the card. Results are cached in memory so each
 * logo is fetched at most once per app run.
 */
public final class LogoLoader {

    private static final String BASE = "https://api.iconify.design/";
    private static final int TIMEOUT_MS = 6000;

    /** Key is "icon|height|tint" so the same logo at two sizes caches separately. */
    private static final LruCache<String, Bitmap> CACHE = new LruCache<>(64);

    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private LogoLoader() {
    }

    public static void into(final ImageView view, final String icon,
                            final int heightPx, final String tintHexOrNull) {
        if (view == null || icon == null || icon.isEmpty() || heightPx <= 0) return;

        final String key = icon + "|" + heightPx + "|" + (tintHexOrNull == null ? "-" : tintHexOrNull);

        // Tag guard: RecyclerView recycles views, so by the time a fetch returns
        // this ImageView may already have been rebound to a different card.
        view.setTag(key);

        Bitmap cached = CACHE.get(key);
        if (cached != null) {
            view.setImageBitmap(cached);
            return;
        }

        view.setImageDrawable(null);

        new Thread(new Runnable() {
            @Override
            public void run() {
                final Bitmap bmp = fetch(icon, heightPx, tintHexOrNull);
                if (bmp == null) return;            // offline or unknown slug: stay blank
                CACHE.put(key, bmp);
                MAIN.post(new Runnable() {
                    @Override
                    public void run() {
                        if (key.equals(view.getTag())) view.setImageBitmap(bmp);
                    }
                });
            }
        }, "logo-" + icon).start();
    }

    private static Bitmap fetch(String icon, int heightPx, String tintHexOrNull) {
        HttpURLConnection conn = null;
        try {
            String url = BASE + icon + ".png?height=" + heightPx
                    + (tintHexOrNull == null ? "" : "&color=%23" + tintHexOrNull);

            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setInstanceFollowRedirects(true);

            try (InputStream in = conn.getInputStream()) {
                return BitmapFactory.decodeStream(in);
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** Call if you ever want to force a re-fetch, e.g. after a settings change. */
    public static void clearCache() {
        CACHE.evictAll();
    }
}
