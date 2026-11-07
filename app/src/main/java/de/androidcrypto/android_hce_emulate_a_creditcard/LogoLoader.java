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
 * Loads a logo into an ImageView.
 *
 * source is EITHER a full URL ("https://logo.clearbit.com/chase.com")
 * OR an Iconify slug ("simple-icons/visa").
 * heightPx is pixels. tintHexOrNull only applies to Iconify slugs.
 */
public final class LogoLoader {

    private static final String ICONIFY = "https://api.iconify.design/";
    private static final int TIMEOUT_MS = 6000;

    private static final LruCache<String, Bitmap> CACHE = new LruCache<>(96);
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private LogoLoader() {
    }

    public static void into(final ImageView view, final String source,
                            final int heightPx, final String tintHexOrNull) {
        if (view == null || source == null || source.isEmpty() || heightPx <= 0) {
            if (view != null) view.setImageDrawable(null);
            return;
        }

        final String key = source + "|" + heightPx + "|" + (tintHexOrNull == null ? "-" : tintHexOrNull);
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
                final Bitmap bmp = fetch(source, heightPx, tintHexOrNull);
                if (bmp == null) return;
                CACHE.put(key, bmp);
                MAIN.post(new Runnable() {
                    @Override
                    public void run() {
                        if (key.equals(view.getTag())) view.setImageBitmap(bmp);
                    }
                });
            }
        }, "logo").start();
    }

    private static Bitmap fetch(String source, int heightPx, String tint) {
        Bitmap b = tryFetch(urlFor(source, heightPx, tint));
        if (b == null && source.startsWith("http")) b = tryFetch(favicon(source));
        return b;
    }

    private static String urlFor(String source, int heightPx, String tint) {
        if (source.startsWith("http")) return source;
        return ICONIFY + source + ".png?height=" + heightPx
                + (tint == null ? "" : "&color=%23" + tint);
    }

    /** Last-resort: the site's own favicon. Always available, never rate limited. */
    private static String favicon(String url) {
        String d = url.replaceFirst("^https?://", "").replaceFirst("^www\\.", "");
        int slash = d.indexOf('/');
        if (slash > 0) d = d.substring(0, slash);
        return "https://www.google.com/s2/favicons?domain=" + d + "&sz=128";
    }

    private static Bitmap tryFetch(String url) {
        HttpURLConnection conn = null;
        try {
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

    public static void clearCache() {
        CACHE.evictAll();
    }
}
