package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;

/**
 * The one AssetCardEngine for the whole process.
 *
 * ShadowApduService and MainActivity are two components of the same app, in
 * the same process - ShadowApduService carries no android:process in the
 * manifest. A dump MainActivity loads has to land on the SAME instance the
 * service answers taps from, or loadDump() runs against a card nobody ever
 * serves. This replaces what used to be a service-private lazy field
 * (private AssetCardEngine assetCard in ShadowApduService).
 *
 * Still lazy, still built once: the asset read and the ATC restore only
 * have to happen for whichever caller - service or activity - reaches here
 * first.
 */
final class AssetCardHolder {

    /** Same key ShadowApduService.assetCard() used for its own field. */
    private static final String PREF_ASSET_ATC = "asset_atc";

    private static AssetCardEngine instance;

    private AssetCardHolder() { }

    /**
     * Test-only: drop the shared instance so the next get() builds a fresh
     * one. A real process never calls this - the whole point of this class
     * is that the instance outlives any one component - but a test method
     * simulating "a fresh process" needs the same reset Prefs.reset()
     * already gives its own static cache, or state (the ATC, a loaded dump)
     * leaks from one test into the next.
     */
    static synchronized void reset() {
        instance = null;
    }

    static synchronized AssetCardEngine get(Context ctx) throws IOException {
        if (instance == null) {
            Context app = ctx.getApplicationContext();
            try (InputStream in = app.getAssets().open(AssetCardEngine.ASSET);
                 InputStream key = app.getAssets().open(AssetCardEngine.ICC_KEY_ASSET)) {
                instance = AssetCardEngine.load(in, key);
            }
            String saved = Prefs.get(app).getString(PREF_ASSET_ATC, "");
            if (saved.length() == 4) {
                instance.setAtc(Integer.parseInt(saved, 16));
            }
        }
        return instance;
    }
}
