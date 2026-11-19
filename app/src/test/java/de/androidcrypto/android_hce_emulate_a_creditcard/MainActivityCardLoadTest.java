package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.os.Looper;
import android.widget.EditText;

import org.junit.Before;
import org.junit.Test;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.junit.runner.RunWith;

/**
 * LoadedCard merged into the per-slot EDIT screen - a track 2 or a block
 * typed into TRACK 2 RAW HEX (etTrack2) becomes the selected card record,
 * the same fields and tile every hand-typed card uses. See
 * MainActivity.applyCardBlock()'s and LoadedCard's class docs; this
 * replaces what used to be a separate "Load card" dialog/store.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MainActivityCardLoadTest {

    private MainActivity activity;
    private EditText etTrack2, etPan, etExpiry, etService, etDiscretionary,
            etAid, etAip, etAfl, etCid, etAtc;

    @Before
    public void setUp() {
        Prefs.reset(RuntimeEnvironment.getApplication());
        activity = Robolectric.buildActivity(MainActivity.class).create().start().resume().get();
        shadowOf(Looper.getMainLooper()).idle();

        etTrack2 = activity.findViewById(R.id.etTrack2);
        etPan = activity.findViewById(R.id.etPan);
        etExpiry = activity.findViewById(R.id.etExpiry);
        etService = activity.findViewById(R.id.etService);
        etDiscretionary = activity.findViewById(R.id.etDiscretionary);
        etAid = activity.findViewById(R.id.etAid);
        etAip = activity.findViewById(R.id.etAip);
        etAfl = activity.findViewById(R.id.etAfl);
        etCid = activity.findViewById(R.id.etCid);
        etAtc = activity.findViewById(R.id.etAtc);
    }

    /**
     * MainActivity now debounces the track2/PAN filler 250ms (see
     * FILLER_TOKEN) - idle() alone only runs what is already due at the
     * current virtual time, so it never fires a postDelayed(..., 250).
     * idleFor() advances the clock past the debounce window first.
     */
    private void type(EditText field, String text) {
        field.setText(text);
        shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofMillis(300));
    }

    /** The task's own test: pasting a track 2 into the editor fills PAN/expiry/SC/discretionary. */
    @Test
    public void bareTrack2_fillsPanExpiryServiceCodeAndDiscretionary() {
        type(etTrack2, "5555555555554444=29122015678");

        assertEquals("5555555555554444", etPan.getText().toString());
        assertEquals("2912", etExpiry.getText().toString());
        assertEquals("201", etService.getText().toString());
        assertEquals("5678", etDiscretionary.getText().toString());
    }

    /**
     * A block's own AID/AIP/AFL/CID/ATC win over applyProfile()'s hand-typed
     * network defaults (Mastercard's own default AIP is 1880, not this
     * block's 5800) - "1880/auto is the hand-typed default, not the card's."
     */
    @Test
    public void block_aidAipAflCidAtcComeFromTheCardNotTheDefaults() {
        String block = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=08010100\n"
                + "9F27=80\n"
                + "9F36=0005\n";
        type(etTrack2, block);

        assertEquals("5555555555554444", etPan.getText().toString());
        assertEquals("2912", etExpiry.getText().toString());
        assertEquals("A0000000049999", etAid.getText().toString().toUpperCase());
        assertEquals("5800", etAip.getText().toString().toUpperCase());
        assertEquals("08010100", etAfl.getText().toString().toUpperCase());
        assertEquals("80", etCid.getText().toString().toUpperCase());
        assertEquals("0005", etAtc.getText().toString().toUpperCase());

        // No chain, no ICC key in this block - the tile must say so.
        CardAdapter.CardModel c = activity.cardAt(activity.currentSlot());
        assertTrue("certWarning must name the missing chain: " + c.certWarning,
                c.certWarning.contains("9F46") && c.certWarning.contains("ICCKEY"));
    }

    /**
     * The other half of the guard the test above does not touch: once the
     * user has hand-edited etAfl, a SECOND card block (same PAN/network,
     * different 94) must not clobber that typed value. Only applyCardBlock()
     * reads aflDirty/aipDirty (MainActivity.java ~1178) - this is the one
     * test that actually exercises the guard, not just its absence.
     */
    @Test
    public void typedAflSurvives_aSecondCardBlockOnTheSamePan() {
        String block1 = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=08010100\n"
                + "9F27=80\n"
                + "9F36=0005\n";
        type(etTrack2, block1);
        assertEquals("08010100", etAfl.getText().toString().toUpperCase());

        type(etAfl, "DEADBEEF");

        String block2 = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=10020200\n"
                + "9F27=80\n"
                + "9F36=0006\n";
        type(etTrack2, block2);

        assertEquals("the user's typed AFL must survive the second block",
                "DEADBEEF", etAfl.getText().toString().toUpperCase());
    }

    /**
     * A card block with a DIFFERENT PAN is a different card - the typed AFL
     * must NOT survive this time, unlike the same-PAN case above. The PAN
     * compare runs before etPan is overwritten (MainActivity.java, right
     * before applyCardBlock()'s own binding=true block).
     */
    @Test
    public void typedAflIsResetByACardBlockOnADifferentPan() {
        String block1 = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=08010100\n"
                + "9F27=80\n"
                + "9F36=0005\n";
        type(etTrack2, block1);
        assertEquals("08010100", etAfl.getText().toString().toUpperCase());

        type(etAfl, "DEADBEEF");

        String block2 = "5A=5555555555557777\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=10020200\n"
                + "9F27=80\n"
                + "9F36=0006\n";
        type(etTrack2, block2);

        assertEquals("a different PAN's own AFL must win - the old typed value is stale",
                "10020200", etAfl.getText().toString().toUpperCase());
    }

    /**
     * applyDump()'s bare-track2 path (MainActivity.java ~1049) has no guard
     * at all - a bare track 2 carries no AFL, so it always clears the box
     * and resets aflDirty, even over a value the user just typed. Proves
     * that reset is unconditional, the opposite of applyCardBlock()'s.
     */
    @Test
    public void aDirtyAflIsStillClearedByABareTrack2() {
        String block = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=08010100\n"
                + "9F27=80\n"
                + "9F36=0005\n";
        type(etTrack2, block);

        type(etAfl, "DEADBEEF");
        assertEquals("DEADBEEF", etAfl.getText().toString().toUpperCase());

        type(etTrack2, "5555555555554444=29122015678");

        assertEquals("a bare track 2 always clears the AFL box, dirty or not",
                "", etAfl.getText().toString());
    }

    /** The task's own test: the tile shows the card after save. */
    @Test
    public void tileShowsTheCardAfterSave() {
        String block = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=08010100\n"
                + "9F27=80\n"
                + "9F36=0005\n";
        type(etTrack2, block);

        activity.findViewById(R.id.btnSave).performClick();
        shadowOf(Looper.getMainLooper()).idle();

        CardAdapter.CardModel c = activity.cardAt(activity.currentSlot());
        assertEquals("5555555555554444", c.pan);
        assertEquals("A0000000049999", c.aid.toUpperCase());
        assertTrue(c.certWarning.contains("9F46"));
    }

    /** The task's own test: taps serve it. */
    @Test
    public void tapsServeTheSavedCard() {
        String block = "5A=5555555555554444\n"
                + "5F24=291231\n"
                + "84=A0000000049999\n"
                + "82=5800\n"
                + "94=08010100\n"
                + "9F27=80\n"
                + "9F36=0005\n";
        type(etTrack2, block);
        activity.findViewById(R.id.btnSave).performClick();
        shadowOf(Looper.getMainLooper()).idle();

        ShadowApduService svc = Robolectric.buildService(ShadowApduService.class).create().get();

        String ppse = Hex.toHex(svc.processCommandApdu(
                Hex.hex("00A404000E325041592E5359532E4444463031"), null));
        assertTrue("PPSE must list the saved AID: " + ppse, ppse.contains("4F07A0000000049999"));
        assertTrue(ppse.endsWith("9000"));

        String fci = Hex.toHex(svc.processCommandApdu(Hex.hex("00A4040007A0000000049999"), null));
        assertFalse("SELECT must not 6A82 the saved AID: " + fci, fci.endsWith("6A82"));
        assertTrue(fci.endsWith("9000"));

        String gpo = Hex.toHex(svc.processCommandApdu(Hex.hex("80A8000002830000"), null));
        assertFalse("GPO must not refuse: " + gpo, gpo.endsWith("6985"));
        assertTrue(gpo.endsWith("9000"));
        // The saved AIP was 5800 - SDA (0x40) set. This engine has no cert
        // chain and no CA key (that is AssetCardEngine/DumpChain's job, a
        // separate engine this one never touches), so F01's fix clears the
        // ODA bits here same as the captured-replay branch already did:
        // 0x58 & ~0x65 = 0x18, then F02 ORs in Emv.AIP_CDCVM (0x02) -> 0x1A.
        // Still distinct from the profile default 1880 in both bytes, so
        // this still proves the saved AIP (minus the claims this engine
        // cannot back), not a fallback to the default.
        assertTrue("GPO must answer with the saved AIP minus its ODA bits, not the profile default 1880: " + gpo,
                gpo.contains("82021A00"));
    }
}
