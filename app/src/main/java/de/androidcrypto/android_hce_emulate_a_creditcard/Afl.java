package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * The one AFL walk shared by every class that has to parse a REAL,
 * genuinely multi-entry tag 94 - DumpChain.parse() (validation and record
 * attribution), AssetCardEngine.readRecord() (the "is this record named"
 * gate) and OdaVerifier.buildStaticData() (the ODA record-and-count walk).
 *
 * A normal AFL is nothing but a run of 4-byte entries (SFI/first/last/
 * ODA-count), and i+4 is always the next one. But a real dump's AFL can
 * also carry a trailing, length-prefixed AID list after its last real
 * entry - the same non-spec shape ShadowApduService's
 * AFL_MC_PROBE_WITH_AID/aflContains() use (see that method's own doc) - so
 * the 4 bytes right after an entry are checked before being trusted as
 * another one: a real AFL entry always has last >= first (every caller
 * above already rejects any entry where that is not true), so when the 4
 * bytes at i+4 fail that test, or there are not even 4 of them left, they
 * are not a second entry at all - they are one length byte plus that many
 * bytes of appended AID data to skip instead.
 *
 * aflContains() does not go through this: its one caller (the Mastercard
 * GPO probe) always has exactly one real entry, so there is never a
 * genuine second entry to mistake the AID list for, and a dedicated,
 * simpler skip is enough there. The three callers here are not that
 * constrained - they walk real, multi-entry AFLs (profile.json's own
 * three entries, among others) - so this class's extra validity check is
 * required, not optional, and is applied the same way, unconditionally,
 * every time: there is no caller-specific variant of this walk.
 */
final class Afl {

    private Afl() { }

    /**
     * The index of the next AFL entry after the 4-byte one starting at
     * {@code i}.
     */
    static int afterEntry(byte[] afl, int i) {
        int next = i + 4;
        if (next + 4 <= afl.length) {
            int first = afl[next + 1] & 0xFF;
            int last = afl[next + 2] & 0xFF;
            if (last >= first) return next; // looks like a real entry - let the walk read it as one
        }
        if (next < afl.length) {
            int len = afl[next] & 0xFF;
            next += 1 + len;
        }
        return next;
    }

    /**
     * True when the AFL is a run of valid 4-byte entries - each optionally
     * followed by one appended field, see {@link #afterEntry} - that lands
     * exactly on the AFL's own end. Anything that overruns or falls short
     * is malformed.
     */
    static boolean wellFormed(byte[] afl) {
        int i = 0;
        while (i < afl.length) {
            if (i + 4 > afl.length) return false;
            i = afterEntry(afl, i);
        }
        return true;
    }
}
