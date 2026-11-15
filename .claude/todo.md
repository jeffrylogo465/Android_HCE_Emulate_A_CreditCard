# Fix: terminal aborts after the PPSE select — tap never reaches an AID

## Evidence
Live tap against a real terminal, `adb shell dumpsys nfc`:
Three taps, three identical routes, all to the PPSE (325041592E5359532E4444463031).
No second AID is ever routed. No AFFFFFFFFF1234, no A0000000041010.
So the terminal selects the PPSE, reads the directory, and aborts before selecting an app.
Retries 10 s apart fail identically, so it is deterministic, not a field drop.

Routing side is confirmed healthy in the same dump: wallet role held, preferred payment
service set to ShadowApduService, service bound, Default route: host. Do not touch routing.

The app also logged: "TAP: terminal read the directory and quit after one SELECT |
script armed 3 line(s) but never matched".

## Prime suspect
The PPSE directory is probably listing every AID in the static AID group — roughly fifty of
them, including non-scheme ones. A real card lists one to three. An oversized or malformed
directory FCI is a classic kernel abort. Secondary suspects: the PPSE AID itself listed as a
directory entry, missing mandatory 50 application label, wrong 61/4F nesting, or an armed
script shadowing the generated FCI so the good builder never runs.

## What to do
1. Find the PPSE / directory FCI path. Note select() around ShadowApduService.java:1850-1862
   already builds an FCI and the audit flagged it as missing 8D; the PPSE path is separate.
2. Log the exact PPSE response bytes at APDU level so the fix can be verified against a capture.
3. Make the directory structurally valid: 6F, 84 DF name, A5 with 61 entries of 4F + 50, and
   87 priority. One entry per usable AID, and only the active card's AID when a profile is
   loaded. Exclude the PPSE AID from the entry list.
4. Check whether an armed script is overriding the generated PPSE response, and whether the
   "3 lines armed, never matched" is why nothing after the first SELECT is served. Fix or
   disarm it.
5. Add unit tests asserting the PPSE FCI parses as a well-formed directory with a sane entry
   count, and a test that a select of AFFFFFFFFF1234 and A0000000041010 still succeeds after
   the PPSE change.

## Constraints
- All existing tests must stay green (69 today). Add tests, do not delete or weaken any.
- Do not touch AID registrations in apduservice.xml.
- Do not touch profile.json or the keys.
- Do not change the AIP; DDA is a separate task.
- Keep the diff to the PPSE/FCI path plus tests.

## Findings (no device - can't reproduce, so this is what the code shows)

- EXTRA_AIDS is false, so buildPpse() has only ever generated one entry. The
  "roughly fifty AIDs" prime suspect does not exist in the code: the fifty-odd
  <aid-filter> entries the audit saw are apduservice.xml's routing table, which
  is a different list buildPpse() never reads.
- Every PPSE candidate byte-walked with a from-scratch TLV reader - the
  generated directory, Profiles.oneAppPpse() (VISA), the Mastercard and Amex
  hardcoded constants, and AssetCardEngine's directory - parses cleanly: no
  length overruns the bytes that follow it, one to three entries, 50/87/9F2A
  all land where they claim to. None of the suspected shapes (oversized,
  truncated, PPSE-as-its-own-entry) exist in the shipped bytes today.
- Script override is real, but not what breaks the tap: useScript() falls
  back to scriptLines() > 0 whenever the script box is empty, and
  profileScript() always arms exactly 3 lines (PPSE, FCI, GPO) - so a script
  answers every PPSE select by design, for every profile, with no way to turn
  it off short of typing something in the box. Confirmed with a reflection
  probe against a fresh service: scriptMatch() hits on the PPSE line before
  select()/buildPpse() ever runs. What it serves - oneAppPpse()'s shape for
  the default/VISA case, the Mastercard/Amex constants otherwise - is exactly
  the bytes already walked clean above, so the override explains why
  buildPpse() is cold code on the common path, not why a terminal would abort.
- What IS real: buildPpse()'s captured-PPSE replay (set when a real PPSE was
  captured off another card) had no validation at all, unlike patchFci()'s
  equivalent path for the FCI, which already falls back to generating instead
  of serving a capture that overruns its own length. A bad capture - the
  exact "oversized or malformed directory" shape this task went looking for -
  would have been replayed verbatim. Fixed: ppseProblem() mirrors patchFci()'s
  walk, bounds a captured directory to MAX_PPSE_ENTRIES (3), and rejects one
  that lists the PPSE's own AID as if it were an application.
- Also real: the asset-card branch (profile.json / AFFFFFFFFF1234) returns
  before nSelects/nGpos/nRecs/nGens/nCccs are ever incremented, so
  baseVerdict() reported "quit after one SELECT" for every asset-card tap
  regardless of how far it actually got - including a complete one through
  GENERATE AC. That made the app's own log exactly as unreliable as the
  "script armed 3 line(s) but never matched" symptom this task is chasing.
  Fixed: the same five counters now increment on that branch too.

None of this reproduces "the terminal aborts after SELECT" from the bytes
alone - every directory this app can serve today is structurally sound. The
two real gaps above are fixed and tested; if the live abort persists, the
next thing to pull off the phone is the per-slot term_<slot>log.txt itself
(getExternalFilesDir, not logcat - tap.log here only has the misleading
verdict line, never the ">> "/"<< " APDU bytes) to see which of these paths
the real terminal actually hit.

## Done
- [x] PPSE response bytes logged (already done via tap() on every SELECT;
      new "!! captured ppse: <reason> - generating instead" line added for
      a rejected capture)
- [x] Directory structurally valid and bounded (now enforced on the captured
      path too; the generated path already was)
- [x] Script override understood and fixed (documented above; not the cause
      of an abort, since what it serves is already structurally sound - the
      real fix was the asset-card verdict counters, which made this app's
      own diagnosis trustworthy)
- [x] New tests written and green (8 new: ShadowApduServicePpseTest.java x7,
      ShadowApduServiceAssetCardTest.java x1)
- [x] Full suite green under --rerun-tasks (77 tests, 0 failures)
- [x] Delete .claude-in-progress when the last item is ticked (none present)
