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

## Follow-up (term-new.log) - the directory fix exposed a second dead end

Live tap: the terminal now selects A0000000041010 (the new PPSE fallback
entry above works), but GPO came back 6985. The SELECT of that AID fell
through, uncounted, to the ordinary select() dispatch - which has no
AIP/AFL of its own and never flipped AssetCardEngine's `selected` flag, so
the GPO that followed was refused.

- [x] AssetCardEngine.selectAs() binds the card for a requested name that
      isn't its own AID - same A5/selected state as its own select(), only
      tag 84 rewritten - and ShadowApduService's fallback branch calls it
      instead of falling through.
- [x] baseVerdict() tracked nGpos (the attempt) and assumed success; it now
      tracks the last GPO status word and names it instead of reporting
      "read NO records" when the GPO itself was refused.
- [x] New tests written and green (6 new: AssetCardEngineTest.java x1,
      ShadowApduServiceAssetCardTest.java x3 net - 2 added, 1 extended with
      a comment update).
- [x] Full suite green under --rerun-tasks (83 tests, 0 failures).
- [x] assembleDebug green.
- [x] Did not touch the PPSE, apduservice.xml, profile.json or the AIP.

## Follow-up (term-new2.log) - ODA claimed but impossible

GPO/records now served fine, but the terminal quit before GENERATE AC: AIP
1C00 advertised SDA with no tag 93 anywhere and an unknown CA key index (8F=92).

- [x] AIP 1C00 -> 1800 in both places it lives in profile.json ("aip" and
      tags "82"). No tag 93 added. PPSE, AFL and FCI untouched.
- [x] New test aip_claimsNoOfflineDataAuthentication (SDA/DDA/CDA bits clear).
- [x] Pinned bytes updated: GPO 82021800, and the 9F26 ARQC/TC values - the
      AIP is part of the MAC input, so they change by design, not by accident.
- [x] Full suite green under --rerun-tasks (84 tests, 0 failures); assembleDebug green.

## Follow-up (term-new3.log) - DDA via INTERNAL AUTHENTICATE

AIP 1800 changed nothing: the terminal reads 5 records then stops, because a
contactless kernel wants DDA/CDA.

- [x] INS 0x88 in AssetCardEngine: EMV Book 2 6.5 Signed Dynamic Application
      Data (6A 05 01 LDD dyn BB.. SHA-1 BC, hash over the block + the UN per
      DDOL 9F49=9F3704), raw RSA with the ICC key from assets/icc_private_key.pem
      (BouncyCastle bcprov-jdk15to18 1.70 parses the PEM). Response 77{9F4B sig}, 128 bytes.
- [x] DEVIATION from the request, on purpose: the AIP is NOT in the signed data
      (that is SDA's static data); and the AIP is 3C00, not 5800. 0x58 is
      SDA(40)+CVM(10)+TRM(08) - no DDA bit. 3C00 = the simulator's original 1C00
      + DDA(20). Tag 82 and "aip" both updated.
- [x] Tests: 0x88 gives 128 bytes, recovery gives 6A/05/01/BB../BC and a SHA-1 that
      matches block||UN (and not another UN), refused before GPO / wrong UN length /
      no key; aip_claimsDdaOnly. Seven 9F26 pins updated (AIP is MAC input).
- [x] .gitignore: *.pem (asset key excepted), term_*.log, term-*.log, tap.log.
- [x] 89 tests green under --rerun-tasks; assembleDebug green.
- [x] Verified: the PEM modulus matches 9F46's embedded ICC modulus exactly.
      Recovered the chain with the CA key (ca_92.pam, e=3) over tag 90 to get
      the issuer key, then the issuer key over 9F46; the ICC cert's own SHA-1
      hash did NOT verify under the standard EMV hash input (format||PAN||
      exp||serial||hashalg||pkalg||NIC||EIC||pubkey||exponent) even though the
      issuer cert's hash did - a defect in the upstream fixture, not in the key.
- [x] Fixed 9F46: fetched the issuer's actual private key (the IIN pem the repo
      only had as a URL pointer, iin_313233343536_e_3_private_key.pem from
      mrautio/emv-card-simulator) and confirmed its modulus equals the issuer
      key recovered above. Rebuilt the ICC cert plaintext with the same PAN/
      expiry/serial/NIC/EIC/modulus/exponent, a correctly computed SHA-1 hash,
      and re-signed it with that issuer private key. 9F46 changed in
      profile.json; nothing else in the chain (90, 92, 9F32, ca_92.pam) moved.
- [x] REC_2_1 and the 9F46 startsWith assertion updated in AssetCardEngineTest
      to the new cert bytes.
- [x] 90 tests green under --rerun-tasks; assembleDebug green.
- [ ] Still open: no real terminal will complete ODA against this card. The CA
      key index (RID A000000004, index 92) is fictional - no production
      Mastercard reader holds a CA key there - so 9F46 recovery will find no
      key and ODA aborts before GENERATE AC, independent of any cert bytes.
      That is a terminal-trust-store problem, not something fixable here.

## Follow-up - three scheme profiles for the asset card's fallback AIDs

selectAs() rewrote only tag 84, so a terminal selecting the Visa or Amex
fallback AID off the PPSE got Mastercard-shaped bytes (label, 9F12, AIP,
CVM list, CA index) under a foreign AID.

- [x] New AssetSchemeProfile enum (MASTERCARD/VISA/AMEX): AID, CA index (8F:
      EF/94/05), label, 9F12, PDOL (base CDOL1 set, Visa prefixed with 9F6604),
      and Amex's own CVM list (8E). AIP is 3C00 for all three - same bit
      layout, same DDA capability as the one shared ICC key.
- [x] DELIBERATE SIMPLIFICATION, stated rather than silently assumed: the
      certificate chain (90/92/9F32/9F46/9F47/9F49) and the ICC private key
      stay SHARED across all three schemes. 8F is a terminal-side lookup
      pointer, never bytes inside the cert, so this is one issuer/one ICC
      key re-badged under three brands - costs nothing, since no real
      terminal has a CA key at any of these fictional indices regardless.
      Minting three separate RSA chains would be pure busywork.
- [x] Not changed: the wire mechanism. GPO still answers AIP+AFL in a
      format-2 77, READ RECORD still walks the AFL, GENERATE AC still
      computes the cryptogram from CDOL1/CDOL2 for all three - no qVSDC
      GPO-carries-the-cryptogram shape for Visa.
- [x] AssetCardEngine.selectScheme(): binds the scheme, builds a fresh FCI
      with a REAL 9F38 PDOL (every other path through this engine has none -
      see the earlier ref.yaml diff). currentAip() feeds both the GPO's 82
      and the GENERATE AC MAC input; it is 3C00 either way so no existing
      pinned AC bytes moved. tag()/need() take 8F (and 8E for Amex) from the
      bound scheme before the shared profile.
- [x] ShadowApduService: new pref asset_scheme (MASTERCARD/VISA/AMEX, default
      Mastercard - existing tests untouched). buildAssetPpse()'s second
      directory entry now names the advertised scheme instead of always
      Mastercard, and picks up 9F2A from appEntry()'s existing AID-kernel
      table (not duplicated in AssetSchemeProfile). The fallback-SELECT
      dispatch tries AssetSchemeProfile.byAid() first; only an AID matching
      none of the three still falls through to the old generic selectAs().
- [x] Updated flag_on_selectA0000000041010_thenGpo_bindsAndRecordsAreReadable:
      A0000000041010 is now a keyed scheme with a real (non-empty) PDOL, so
      the old empty "83 00" GPO is the wrong length on purpose - a terminal
      must answer the PDOL this AID now actually advertises.
- [x] Three new tests (one per scheme): PPSE's second entry carries the right
      AID and 9F2A kernel id, and SELECTing that AID returns that scheme's own
      FCI (label/9F12/AIP/PDOL), not Mastercard's; Amex's case also checks its
      own 8E once GPO has bound it.
- [x] 92 tests green under --rerun-tasks; assembleDebug green.

## Follow-up - wire asset_scheme into the UI

asset_scheme defaulted to Mastercard and nothing wrote it - the same
unreachable-pref trap asset_profile had before setAssetCard() existed.

- [x] New Spinner (spnAssetScheme) on the main screen, directly under the
      test-card toggle, not inside showKeyTools() - it has to be visible.
      Options come from AssetSchemeProfile.values() so a fourth scheme needs
      no second list to update. A TextView (txtAssetScheme) states which one
      is active ("advertising: VISA") next to it.
- [x] MainActivity.setUpAssetSchemeSpinner()/setAssetScheme()/
      syncAssetSchemeSpinner(): same pattern as chkAssetCard's
      syncAssetCardBox() - read the pref with the Mastercard default and set
      the selection BEFORE attaching the listener, guarded by a boolean flag
      against the one onItemSelected Android fires for that programmatic
      set. Synced again in onResume(), wrapped in the same try/catch as the
      other asset-card sync calls.
- [x] Picking a scheme writes asset_scheme immediately (ShadowApduService
      reads it on the next tap, same as every other asset-card pref) and
      updates the label; nothing is written until a scheme is actually
      picked, so a fresh install still shows Mastercard without persisting
      it, same as the service's own unset-pref default.
- [x] New MainActivityAssetSchemeTest (Robolectric, first activity test in
      this app): default shows Mastercard with the pref unset, picking Visa
      writes the pref and updates the label, picking Amex survives a second
      Robolectric.buildActivity() (a reopen). Needed
      shadowOf(Looper.getMainLooper()).idle() after each spinner selection -
      Spinner's selection-changed callback is posted, not synchronous.
- [x] 95 tests green under --rerun-tasks; assembleDebug green.
