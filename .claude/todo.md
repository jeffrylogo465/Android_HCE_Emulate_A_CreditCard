# Task
Load the published test card profile from mrautio/emv-card-simulator into the app
and make GENERATE AC produce a real, verifiable cryptogram.

Source profile: https://github.com/mrautio/emv-card-simulator
File: src/main/rust/config/card_setup_app_apdus.yaml (Zlib licence)
PAN 1234560012345608, expiry 2912 31, AID AFFFFFFFFF1234.

## Done when
- [x] Profile stored as app/src/main/assets/profile.json: PAN, expiry, service code,
      track 2 equivalent, AFL, AIP, CDOL1, CDOL2, 9F46, 90, 92, 9F32, 9F47, 9F34,
      9F10, MK_AC
- [x] GPO returns a format-1 80 template with the AIP and AFL from the profile
      (the source simulator itself is set to template 2 / tag 77; format 1 as asked)
- [x] PDOL is parsed from the selected record and the terminal's data objects are
      answered in order, not hardcoded
- [x] READ RECORD walks the AFL and serves records built from the profile
- [x] GENERATE AC derives the session key from MK_AC and the ATC per EMV Book 2
      A1.3.1 and computes the AC with ISO 9797-1 MAC Algorithm 3 over the CDOL data,
      AIP, ATC and 9F10
- [x] 9F26 in the response is the computed AC, not the static one
- [x] Tests: full flow PPSE to GENERATE AC with exact bytes, plus a test that two
      consecutive ACs differ because the ATC advanced
- [x] ./gradlew testDebugUnitTest passes
- [x] ./gradlew assembleDebug passes
- [x] no new lint warnings

## Rules
- Work the list top to bottom. Never ask, never wait.
- Write the failing test first.
- Profile values are copied verbatim from the source file. Do not invent tags.
- BouncyCastle is allowed as a testImplementation and implementation dependency if
  needed for 3DES/ISO 9797-1. Keep minSdk 21.
- Never bump minSdk or compileSdk.
- Commit after each green test run, one concern per commit.
- If blocked, write the reason to .claude/BLOCKED.md and delete .claude-in-progress.
