# Task
Stop advertising DDA in the GPO response.

The AIP is 3C00, which claims DDA support, but GENERATE AC never sends 9F4B. A
kernel that honours the bit demands a signature and aborts at GPO. Clear the DDA
bit so kernels skip offline data authentication.

## Done when
- [x] AIP in profile.json is 1C00 (both "aip" and tags."82")
- [x] The GPO test asserts 82 02 1C00
- [x] All 68 existing tests still pass (7 had the 9F26 cryptograms updated deliberately: the AIP is part of the MAC input)
- [x] ./gradlew testDebugUnitTest and ./gradlew assembleDebug pass
- [x] no new lint warnings (1 error + 291 warnings, identical at HEAD)

## Rules
- Byte-exact. Only the AIP byte changes; the AFL and template stay as they are.
- Don't touch anything else. No 9F4B implementation in this task.
- Commit after the green test run.
- If blocked, write the reason to .claude/BLOCKED.md and delete .claude-in-progress.
