# Task
Complete the contactless response path: GPO format 2, and a second GENERATE AC over CDOL2.

## Done when
- [x] GPO returns template 2 (77) carrying 82 AIP and 94 AFL
- [x] First GENERATE AC returns 77 with 9F27, 9F26 and 9F10
- [x] Second GENERATE AC parses CDOL2, recomputes the AC over the CDOL2 data and returns a different 9F26 from the first
- [x] A third GENERATE AC returns 6985
- [x] Tests: format 2 GPO bytes, second AC differs from first, third AC returns 6985
- [x] All 63 existing tests still pass (68 now; 2 of the 63 asserted format-1 GPO / refused-second-AC, updated deliberately)
- [x] ./gradlew testDebugUnitTest passes
- [x] ./gradlew assembleDebug passes
- [x] no new lint warnings (268 warnings + 1 manifest error, same as before)
- [x] Key-tools toggle moved to the main screen

## Rules
- Write the failing test first.
- Keep the asset path behind the pref; when off, nothing changes.
- CDOL1 and CDOL2 from profile.json verbatim. Do not invent tags.
- Never bump minSdk or compileSdk. Don't touch the PPSE AID or existing aid-filters.
- Commit after each green test run.
