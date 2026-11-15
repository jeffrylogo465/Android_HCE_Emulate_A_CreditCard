# Task
Fix the fallback CVM list so the signature rule is reachable.

CVMList at ShadowApduService.java:159 uses condition code 03 on both rules. Code 03
means "if terminal supports the CVM", which is always true for No CVM Required, so
rule 1 always wins and the signature rule never fires. Codes 06 and 07 are the
under/over-amount conditions the comment at lines 155-156 describes.

## Done when
- [x] CVMList amounts X and Y are both 000003E8 (10.00 in minor units)
- [x] Rule 1 is 1F06 (No CVM Required, if transaction is under X)
- [x] Rule 2 is 1E07 (Signature, if transaction is over X)
- [x] The comment above it matches what the list now does
- [x] Tests: a transaction under 1000 selects No CVM, one over selects Signature
- [x] All 68 existing tests still pass
- [x] ./gradlew testDebugUnitTest and ./gradlew assembleDebug pass
- [x] no new lint warnings (1 error + 291 warnings, identical to before)

## Rules
- Work top to bottom. Never ask, never wait.
- Write the failing test first. Byte-exact on the CVM list.
- Change only the CVM list and its comment. Nothing else.
- Never bump minSdk or compileSdk.
- Commit after the green test run.
- If blocked, write the reason to .claude/BLOCKED.md and delete .claude-in-progress.
