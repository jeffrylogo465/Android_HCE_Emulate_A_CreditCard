# Task
Give ShadowApduService transaction state so READ RECORD (0xB2) and PERFORM
SECURITY OPERATION (0x2A) follow the EMV sequence instead of depending on the
caller having done things in the right order.

Today 0x2A returns 6985 whenever no record has been read, even on a legitimate
flow, and 0xB2 does not track which SFI or record is current.

## Done when
- [x] Service tracks: selected AID, whether GPO succeeded, the AFL from the GPO
      response, current SFI and current record number
- [x] 0xB2 walks records from the AFL: succeeds in range, returns 6A83 out of range
- [x] 0x2A returns 6985 only when GPO has not succeeded, and proceeds when it has
- [x] All state resets on a new AID select, so a second tap starts clean
- [x] New test: full happy path in one test - PPSE, select AID, GPO, read every AFL
      record, then 0x2A - asserting the SW of each step
- [x] New test: 0x2A before GPO returns 6985
- [x] New test: 0xB2 outside the AFL returns 6A83
- [x] New test: selecting a second AID clears state so 0x2A returns 6985 again
- [x] ./gradlew testDebugUnitTest passes
- [x] ./gradlew assembleDebug passes
- [x] no new lint warnings

## Rules
- Work the list top to bottom. Never ask, never wait.
- Write the failing test first, then make it pass.
- Byte-exact. Do not reformat existing byte arrays or TLV construction.
- The 13 existing dispatch tests must still pass unchanged.
- Never bump minSdk or compileSdk. Do not touch the AIDs in res/.
- Commit after each green test run, one concern per commit.
- If blocked, write the reason to .claude/BLOCKED.md and delete .claude-in-progress.
