# HCE credit card emulator — working rules

Java 8 source level, minSdk 21, compileSdk 34, package
`de.androidcrypto.android_hce_emulate_a_creditcard`. Gradle Kotlin DSL, JDK 17.

## Hard rules
- Never bump minSdk or compileSdk. Dependencies must stay API 21 compatible.
- Build gate is `./gradlew testDebugUnitTest` plus `./gradlew assembleDebug`.
  Nothing else counts as proof that the build is green.
- A physical phone (RFCW216RFBE, SM_S911U) is attached over adb and has been
  tapped against a reader all session. `adb install -r
  app/build/outputs/apk/debug/app-debug.apk` followed by a live tap is the
  only thing that proves protocol behaviour (APDU sequencing, AFL/GPO
  content, timing against a real terminal) — the unit tests fix expected
  byte arrays but do not exercise a real reader. A tap is not "proof" in the
  unit-test sense: it's not pass/fail and isn't asserted against; read the
  resulting terminal log (e.g. `term-new*.log`) and say what happened.
- EMV is byte-exact. Length bytes, tag order and FCI construction must match the
  existing tests. Do not "tidy" byte arrays.
- `res/xml/apduservice.xml` and the AID strings in `res/values/strings.xml` are
  load-bearing. The PPSE AID 325041592E5359532E4444463031 must not change.
- `app/src/test` is the source of truth for expected APDU bytes. If behavior
  changes, update the test in the same commit and say why.

## Working style
- Work `.claude/todo.md` top to bottom. Never ask, never wait for confirmation.
- Follow changes through every call site, then compile, then test.
- Commit after each green test run, one concern per commit.
- If blocked, write the reason to .claude/BLOCKED.md and delete .claude-in-progress.
