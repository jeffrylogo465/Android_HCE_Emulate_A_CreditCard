# Task
Add JVM unit tests covering the INS dispatch in ShadowApduService.

The class dispatches on the INS byte: 0xA8, 0xB2, 0xAE, 0x2A, 0xCA, 0x20,
0x84, and returns SW_UNSUPPORTED for anything else. Today only
ProfileTlvTest exists and the dispatcher is untested.

## Done when
- [x] New test class app/src/test/java/de/androidcrypto/android_hce_emulate_a_creditcard/ShadowApduServiceDispatchTest.java
- [x] One test per handled INS asserting the response and status word
- [x] One test asserting an unknown INS returns SW_UNSUPPORTED
- [x] One test asserting a known INS with a truncated or empty data field does not throw
- [x] ./gradlew testDebugUnitTest passes
- [x] ./gradlew assembleDebug passes
- [x] no new lint warnings

## Rules
- Work the list top to bottom. Never ask, never wait.
- processCommandApdu takes an android.os.Bundle. Pass null; it is unused in dispatch.
- If android.jar stubs throw "Stub!", add Robolectric as testImplementation and use
  @RunWith(RobolectricTestRunner::class) or the Java equivalent. Do not add a device dependency.
- Assert exact bytes and exact SW values. No assertNotNull-only tests.
- Do not change production behaviour in this task. Tests only, plus build deps if needed.
- Commit after each green test run.
- If blocked, write the reason to .claude/BLOCKED.md and delete .claude-in-progress.
