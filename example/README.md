# react-native-sodium example

A test suite that runs the whole native surface on a real device or emulator.
The library is linked from the parent directory with `file:..`, so the app
exercises the working tree rather than a published build.

## Running

```sh
cd example
npm install
npx react-native start          # in one terminal

npx react-native run-android    # in another
# or
cd ios && pod install && cd .. && npx react-native run-ios
```

The suite runs automatically on launch. Tap a chip to run one group, or **Run**
to run everything again.

### Driving it from a terminal

Every result is also written to the JS console, so a full run can be collected
without touching the screen:

```sh
adb logcat -c
adb shell am start -n com.sodiumexample/.MainActivity
adb logcat -v brief ReactNativeJS:V '*:S' | grep SODIUM_TEST
```

The run ends with a machine readable line:

```
SODIUM_TEST_SUMMARY {"platform":"android","total":88,"passed":86,"failed":0,"skipped":2,"ms":7964}
SODIUM_TEST_DONE
```

## What is covered

| Group | What it checks |
| --- | --- |
| `module surface` | every method the TypeScript API declares actually exists, `sodium_version_string` |
| `key derivation` | `deriveKey` determinism, salt handling, `hashPassword`, the iOS `*Fallback` variants, concurrent derivations |
| `encrypt and decrypt` | round trips, empty and 1 MB payloads, multi-byte UTF-8, both base64 alphabets, nonce uniqueness, tampering |
| `encryptMulti and decryptMulti` | batch round trips, ordering, cross-compatibility with the single-item API, a corrupt item mid-batch |
| `file encryption` | chunk boundary sizes (`n-1`, `n`, `n+1`, `2n`), empty files, exact reported size, ciphertext length, progress events |
| `file hashing` | the file and base64 code paths agreeing, multi-chunk hashing, stability |
| `error surface` | every failure arrives with a message that names the real cause |
| `notesnook: *` | the app's own API layer, ported from `apps/mobile/app/common/database/encryption.ts` and `filesystem/io.ts` |

Two tests are iOS-only (`deriveKeyFallback`) and report as skipped elsewhere.

## Why the Notesnook layer is duplicated

`src/notesnook/` is a faithful copy of the app's wrappers, including the iOS
fallback-key control flow and the exact argument shapes. Testing through it
means a change that would break the app breaks here first. Two behaviours it
pins down deliberately:

- a wrong password must reject with a message of exactly `FAILURE`, because
  `packages/core/src/database/backup.ts` matches on that string to show
  "Incorrect password";
- `decryptMulti` must survive a key whose `salt` is explicitly `null`, which is
  the shape that produced the `Pair.first` null dereference in the field.

### Collecting results from the host

The run also writes `sodium-test-results.json` into the app's Documents
directory, which is the reliable way to collect results on iOS:

```sh
CONTAINER=$(xcrun simctl get_app_container booted org.reactjs.native.example.SodiumExample data)
cat "$CONTAINER/Documents/sodium-test-results.json"
```

## Notes

Three things a consuming app has to do, all of which this example demonstrates:

- **`android/settings.gradle` includes `:lazysodium-android` by hand.**
  Autolinking cannot discover it, so every consuming app needs the same three
  lines.
- **The simulator has to be built for x86_64.** The vendored `libsodium.a` is an
  old-style fat binary whose `arm64` slice is device-only; there is no
  arm64-simulator slice, so an Apple Silicon simulator build cannot link it.
  `ios/Podfile` sets `EXCLUDED_ARCHS[sdk=iphonesimulator*] = arm64` for both the
  pods and the app target. Device builds are unaffected.
- **fmt needs patching on Xcode >= 26.2.** React Native 0.82 vendors fmt 11.0.2,
  which a current Xcode rejects. `ios/scripts/patch_fmt_consteval.rb` runs from
  `post_install`. This is unrelated to this library; the Notesnook app carries
  the same patch.

The suite writes scratch files under the app cache directory and cleans up after
itself.
