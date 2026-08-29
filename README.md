# @ammarahmed/react-native-sodium

[libsodium](https://libsodium.org) bindings for React Native, built around the
primitives an end-to-end encrypted app actually needs: authenticated encryption
for strings, streaming authenticated encryption for files, and password-based
key derivation.

Precompiled libsodium binaries ship with the package. There is nothing to
compile.

- **Strings** — XChaCha20-Poly1305-IETF AEAD, one shot or in batches
- **Files** — XChaCha20-Poly1305 `secretstream`, chunked, never fully in memory
- **Key derivation** — Argon2
- **Hashing** — xxHash64, for content addressing attachments

Works with the New Architecture (via the TurboModule interop layer) and the old
bridge.

## Install

```sh
npm install @ammarahmed/react-native-sodium
cd ios && pod install
```

Autolinking handles the rest **except two things it cannot discover**.

### Android: include the lazysodium subproject

The native module depends on a vendored Gradle subproject that autolinking has
no way to find. Add this to `android/settings.gradle`:

```gradle
include ':lazysodium-android'
project(':lazysodium-android').projectDir = new File(
        rootProject.projectDir,
        '../node_modules/@ammarahmed/react-native-sodium/android/lazysodium-android/app')
```

Without it the build fails with `Project with path ':lazysodium-android' could
not be found`.

### iOS: exclude arm64 for the simulator

The bundled `libsodium.a` is an old-style fat binary whose `arm64` slice is
device-only — there is no arm64-simulator slice, so an Apple Silicon simulator
build cannot link it. In your `Podfile`:

```ruby
post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'arm64'
    end
  end
  # ...and the same for your app target; see example/ios/Podfile
end
```

Device builds are unaffected. Simulator builds run as x86_64 under Rosetta.

Minimum iOS version is 15.1.

## Usage

```ts
import Sodium from "@ammarahmed/react-native-sodium";

// Derive a key from a password. Omit the salt to generate a new one.
const key = await Sodium.deriveKey("correct horse battery staple");
// -> { key: "<43 chars>", salt: "<22 chars>" }

const cipher = await Sodium.encrypt(key, { type: "plain", data: "a secret" });
// -> { iv, salt, cipher, length }

const plain = await Sodium.decrypt(key, { ...cipher, output: "plain" });
// -> "a secret"
```

Every method takes either a derived key or a raw password:

```ts
await Sodium.encrypt({ password: "hunter2" }, { type: "plain", data: "..." });
await Sodium.decrypt({ password: "hunter2" }, cipher);
```

With a password, `encrypt` generates a fresh salt and returns it on the cipher;
`decrypt` re-derives the key from `cipher.salt`. That costs one Argon2 run per
call, so prefer deriving the key once and reusing it.

### Files

Files are streamed in 512 KiB chunks and never held in memory in full — except
when you ask for the plaintext back as a string.

```ts
const meta = await Sodium.encryptFile(key, { uri: filePath, type: "url" });
// -> { iv, salt, hash, hashType: "xxh64", size, chunkSize }

// Decrypt back to a string...
const base64 = await Sodium.decryptFile(key, meta, "base64");

// ...or to a file in the module's cache directory, which is much faster and
// bounds memory. Resolves the cache file name.
const name = await Sodium.decryptFile(key, meta, "cache");
```

`uri` is a plain filesystem path on iOS and a `file://` or `content://` URI on
Android.

`encryptFile` writes the ciphertext into the module's own cache directory, keyed
by the content hash:

| | path |
| --- | --- |
| iOS | `<NSLibraryDirectory>/.cache/<hash>` |
| Android | `<filesDir>/.cache/<hash>` |

### Hashing

```ts
await Sodium.hashFile({ uri: filePath, type: "url" });      // fast
await Sodium.hashFile({ uri: "", type: "base64", data });   // ~14x slower
```

Both produce the same xxHash64 of the same bytes. Prefer the path form when the
data is already on disk.

## API

| Method | Notes |
| --- | --- |
| `sodium_version_string()` | The linked libsodium version |
| `deriveKey(password, salt?)` | Argon2i13. Omit `salt` to generate one |
| `hashPassword(password, email)` | Argon2id13, for a server-side login hash |
| `encrypt(key, data)` / `decrypt(key, cipher)` | One string |
| `encryptMulti(key, data[])` / `decryptMulti(key, ciphers[])` | Batched; derives the key once |
| `encryptFile(key, data)` / `decryptFile(key, cipher, type)` | Streaming; `type` is `base64`, `text`, `cache` or `file` |
| `hashFile(data)` | xxHash64 |
| `deriveKeyFallback` / `hashPasswordFallback` | **iOS only**, see below |

Types are in [`types.ts`](./types.ts).

### The iOS-only fallbacks

`deriveKeyFallback` and `hashPasswordFallback` reproduce a historical bug in
which the password's length was measured in UTF-16 code units rather than
bytes. They exist so keys derived by affected iOS builds can still be recovered,
and they resolve `null` for a pure-ASCII password, where the two measurements
agree.

They are **undefined on Android**, so call them optionally:

```ts
const fallback = await Sodium.deriveKeyFallback?.(password, salt);
```

Do not use them for anything new.

## Cryptographic details

Useful if you need to interoperate, or to understand what is stored.

| | |
| --- | --- |
| String encryption | `crypto_aead_xchacha20poly1305_ietf` |
| File encryption | `crypto_secretstream_xchacha20poly1305`, 512 KiB chunks |
| Key derivation | `crypto_pwhash` Argon2i13, 8 MiB, 3 passes |
| Login hash | `crypto_pwhash` Argon2id13, 64 MiB, 3 passes, over a BLAKE2b salt |
| Key / salt / nonce | 32 / 16 / 24 bytes |
| AEAD tag | 16 bytes; secretstream tag 17 bytes |
| Encoding | url-safe base64, unpadded (libsodium variant 7) |
| File hash | xxHash64, reported as `hashType: "xxh64"` |

All encoded fields (`key`, `salt`, `iv`, `cipher`) are url-safe base64. Payloads
you hand in — `type: "b64"` data and `hashFile` base64 input — are accepted in
either the standard or the url-safe alphabet, padded or not.

## Errors

Every rejection carries a message naming what actually went wrong: which field
was missing or malformed, which chunk failed, which file could not be read.

One message is deliberately stable: **a failed authentication tag rejects with
the message `FAILURE`** and the code `BAD_MAC`. That is the wrong-key case, and
callers match on it to tell a user their password is incorrect.

```ts
try {
  await Sodium.decrypt(key, cipher);
} catch (e) {
  if (e.message === "FAILURE") {
    // wrong key, or the ciphertext was tampered with
  }
}
```

## Example app and test suite

[`example/`](./example) is a React Native app that runs the whole native surface
on a real device or simulator — round trips, chunk-boundary sizes, batch
operations, the error surface, and a benchmark group.

```sh
cd example
npm install
npx react-native start
npx react-native run-android   # or run-ios
```

See [example/README.md](./example/README.md) for how to collect results from a
terminal.

## Performance

Measured on an emulator, warm, median of 5 — treat these as relative, not
absolute. `example/` contains the benchmarks.

| Operation | Throughput |
| --- | --- |
| `hashFile` 10 MiB from a path | ~1000 MiB/s |
| `decryptFile` 10 MiB → `cache` | ~420 MiB/s |
| `encryptFile` 10 MiB | ~290 MiB/s |
| `decryptFile` 10 MiB → `base64` | ~150 MiB/s |
| `hashFile` 10 MiB from base64 | ~70 MiB/s |

Two things dominate, and both are avoidable:

- **`base64` output costs about 2.75x the `cache` path** and buffers the whole
  plaintext plus its base64 form in memory. Prefer `cache` for large files.
- **Argon2 is the floor for password-based calls.** Derive a key once and pass
  the key, rather than passing a password to every call.

## Credits

Originally by [Lyubomir Ivanov](https://github.com/lyubo/react-native-sodium).
Bundles [lazysodium-android](https://github.com/terl/lazysodium-android)
(MPL-2.0) and libsodium (ISC).
