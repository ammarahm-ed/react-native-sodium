package org.libsodium.rn;

import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Base64;
import android.util.Base64OutputStream;
import android.util.Pair;

import androidx.annotation.Nullable;
import androidx.documentfile.provider.DocumentFile;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.interfaces.AEAD;
import com.goterl.lazysodium.interfaces.PwHash;
import com.goterl.lazysodium.interfaces.SecretStream;
import com.goterl.lazysodium.utils.Key;
import com.sun.jna.NativeLong;

import net.jpountz.xxhash.StreamingXXHash64;
import net.jpountz.xxhash.XXHashFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@ReactModule(name = "Sodium")
public class RCTSodiumModule extends ReactContextBaseJavaModule {

    static final String ESODIUM = "ESODIUM";
    static final String ERR_FAILURE = "FAILURE";
    // Distinguishes an authentication-tag mismatch (almost always a wrong key)
    // from every other failure. The message stays ERR_FAILURE because callers
    // match on it to report "Incorrect password".
    static final String ERR_BAD_MAC = "BAD_MAC";

    final int iv_length = 24;
    final int salt_length = 16;
    final int key_length = 32;
    final int a_bytes_length = 16;

    final int variant = Base64.NO_PADDING | Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_CLOSE;

    final SodiumAndroid Sodium;
    final LazySodiumAndroid lazySodium;

    // Bounded on purpose: every in-flight operation can hold an argon2 arena
    // (8 MiB for deriveKey, 64 MiB for hashPassword) plus two chunk buffers, so
    // unbounded concurrency turns into an allocation failure reported as
    // "crypto_pwhash: failed".
    private final ExecutorService executor = Executors.newFixedThreadPool(
            Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors())));

    ReactContext reactContext;

    /**
     * Progress is advisory. It is emitted from inside the encrypt/decrypt loop,
     * so a failure to deliver it must never abort a transfer that is otherwise
     * succeeding: getJSModule() throws once the react instance is torn down,
     * which used to surface as a failed encryption of an already written file.
     */
    public void onSodiumProgress(double total, double progress) {
        try {
            if (!reactContext.hasActiveReactInstance()) return;

            WritableMap params = Arguments.createMap();
            params.putDouble("total", total);
            params.putDouble("progress", progress);

            reactContext
                    .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                    .emit("onSodiumProgress", params);
        } catch (Exception ignored) {
        }
    }

    public RCTSodiumModule(ReactApplicationContext rc) {
        super(rc);
        Sodium = new SodiumAndroid();
        lazySodium = new LazySodiumAndroid(Sodium);
        reactContext = rc;
    }

    @Override
    public String getName() {
        return "Sodium";
    }

    @Override
    public void invalidate() {
        super.invalidate();
        executor.shutdown();
    }


    private byte[] randombytes_buf(int size) {
        byte[] buf = new byte[size];
        Sodium.randombytes_buf(buf, size);
        return buf;
    }

    private Pair<byte[], byte[]> crypto_pwhash(final String password, @Nullable final String salt) throws Exception {
        byte[] key = new byte[key_length];
        byte[] passwordb = password.getBytes(StandardCharsets.UTF_8);
        byte[] saltb = new byte[salt_length];
        if (salt != null)
            saltb = decodeBase64(salt, "salt");
        else
            Sodium.randombytes_buf(saltb, saltb.length);

        // crypto_pwhash always reads salt_length bytes from this array, so a
        // salt that decodes to anything shorter reads past the end of it.
        if (saltb.length != salt_length)
            throw new Exception("crypto_pwhash: salt must decode to " + salt_length
                    + " bytes but decoded to " + saltb.length);
        int memlimit = 1024 * 1024 * 8;
        int result;
        try {
            result = Sodium.crypto_pwhash(key, key_length, passwordb, passwordb.length, saltb, 3, new NativeLong(memlimit), PwHash.Alg.PWHASH_ALG_ARGON2I13.getValue());
        } finally {
            // The password bytes are no longer needed once the KDF has run.
            Arrays.fill(passwordb, (byte) 0);
        }

        if (result != 0)
            throw new Exception("crypto_pwhash: failed");
        return new Pair<byte[], byte[]>(key, saltb);
    }


    @ReactMethod
    public void hashFile(@Nullable final ReadableMap data, final Promise p) {
        executor.execute(() -> {
            try {
                p.resolve(xxhash64(data));
            } catch (Exception e) {
                p.reject(ESODIUM, "hashFile: " + e.getMessage(), e);
            }
        });
    }

    public String xxhash64(@Nullable final ReadableMap data) throws Exception {
        XXHashFactory factory = XXHashFactory.fastestInstance();
        InputStream inputStream = getInputStream(data);
        try {
            int seed = 0;
            StreamingXXHash64 hash64 = factory.newStreamingHash64(seed);
            byte[] buf = new byte[512 * 1024];
            for (; ; ) {
                int read = inputStream.read(buf);
                if (read == -1) {
                    break;
                }
                hash64.update(buf, 0, read);
            }
            return Long.toHexString(hash64.getValue());
        } finally {
            try {
                inputStream.close();
            } catch (Exception ignored) {
            }
        }
    }

    public WritableMap getCipherData(byte[] iv, byte[] salt, int length, String hash, byte[] cipher) {
        WritableMap args = Arguments.createMap();
        args.putString("iv", Base64.encodeToString(iv, variant));
        args.putString("salt", Base64.encodeToString(salt, variant));
        args.putInt("length", length);

        if (cipher != null) {
            args.putString("cipher", Base64.encodeToString(cipher, variant));
        }

        if (hash != null) {
            args.putString("hash", hash);
            // xxhash64, matching what iOS reports and what is actually computed.
            args.putString("hashType", "xxh64");
        }
        return args;
    }

    public File getFilesFromFilesDirCache(String hash, Boolean deleteIfExists) throws Exception {
        if (hash == null)
            throw new Exception("getFilesFromFilesDirCache: hash is null");

        String path = reactContext.getFilesDir().getAbsolutePath() + File.separator + ".cache";
        File dir = new File(path);
        if (!dir.exists() && !dir.mkdirs() && !dir.isDirectory())
            throw new Exception("getFilesFromFilesDirCache: could not create cache directory " + path);

        File file = new File(dir, hash);
        if (deleteIfExists && file.exists()) {
            file.delete();
            file.createNewFile();
        }

        return file;
    }

    @ReactMethod
    public void sodium_version_string(final Promise p) {
        try {
            p.resolve(Sodium.sodium_version_string());
        } catch (Throwable t) {
            p.reject(ESODIUM, "sodium_version_string: " + t.getMessage(), t);
        }
    }

    @ReactMethod
    public void addListener(String eventName) {
        // Keep: Required for RN built in Event Emitter Calls.
    }

    @ReactMethod
    public void removeListeners(Integer count) {
        // Keep: Required for RN built in Event Emitter Calls.
    }

    public DocumentFile getFileFromUri(ReadableMap cipher) throws Exception {
        String uri = requireString(cipher, "uri", "getFileFromUri");
        String fileName = requireString(cipher, "fileName", "getFileFromUri");
        String mime = requireString(cipher, "mime", "getFileFromUri");

        DocumentFile dir = DocumentFile.fromTreeUri(reactContext, Uri.parse(uri));
        if (dir == null)
            throw new Exception("getFileFromUri: not a readable tree uri: " + uri);

        DocumentFile fileExists = dir.findFile(fileName);
        if (fileExists != null) fileExists.delete();

        DocumentFile documentFile = dir.createFile(mime, fileName);
        if (documentFile == null)
            throw new Exception("getFileFromUri: could not create '" + fileName + "' (" + mime + ") in " + uri);
        return documentFile;
    }

    /**
     * Reads a string field, treating a missing key, an explicit JS null and a
     * non-string value all as "not provided" rather than throwing.
     */
    private String optString(ReadableMap map, String field) {
        if (map == null || !map.hasKey(field) || map.isNull(field)) return null;
        try {
            return map.getString(field);
        } catch (Exception e) {
            return null;
        }
    }

    private int optInt(ReadableMap map, String field, int fallback) {
        if (map == null || !map.hasKey(field) || map.isNull(field)) return fallback;
        try {
            return map.getInt(field);
        } catch (Exception e) {
            return fallback;
        }
    }

    private String requireString(ReadableMap map, String field, String owner) throws Exception {
        String value = optString(map, field);
        if (value == null)
            throw new Exception(owner + ": '" + field + "' is missing");
        return value;
    }

    /**
     * Caller supplied payloads are decoded leniently: iOS historically decoded
     * these as standard base64 while android used the url-safe alphabet, so the
     * same input worked on one platform and failed on the other. Cipher fields
     * keep using the strict url-safe variant.
     */
    private byte[] decodeAnyBase64(String value, String owner, String field) throws Exception {
        // The two alphabets differ only in the final two symbols, so translating
        // them lets a single strict decode accept either form. Decoding twice
        // with different flags does not work: the decoder does not reject the
        // foreign symbols outright, it drops them, which silently shifts every
        // byte after the first one.
        String normalized = value.replace('-', '+').replace('_', '/');
        try {
            return Base64.decode(normalized, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new Exception(owner + ": '" + field
                    + "' is not valid base64, standard or url-safe: " + e.getMessage(), e);
        }
    }

    private byte[] decodeBase64(String value, String field) throws Exception {
        try {
            return Base64.decode(value, variant);
        } catch (IllegalArgumentException e) {
            throw new Exception("getKey: '" + field + "' is not valid url-safe base64 (length "
                    + value.length() + "): " + e.getMessage(), e);
        }
    }

    public Pair<byte[], byte[]> getKey(ReadableMap passwordOrKey, String cipherSalt) throws Exception {
        String keyB64 = optString(passwordOrKey, "key");
        String saltB64 = optString(passwordOrKey, "salt");
        String password = optString(passwordOrKey, "password");

        if (keyB64 != null && saltB64 != null) {
            byte[] key = decodeBase64(keyB64, "key");
            byte[] salt = decodeBase64(saltB64, "salt");
            if (key.length != key_length)
                throw new Exception("getKey: 'key' must decode to " + key_length
                        + " bytes but decoded to " + key.length);
            return Pair.create(key, salt);
        }

        if (password != null) {
            return crypto_pwhash(password, cipherSalt);
        }

        // Never fall through to an all-zero key: that silently encrypts real
        // user data under a key of 32 zero bytes.
        throw new Exception("getKey: expected { key, salt } or { password }, but got"
                + " key=" + (keyB64 == null ? "missing" : "present")
                + " salt=" + (saltB64 == null ? "missing" : "present")
                + " password=" + (password == null ? "missing" : "present"));
    }

    public InputStream getInputStream(ReadableMap data) throws Exception {
        String type = optString(data, "type");

        if ("base64".equals(type)) {
            String b64 = optString(data, "data");
            if (b64 == null)
                throw new Exception("getInputStream: type is 'base64' but 'data' is missing");
            return new ByteArrayInputStream(decodeAnyBase64(b64, "getInputStream", "data"));
        }

        String uri = optString(data, "uri");
        if (uri == null)
            throw new Exception("getInputStream: 'uri' is missing (type=" + type + ")");

        if ("cache".equals(type)) {
            return new FileInputStream(new File(uri));
        }

        InputStream inputStream = reactContext.getContentResolver().openInputStream(Uri.parse(uri));
        if (inputStream == null)
            throw new Exception("getInputStream: content resolver returned no stream for " + uri);
        return inputStream;
    }

    @ReactMethod
    public void encryptFile(final ReadableMap passwordOrKey, @Nullable final ReadableMap data, final Promise p) {
        executor.execute(() -> {
            try {
                int CHUNK_SIZE = 512 * 1024;
                Pair<byte[], byte[]> pair = getKey(passwordOrKey, null);

                byte[] key = pair.first;
                byte[] salt = pair.second;

                String hash = data.getString("hash");
                if (hash == null) {
                    hash = xxhash64(data);
                }
                InputStream inputStream = getInputStream(data);

                byte[] header = new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES];

                SecretStream.State state = lazySodium.cryptoSecretStreamInitPush(header, Key.fromBytes(key));

                FileOutputStream outputStream = new FileOutputStream(getFilesFromFilesDirCache(hash, true));

                long length = Transform(state, inputStream, outputStream, CHUNK_SIZE, false);

                WritableMap map = getCipherData(header, salt, (int) length, hash, null);
                map.putInt("chunkSize", 512 * 1024);
                map.putInt("size", (int) length);

                p.resolve(map);

            } catch (Exception e) {
                p.reject(e);
            }
        });
    }


    @ReactMethod
    public void decryptFile(final ReadableMap passwordOrKey, final ReadableMap cipher, final String type, final Promise p) {
        executor.execute(() -> {
            try {
                // Ciphers written before chunkSize was recorded always used 512 KiB.
                int chunkSizeFromCipher = optInt(cipher, "chunkSize", 512 * 1024);
                int CHUNK_SIZE = chunkSizeFromCipher + Sodium.crypto_secretstream_xchacha20poly1305_abytes();
                Pair<byte[], byte[]> pair = getKey(passwordOrKey, cipher.getString("salt"));
                byte[] key = pair.first;

                OutputStream outputStream;
                ParcelFileDescriptor descriptor = null;
                DocumentFile outputFile = null;
                final ByteArrayOutputStream output = new ByteArrayOutputStream();
                String outputPath = "";

                if (type.equals("base64")) {
                    outputStream = new Base64OutputStream(output, Base64.NO_WRAP);
                } else if (type.equals("text")) {
                    outputStream = output;
                } else if (type.equals("cache")) {
                    outputPath = requireString(cipher, "hash", "decryptFile") + "_dcache";
                    outputStream = new FileOutputStream(getFilesFromFilesDirCache(outputPath, true));
                } else {
                    outputFile = getFileFromUri(cipher);
                    descriptor = reactContext.getContentResolver().openFileDescriptor(outputFile.getUri(), "rw");
                    outputStream = new FileOutputStream(descriptor.getFileDescriptor());
                }

                byte[] iv = decodeBase64(requireString(cipher, "iv", "decryptFile"), "iv");

                SecretStream.State state = lazySodium.cryptoSecretStreamInitPull(iv, Key.fromBytes(key));

                File file = getFilesFromFilesDirCache(requireString(cipher, "hash", "decryptFile"), false);
                InputStream inputStream =
                        reactContext.getContentResolver().openInputStream(Uri.fromFile(file));

                try {
                    Transform(state, inputStream, outputStream, CHUNK_SIZE, true);
                } finally {
                    if (descriptor != null) {
                        descriptor.close();
                    }
                }

                if (type.equals("base64") || type.equals("text")) {
                    p.resolve(output.toString("UTF-8"));
                } else if (type.equals("file")) {
                    p.resolve(outputFile.getUri().toString());
                } else {
                    p.resolve(outputPath);
                }

            } catch (Exception e) {
                p.reject(e);
            }
        });
    }

    /**
     * InputStream.read(byte[]) is free to return fewer bytes than asked for, and
     * a content provider backed by a pipe routinely does. The unfilled tail of
     * the buffer would otherwise be encrypted as if it were real data.
     */
    private static int readFully(InputStream inputStream, byte[] buffer) throws Exception {
        int total = 0;
        while (total < buffer.length) {
            int read = inputStream.read(buffer, total, buffer.length - total);
            if (read == -1) break;
            total += read;
        }
        return total;
    }

    /**
     * Returns the number of plaintext bytes processed.
     *
     * The loop runs to end of stream rather than to a chunk count derived from
     * available(): available() is only an estimate of what can be read without
     * blocking, and for a pipe-backed content provider it can fall far short of
     * the real length, which silently truncated the ciphertext. It is still
     * good enough to drive the progress denominator.
     */
    public long Transform(SecretStream.State state, InputStream inputStream, OutputStream outputStream, int chunkSize, boolean decrypt) throws Exception {
        final int aBytes = Sodium.crypto_secretstream_xchacha20poly1305_abytes();

        try {
            double totalChunks = Math.max(Math.ceil((double) inputStream.available() / (double) chunkSize), 1);
            long processed = 0;
            int index = 0;

            // Allocated once and reused for the whole stream. Allocating a chunk
            // buffer per iteration turned a 100 MiB file into roughly 200 MiB of
            // garbage, which is pure GC pressure on the encryption path.
            byte[] current = new byte[chunkSize];
            byte[] next = new byte[chunkSize];
            byte[] output = new byte[decrypt ? chunkSize : chunkSize + aBytes];
            byte[] tag = new byte[1];

            int currentLength = readFully(inputStream, current);

            do {
                int nextLength = readFully(inputStream, next);
                boolean isFinal = nextLength == 0;

                if (decrypt && currentLength < aBytes)
                    throw new Exception("truncated ciphertext: chunk " + (index + 1) + " is only "
                            + currentLength + " bytes, need at least " + aBytes);

                // The output length is fixed by the construction, so it does not
                // need to be read back out of libsodium.
                int outputLength = decrypt ? currentLength - aBytes : currentLength + aBytes;

                int result;
                if (decrypt) {
                    result = Sodium.crypto_secretstream_xchacha20poly1305_pull(
                            state, output, null, tag, current, currentLength, null, 0);
                } else {
                    byte chunkTag = isFinal
                            ? Sodium.crypto_secretstream_xchacha20poly1305_tag_final()
                            : Sodium.crypto_secretstream_xchacha20poly1305_tag_message();
                    result = Sodium.crypto_secretstream_xchacha20poly1305_push(
                            state, output, null, current, currentLength, null, 0, chunkTag);
                }

                if (result != 0)
                    throw new Exception((decrypt ? "crypto_secretstream_xchacha20poly1305_pull"
                            : "crypto_secretstream_xchacha20poly1305_push")
                            + " failed on chunk " + (index + 1)
                            + " (chunk " + currentLength + " bytes)");

                outputStream.write(output, 0, outputLength);
                processed += decrypt ? outputLength : currentLength;

                onSodiumProgress(Math.max(totalChunks, index + 1), index);
                index++;

                byte[] swap = current;
                current = next;
                next = swap;
                currentLength = nextLength;
            } while (currentLength > 0);

            outputStream.flush();
            return processed;
        } finally {
            try {
                inputStream.close();
            } catch (Exception ignored) {
            }
            try {
                outputStream.close();
            } catch (Exception ignored) {
            }
        }

    }

    @ReactMethod
    public void encryptMulti(final ReadableMap passwordOrKey, final ReadableArray array, final Promise p) {
        executor.execute(() -> {

            WritableArray results = Arguments.createArray();
            // Derived once for the whole batch. Deriving per item ran argon2i
            // (8 MiB, 3 passes) once per element. Every item still gets its own
            // random nonce, and iOS has always derived once per batch.
            byte[] key;
            byte[] salt;
            try {
                Pair<byte[], byte[]> pair = getKey(passwordOrKey, null);
                key = pair.first;
                salt = pair.second;
            } catch (Exception e) {
                p.reject(ESODIUM, "encryptMulti: " + e.getMessage(), e);
                return;
            }

            for (int i = 0; i < array.size(); i++) {
                try {
                    ReadableMap data = array.getMap(i);

                    byte[] dataB;

                    String plain = requireString(data, "data", "encryptMulti");
                    if ("b64".equals(optString(data, "type"))) {
                        dataB = decodeAnyBase64(plain, "encryptMulti", "data");
                    } else {
                        dataB = plain.getBytes(StandardCharsets.UTF_8);
                    }

                    int length = dataB.length + a_bytes_length;
                    byte[] cipher = new byte[length];
                    byte[] iv = randombytes_buf(iv_length);
                    long[] cipher_length = new long[1];

                    int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, cipher_length, dataB, dataB.length, null, 0, null, iv, key);

                    if (result != 0) {
                        p.reject(ESODIUM, "crypto_aead_xchacha20poly1305_ietf_encrypt failed (result "
                                + result + ", " + dataB.length + " bytes input, " + key.length + " byte key)");
                        return;
                    }

                    results.pushMap(getCipherData(iv, salt, dataB.length, null, cipher));

                } catch (Exception e) {
                    p.reject(ESODIUM, "encryptMulti: item " + i + " of " + array.size()
                            + " failed: " + e.getMessage(), e);
                    return;
                }
            }

            p.resolve(results);
        });
    }


    @ReactMethod
    public void encrypt(final ReadableMap passwordOrKey, final ReadableMap data, final Promise p) {
        executor.execute(() -> {
            try {

                byte[] dataB;

                Pair<byte[], byte[]> pair = getKey(passwordOrKey, null);

                byte[] key = pair.first;
                byte[] salt = pair.second;

                String plain = requireString(data, "data", "encrypt");
                if ("b64".equals(optString(data, "type"))) {
                    dataB = decodeAnyBase64(plain, "encrypt", "data");
                } else {
                    dataB = plain.getBytes(StandardCharsets.UTF_8);
                }

                int length = dataB.length + a_bytes_length;
                byte[] cipher = new byte[length];
                byte[] iv = randombytes_buf(iv_length);
                long[] cipher_length = new long[1];

                int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, cipher_length, dataB, dataB.length, null, 0, null, iv, key);

                if (result != 0) {
                    p.reject(ESODIUM, "crypto_aead_xchacha20poly1305_ietf_encrypt failed (result "
                            + result + ", " + dataB.length + " bytes input, " + key.length + " byte key)");
                    return;
                }

                p.resolve(getCipherData(iv, salt, dataB.length, null, cipher));

            } catch (Exception e) {
                p.reject(e);
            }
        });
    }


    @ReactMethod
    public void decrypt(final ReadableMap passwordOrKey, final ReadableMap cipher, final Promise p) {
        executor.execute(() -> {
            try {
                Pair<byte[], byte[]> pair = getKey(passwordOrKey, cipher.getString("salt"));
                byte[] key = pair.first;

                byte[] cipherb = decodeBase64(requireString(cipher, "cipher", "decrypt"), "cipher");
                byte[] iv = decodeBase64(requireString(cipher, "iv", "decrypt"), "iv");
                if (cipherb.length < a_bytes_length)
                    throw new Exception("ciphertext is only " + cipherb.length
                            + " bytes, need at least " + a_bytes_length);
                // Derived from the ciphertext rather than the caller's "length"
                // field: too small overflows the buffer libsodium writes into,
                // too large leaves trailing NUL bytes in the plaintext.
                byte[] plainText = new byte[cipherb.length - a_bytes_length];
                long[] plaintext_length = new long[1];

                int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(plainText, plaintext_length, null, cipherb, cipherb.length, null, 0, iv, key);

                if (result != 0) {
                    p.reject(ERR_BAD_MAC, ERR_FAILURE, new Exception("crypto_aead_xchacha20poly1305_ietf_decrypt failed (result "
                                + result + ", " + cipherb.length + " byte ciphertext, " + iv.length
                                + " byte iv, " + key.length + " byte key)"));
                    return;
                }

                if ("plain".equals(optString(cipher, "output"))) {
                    String plain = new String(plainText, StandardCharsets.UTF_8);
                    p.resolve(plain);
                } else {
                    p.resolve(Base64.encodeToString(plainText, variant));
                }

            } catch (Exception e) {
                p.reject(e);
            }
        });
    }

    @ReactMethod
    public void decryptMulti(final ReadableMap passwordOrKey, final ReadableArray array, final Promise p) {
        executor.execute(() -> {
            WritableArray results = Arguments.createArray();
            // Cached across items so a batch sharing one salt derives once
            // rather than running argon2i per element.
            String cachedSalt = null;
            Pair<byte[], byte[]> cachedPair = null;

            for (int i = 0; i < array.size(); i++) {
                ReadableMap cipher = array.getMap(i);
                try {
                    String cipherSalt = optString(cipher, "salt");
                    if (cachedPair == null || !Objects.equals(cachedSalt, cipherSalt)) {
                        cachedPair = getKey(passwordOrKey, cipherSalt);
                        cachedSalt = cipherSalt;
                    }
                    byte[] key = cachedPair.first;

                    byte[] cipherb = decodeBase64(requireString(cipher, "cipher", "decryptMulti"), "cipher");
                    byte[] iv = decodeBase64(requireString(cipher, "iv", "decryptMulti"), "iv");
                    if (cipherb.length < a_bytes_length)
                        throw new Exception("ciphertext is only " + cipherb.length
                                + " bytes, need at least " + a_bytes_length);
                    byte[] plainText = new byte[cipherb.length - a_bytes_length];
                    long[] plaintext_length = new long[1];

                    int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(plainText, plaintext_length, null, cipherb, cipherb.length, null, 0, iv, key);

                    if (result != 0) {
                        p.reject(ERR_BAD_MAC, ERR_FAILURE, new Exception("crypto_aead_xchacha20poly1305_ietf_decrypt failed (result "
                                    + result + ", " + cipherb.length + " byte ciphertext, " + iv.length
                                    + " byte iv, " + key.length + " byte key)"));
                        return;
                    }

                    if ("plain".equals(optString(cipher, "output"))) {
                        String plain = new String(plainText, StandardCharsets.UTF_8);
                        results.pushString(plain);
                    } else {
                        results.pushString(Base64.encodeToString(plainText, variant));
                    }

                } catch (Exception e) {
                    p.reject(ESODIUM, "decryptMulti: item " + i + " of " + array.size()
                            + " failed: " + e.getMessage(), e);
                    return;
                }
            }
            p.resolve(results);
        });
    }

    @ReactMethod
    public void deriveKey(final String password, final String salt, final Promise p) {
        executor.execute(() -> {
            try {
                Pair<byte[], byte[]> pair = crypto_pwhash(password, salt);
                WritableMap map = Arguments.createMap();
                map.putString("key", Base64.encodeToString(pair.first, variant));
                map.putString("salt", Base64.encodeToString(pair.second, variant));
                p.resolve(map);
            } catch (Throwable t) {
                p.reject(ESODIUM, t.getMessage() == null ? ERR_FAILURE : "deriveKey: " + t.getMessage(), t);
            }
        });
    }

    @ReactMethod
    public void hashPassword(final String password, final String email, final Promise p) {
        executor.execute(() -> {
            try {
                String app_salt = "oVzKtazBo7d8sb7TBvY9jw";
                byte[] hash = new byte[16];
                byte[] input = (app_salt + email).getBytes(StandardCharsets.UTF_8);

                Sodium.crypto_generichash(hash, 16, input, input.length, null, 0);

                byte[] key = new byte[32];
                byte[] passwordb = password.getBytes(StandardCharsets.UTF_8);

                int result;
                try {
                    result = Sodium.crypto_pwhash(key, 32, passwordb, passwordb.length, hash, 3, new NativeLong(1024 * 1024 * 64), PwHash.Alg.PWHASH_ALG_ARGON2ID13.getValue());
                } finally {
                    Arrays.fill(passwordb, (byte) 0);
                }

                if (result != 0)
                    throw new Exception("crypto_pwhash: failed");

                p.resolve(Base64.encodeToString(key, variant));

            } catch (Throwable t) {
                p.reject(ESODIUM, t.getMessage() == null ? ERR_FAILURE : "hashPassword: " + t.getMessage(), t);
            }
        });
    }
}
