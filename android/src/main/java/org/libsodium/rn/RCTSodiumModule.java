package org.libsodium.rn;

import android.net.Uri;
import android.os.AsyncTask;
import android.os.ParcelFileDescriptor;
import android.util.Base64;
import android.util.Base64InputStream;
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
import java.util.Arrays;
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

    ReactContext reactContext;

    public void onSodiumProgress(double total, double progress) {
        WritableMap params = Arguments.createMap();
        params.putDouble("total", total);
        params.putDouble("progress", progress);

        this.reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit("onSodiumProgress", params);
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


    private byte[] randombytes_buf(int size) {
        byte[] buf = new byte[size];
        Sodium.randombytes_buf(buf, size);
        return buf;
    }

    private Pair<byte[], byte[]> crypto_pwhash(final String password, @Nullable final String salt) throws Exception {
        byte[] key = new byte[key_length];
        byte[] passwordb = password.getBytes();
        byte[] saltb = new byte[salt_length];
        if (salt != null)
            saltb = Base64.decode(salt, variant);
        else
            Sodium.randombytes_buf(saltb, saltb.length);
        int memlimit = 1024 * 1024 * 8;
        int result = Sodium.crypto_pwhash(key, key_length, passwordb, passwordb.length, saltb, 3, new NativeLong(memlimit), PwHash.Alg.PWHASH_ALG_ARGON2I13.getValue());

        if (result != 0)
            throw new Exception("crypto_pwhash: failed");
        return new Pair<byte[], byte[]>(key, saltb);
    }

    @ReactMethod
    public void encryptFile(final ReadableMap passwordOrKey, @Nullable final ReadableMap data, final Promise p) {
        this.encryptFile(passwordOrKey, data, null, p);
    }

    @ReactMethod
    public void hashFile(@Nullable final ReadableMap data, final Promise p) {
        try {
            p.resolve(xxhash64(data));
        } catch (Exception e) {
            p.reject(ESODIUM, "hashFile: " + e.getMessage(), e);
        }
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
            args.putString("hashType", "xxh3");
        }
        return args;
    }

    public File getFileFromCache(String hash) {
        try {
            File file = new File(reactContext.getCacheDir(), hash);
            if (file.exists()) {
                file.delete();
                file.createNewFile();
            }
            return file;
        } catch (Exception e) {
            return null;
        }

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
    public void addListener(String eventName) {
        // Keep: Required for RN built in Event Emitter Calls.
    }

    @ReactMethod
    public void removeListeners(Integer count) {
        // Keep: Required for RN built in Event Emitter Calls.
    }

    public DocumentFile getFileFromUri(ReadableMap cipher) {
        DocumentFile dir = DocumentFile.fromTreeUri(reactContext, Uri.parse(cipher.getString("uri")));
        DocumentFile fileExists = dir.findFile(cipher.getString("fileName"));
        if (fileExists != null) fileExists.delete();
        DocumentFile documentFile = dir.createFile(cipher.getString("mime"), cipher.getString("fileName"));
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
            try {
                return new ByteArrayInputStream(Base64.decode(b64, Base64.NO_WRAP));
            } catch (IllegalArgumentException e) {
                throw new Exception("getInputStream: 'data' is not valid base64: " + e.getMessage(), e);
            }
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

    public void encryptFile(final ReadableMap passwordOrKey, @Nullable final ReadableMap data, @Nullable final byte[] dataA, final Promise p) {
        AsyncTask.execute(() -> {
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
                if (p != null) {
                    p.reject(e);
                }
            }
        });
    }


    @ReactMethod
    public void decryptFile(final ReadableMap passwordOrKey, final ReadableMap cipher, final String type, final Promise p) {
        AsyncTask.execute(() -> {
            try {
                int chunkSizeFromCipher = cipher.getInt("chunkSize");
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
                    outputPath = cipher.getString("hash") + "_dcache";
                    outputStream = new FileOutputStream(getFilesFromFilesDirCache(outputPath, true));
                } else {
                    outputFile = getFileFromUri(cipher);
                    descriptor = reactContext.getContentResolver().openFileDescriptor(outputFile.getUri(), "rw");
                    outputStream = new FileOutputStream(descriptor.getFileDescriptor());
                }

                byte[] iv = Base64.decode(cipher.getString("iv"), variant);

                SecretStream.State state = lazySodium.cryptoSecretStreamInitPull(iv, Key.fromBytes(key));

                File file = getFilesFromFilesDirCache(cipher.getString("hash"), false);
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
                    p.resolve(output.toString());
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

        try {
            double totalChunks = Math.max(Math.ceil((double) inputStream.available() / (double) chunkSize), 1);
            long processed = 0;
            int index = 0;

            byte[] current = new byte[chunkSize];
            int currentLength = readFully(inputStream, current);

            do {
                byte[] next = new byte[chunkSize];
                int nextLength = readFully(inputStream, next);
                boolean isFinal = nextLength == 0;

                byte[] input_chunk = currentLength == chunkSize ? current : Arrays.copyOf(current, currentLength);

                if (decrypt && input_chunk.length < Sodium.crypto_secretstream_xchacha20poly1305_abytes())
                    throw new Exception("truncated ciphertext: chunk " + (index + 1) + " is only "
                            + input_chunk.length + " bytes, need at least "
                            + Sodium.crypto_secretstream_xchacha20poly1305_abytes());

                byte[] output_chunk = decrypt ? decryptChunk(state, input_chunk) : encryptChunk(state, input_chunk, isFinal);
                if (output_chunk == null)
                    throw new Exception((decrypt ? "crypto_secretstream_xchacha20poly1305_pull"
                            : "crypto_secretstream_xchacha20poly1305_push")
                            + " failed on chunk " + (index + 1)
                            + " (chunk " + input_chunk.length + " bytes)");

                outputStream.write(output_chunk);
                outputStream.flush();
                processed += decrypt ? output_chunk.length : input_chunk.length;

                onSodiumProgress(Math.max(totalChunks, index + 1), index);
                index++;

                current = next;
                currentLength = nextLength;
            } while (currentLength > 0);

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

    public byte[] encryptChunk(SecretStream.State state, byte[] input, boolean final_chunk) {
        byte[] output_chunk = new byte[input.length + Sodium.crypto_secretstream_xchacha20poly1305_abytes()];
        byte tag = final_chunk ? Sodium.crypto_secretstream_xchacha20poly1305_tag_final() : Sodium.crypto_secretstream_xchacha20poly1305_tag_message();
        int result = Sodium.crypto_secretstream_xchacha20poly1305_push(state, output_chunk, null, input, input.length, null, 0, tag);
        if (result != 0) {
            return null;
        }
        return output_chunk;
    }

    public byte[] decryptChunk(SecretStream.State state, byte[] input) {
        byte[] output_chunk = new byte[input.length - Sodium.crypto_secretstream_xchacha20poly1305_abytes()];
        byte[] tag = new byte[1];
        int result = Sodium.crypto_secretstream_xchacha20poly1305_pull(state, output_chunk, null, tag, input, input.length, null, 0);
        if (result != 0) {
            return null;
        }
        return output_chunk;
    }


    @ReactMethod
    public void encryptMulti(final ReadableMap passwordOrKey, final ReadableArray array, final Promise p) {
        AsyncTask.execute(() -> {

            WritableArray results = Arguments.createArray();
            for (int i = 0; i < array.size(); i++) {
                try {
                    ReadableMap data = array.getMap(i);

                    byte[] dataB;

                    Pair<byte[], byte[]> pair = getKey(passwordOrKey, null);

                    byte[] key = pair.first;
                    byte[] salt = pair.second;

                    if (data.getString("type").equals("b64")) {
                        dataB = Base64.decode(data.getString("data"), variant);
                    } else {
                        dataB = data.getString("data").getBytes();
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
                    p.reject(e);
                }
            }

            p.resolve(results);
        });
    }


    @ReactMethod
    public void encrypt(final ReadableMap passwordOrKey, final ReadableMap data, final Promise p) {
        AsyncTask.execute(() -> {
            try {

                byte[] dataB;

                Pair<byte[], byte[]> pair = getKey(passwordOrKey, null);

                byte[] key = pair.first;
                byte[] salt = pair.second;

                if (data.getString("type").equals("b64")) {
                    dataB = Base64.decode(data.getString("data"), variant);
                } else {
                    dataB = data.getString("data").getBytes();
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
        AsyncTask.execute(() -> {
            try {
                Pair<byte[], byte[]> pair = getKey(passwordOrKey, cipher.getString("salt"));
                byte[] key = pair.first;

                byte[] cipherb = Base64.decode(cipher.getString("cipher"), variant);
                byte[] iv = Base64.decode(cipher.getString("iv"), variant);
                byte[] plainText = new byte[cipher.getInt("length")];
                long[] plaintext_length = new long[1];

                int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(plainText, plaintext_length, null, cipherb, cipherb.length, null, 0, iv, key);

                if (result != 0) {
                    p.reject(ERR_BAD_MAC, ERR_FAILURE, new Exception("crypto_aead_xchacha20poly1305_ietf_decrypt failed (result "
                                + result + ", " + cipherb.length + " byte ciphertext, " + iv.length
                                + " byte iv, " + key.length + " byte key)"));
                    return;
                }

                if (cipher.getString("output").equals("plain")) {
                    String plain = new String(plainText);
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
        AsyncTask.execute(() -> {
            WritableArray results = Arguments.createArray();
            for (int i = 0; i < array.size(); i++) {
                ReadableMap cipher = array.getMap(i);
                try {
                    Pair<byte[], byte[]> pair = getKey(passwordOrKey, cipher.getString("salt"));
                    byte[] key = pair.first;

                    byte[] cipherb = Base64.decode(cipher.getString("cipher"), variant);
                    byte[] iv = Base64.decode(cipher.getString("iv"), variant);
                    byte[] plainText = new byte[cipher.getInt("length")];
                    long[] plaintext_length = new long[1];

                    int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(plainText, plaintext_length, null, cipherb, cipherb.length, null, 0, iv, key);

                    if (result != 0) {
                        p.reject(ERR_BAD_MAC, ERR_FAILURE, new Exception("crypto_aead_xchacha20poly1305_ietf_decrypt failed (result "
                                    + result + ", " + cipherb.length + " byte ciphertext, " + iv.length
                                    + " byte iv, " + key.length + " byte key)"));
                        return;
                    }

                    if (cipher.getString("output").equals("plain")) {
                        String plain = new String(plainText);
                        results.pushString(plain);
                    } else {
                        results.pushString(Base64.encodeToString(plainText, variant));
                    }

                } catch (Exception e) {
                    p.reject(e);
                }
            }
            p.resolve(results);
        });
    }

    @ReactMethod
    public void deriveKey(final String password, final String salt, final Promise p) {
        try {
            Pair<byte[], byte[]> pair = crypto_pwhash(password, salt);
            WritableMap map = Arguments.createMap();
            map.putString("key", Base64.encodeToString(pair.first, variant));
            map.putString("salt", Base64.encodeToString(pair.second, variant));
            p.resolve(map);
        } catch (Throwable t) {
            p.reject(ESODIUM, t.getMessage() == null ? ERR_FAILURE : "deriveKey: " + t.getMessage(), t);
        }
    }

    @ReactMethod
    public void hashPassword(final String password, final String email, final Promise p) {
        try {
            String app_salt = "oVzKtazBo7d8sb7TBvY9jw";
            byte[] hash = new byte[16];
            byte[] input = (app_salt + email).getBytes();

            Sodium.crypto_generichash(hash, 16, input, input.length, null, 0);

            byte[] key = new byte[32];
            byte[] passwordb = password.getBytes();

            int result = Sodium.crypto_pwhash(key, 32, passwordb, passwordb.length, hash, 3, new NativeLong(1024 * 1024 * 64), PwHash.Alg.PWHASH_ALG_ARGON2ID13.getValue());

            if (result != 0)
                throw new Exception("crypto_pwhash: failed");

            p.resolve(Base64.encodeToString(key, variant));

        } catch (Throwable t) {
            p.reject(ESODIUM, t.getMessage() == null ? ERR_FAILURE : "hashPassword: " + t.getMessage(), t);
        }
    }
}
