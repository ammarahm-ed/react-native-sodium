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
import java.util.concurrent.Executors;

@ReactModule(name = "Sodium")
public class RCTSodiumModule extends ReactContextBaseJavaModule {

    static final String ESODIUM = "ESODIUM";
    static final String ERR_FAILURE = "FAILURE";

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
        p.resolve(xxhash64(data));
    }

    public String xxhash64(@Nullable final ReadableMap data) {
        XXHashFactory factory = XXHashFactory.fastestInstance();
        try {
            InputStream inputStream = getInputStream(data);
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
            long hash = hash64.getValue();
            inputStream.close();
            return Long.toHexString(hash);
        } catch (Exception e) {
            return null;
        }
    }

    public WritableMap getCipherData(byte[] iv, byte[] salt, int length, String hash, byte[] cipher) {
        WritableMap args = new Arguments().createMap();
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

    public File getFilesFromFilesDirCache(String hash, Boolean deleteIfExists) {
        try {
            String path = reactContext.getFilesDir().getAbsolutePath() + File.separator + ".cache";
            File dir = new File(path);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File file = new File(dir, hash);
            if (deleteIfExists && file.exists()) {
                file.delete();
                file.createNewFile();
            }

            return file;
        } catch (Exception e) {
            return null;
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

    public DocumentFile getFileFromUri(ReadableMap cipher) {
        DocumentFile dir = DocumentFile.fromTreeUri(reactContext, Uri.parse(cipher.getString("uri")));
        DocumentFile fileExists = dir.findFile(cipher.getString("fileName"));
        if (fileExists != null) fileExists.delete();
        DocumentFile documentFile = dir.createFile(cipher.getString("mime"), cipher.getString("fileName"));
        return documentFile;
    }

    public Pair<byte[], byte[]> getKey(ReadableMap passwordOrKey, String cipherSalt) {
        try {
            byte[] key = new byte[key_length];
            byte[] salt = new byte[salt_length];
            if (passwordOrKey.hasKey("key") && passwordOrKey.hasKey("salt")) {
                key = Base64.decode(passwordOrKey.getString("key"), variant);
                salt = Base64.decode(passwordOrKey.getString("salt"), variant);
            } else if (passwordOrKey.hasKey("password")) {
                Pair<byte[], byte[]> pair = crypto_pwhash(passwordOrKey.getString("password"), cipherSalt);
                key = pair.first;
                salt = pair.second;
            }
            return Pair.create(key, salt);
        } catch (Exception e) {
            return null;
        }
    }

    public InputStream getInputStream(ReadableMap data) {
        try {
            InputStream inputStream;

            if (data.hasKey("type") && data.getString("type").equals("base64")) {
                byte[] bytes = Base64.decode(data.getString("data"), Base64.NO_WRAP);
                inputStream = new ByteArrayInputStream(bytes);
            } else if (data.hasKey("type") && data.getString("type").equals("cache")) {
                File file = new File(data.getString("uri"));
                inputStream = new FileInputStream(file);
            } else {
                Uri uri = Uri.parse(data.getString("uri"));
                inputStream =
                        reactContext.getContentResolver().openInputStream(uri);
            }
            ;
            return inputStream;
        } catch (Exception e) {
            return null;
        }
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
                int length = inputStream.available();

                byte[] header = new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES];

                SecretStream.State state = lazySodium.cryptoSecretStreamInitPush(header, Key.fromBytes(key));

                FileOutputStream outputStream = new FileOutputStream(getFilesFromFilesDirCache(hash, true));

                int result = Transform(state, inputStream, outputStream, CHUNK_SIZE, false);

                if (result != 0) {
                    p.reject(ESODIUM, ERR_FAILURE);
                    return;
                }
                WritableMap map = getCipherData(header, salt, length, hash, null);
                map.putInt("chunkSize", 512 * 1024);
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

                int result = Transform(state, inputStream, outputStream, CHUNK_SIZE, true);

                if (descriptor != null) {
                    descriptor.close();
                }

                if (result != 0) {
                    p.reject(ESODIUM, ERR_FAILURE);
                    return;
                }

                if (type.equals("base64") || type.equals("text")) {
                    p.resolve(output.toString());
                } else if (type.equals("file")) {
                    p.resolve(outputFile.getUri().toString());
                } else {
                    p.resolve(outputPath);
                }

            } catch (Exception e) {
                p.reject(e.getCause());
            }
        });
    }

    public int Transform(SecretStream.State state, InputStream inputStream, OutputStream outputStream, int chunkSize, boolean decrypt) {

        try {
            int length = inputStream.available();
            double totalChunks = Math.max(Math.ceil((float) length / (float) chunkSize), 1);

            for (int i = 0; i < totalChunks; i++) {
                int start = i * chunkSize;
                int end = Math.min(start + chunkSize, length);
                byte[] input_chunk = new byte[end - start];
                inputStream.read(input_chunk);
                byte[] output_chunk = decrypt ? decryptChunk(state, input_chunk) : encryptChunk(state, input_chunk, i == totalChunks - 1);
                if (output_chunk != null) {
                    outputStream.write(output_chunk);
                } else {
                    inputStream.close();
                    outputStream.close();
                    return -1;
                }
                onSodiumProgress(totalChunks, i);
                outputStream.flush();
            }
            inputStream.close();
            outputStream.close();
            return 0;
        } catch (Exception e) {
            return -1;
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
                        p.reject(ESODIUM, ERR_FAILURE);
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
                    p.reject(ESODIUM, ERR_FAILURE);
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
                    p.reject(ESODIUM, ERR_FAILURE);
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
                        p.reject(ESODIUM, ERR_FAILURE);
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
            WritableMap map = new Arguments().createMap();
            map.putString("key", Base64.encodeToString(pair.first, variant));
            map.putString("salt", Base64.encodeToString(pair.second, variant));
            p.resolve(map);
        } catch (Throwable t) {
            p.reject(ESODIUM, ERR_FAILURE, t);
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
            p.reject(ESODIUM, ERR_FAILURE, t);
        }
    }
}
