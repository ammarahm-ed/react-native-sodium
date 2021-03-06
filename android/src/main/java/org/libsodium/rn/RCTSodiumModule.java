package org.libsodium.rn;

/**
 * Created by Lyubomir Ivanov on 21/09/16.
 */

import java.util.Map;
import java.util.HashMap;

import android.util.Base64;
import android.util.Pair;

import androidx.annotation.Nullable;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import org.libsodium.jni.Sodium;

public class RCTSodiumModule extends ReactContextBaseJavaModule {

    static final String ESODIUM = "ESODIUM";
    static final String ERR_BAD_KEY = "BAD_KEY";
    static final String ERR_BAD_MAC = "BAD_MAC";
    static final String ERR_BAD_MSG = "BAD_MSG";
    static final String ERR_BAD_NONCE = "BAD_NONCE";
    static final String ERR_BAD_SEED = "BAD_SEED";
    static final String ERR_BAD_SIG = "BAD_SIG";
    static final String ERR_FAILURE = "FAILURE";

    final int iv_length = 24;
    final int salt_length = 16;
    final int key_length = 32;
    final int a_bytes_length = 16;

    final int variant = Base64.NO_PADDING | Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_CLOSE;

    public RCTSodiumModule(ReactApplicationContext reactContext) {
        super(reactContext);
        Sodium.loadLibrary();
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
        int result = Sodium.crypto_pwhash(key, key_length, passwordb, passwordb.length, saltb, 3, memlimit, Sodium.crypto_pwhash_algo_argon2i13());
        if (result != 0)
            throw new Exception("crypto_pwhash: failed");
        return new Pair<byte[], byte[]>(key, saltb);
    }


    @ReactMethod
    public void encrypt(final ReadableMap passwordOrKey, final ReadableMap data, final Promise p) {
        try {

            byte[] dataB;

            byte[] key = new byte[key_length];
            byte[] salt = new byte[salt_length];
            if (passwordOrKey.hasKey("key") && passwordOrKey.hasKey("salt")) {
                key = Base64.decode(passwordOrKey.getString("key"), variant);
                salt = Base64.decode(passwordOrKey.getString("salt"), variant);
            } else if (passwordOrKey.hasKey("password")) {
                Pair<byte[], byte[]> pair = crypto_pwhash(passwordOrKey.getString("password"), null);
                key = pair.first;
                salt = pair.second;
            }

            if (data.getString("type").equals("b64")) {
                dataB = Base64.decode(data.getString("data"), variant);
            } else {
                dataB = data.getString("data").getBytes();
            }

            int length = dataB.length + a_bytes_length;
            byte[] cipher = new byte[length];
            byte[] iv = randombytes_buf(iv_length);

            int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, length, dataB, dataB.length, iv, key);
            if (result != 0) {
                p.reject(ESODIUM, ERR_FAILURE);
                return;
            }

            WritableMap args = new Arguments().createMap();
            args.putString("cipher", Base64.encodeToString(cipher, variant));
            args.putString("iv", Base64.encodeToString(iv, variant));
            args.putString("salt", Base64.encodeToString(salt, variant));
            args.putInt("length", dataB.length);
            p.resolve(args);

        } catch (Exception e) {
            p.reject(e);
        }
    }

    @ReactMethod
    public void decrypt(final ReadableMap passwordOrKey, final ReadableMap cipher, final Promise p) {
        try {
            byte[] key = new byte[key_length];
            if (passwordOrKey.hasKey("key") && passwordOrKey.hasKey("salt")) {
                key = Base64.decode(passwordOrKey.getString("key"), variant);
            } else if (passwordOrKey.hasKey("password") && cipher.hasKey("salt")) {
                Pair<byte[], byte[]> pair = crypto_pwhash(passwordOrKey.getString("password"), cipher.getString("salt"));
                key = pair.first;
            }
            byte[] cipherb = Base64.decode(cipher.getString("cipher"), variant);
            byte[] iv = Base64.decode(cipher.getString("iv"), variant);
            byte[] plainText = new byte[cipher.getInt("length")];
            int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(plainText, plainText.length, cipherb, cipherb.length, iv, key);
            if (result != 0) {
                p.reject(ESODIUM, ERR_FAILURE);
                return;
            }

            if (cipher.getString("output").equals("plain")) {
                p.resolve(new String(plainText));
            } else {

                p.resolve(Base64.encodeToString(plainText, variant));
            }

        } catch (Exception e) {
            p.reject(e);
        }
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

            int result = Sodium.crypto_pwhash(key, 32, passwordb, passwordb.length, hash, 3, 1024 * 1024 * 64, Sodium.crypto_pwhash_algo_argon2id13());

            if (result != 0)
                throw new Exception("crypto_pwhash: failed");

            p.resolve(Base64.encodeToString(key, variant));

        } catch (Throwable t) {
            p.reject(ESODIUM, ERR_FAILURE, t);
        }
    }
}
