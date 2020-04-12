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
        byte[] key = new byte[Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes()];
        byte[] passwordb = password.getBytes();
        byte[] saltb = new byte[Sodium.crypto_pwhash_salt_bytes()];
        if (salt != null)
            saltb = Base64.decode(salt, Base64.NO_WRAP);
        else
            Sodium.randombytes_buf(saltb, saltb.length);
        int memlimit = 1024 * 1024 * 8;
        int result = Sodium.crypto_pwhash(key, key.length, passwordb, passwordb.length, saltb, 3, memlimit, Sodium.crypto_pwhash_algo_argon2i13());
        if (result != 0)
            throw new Exception("crypto_pwhash: failed");
        return new Pair<byte[], byte[]>(key, saltb);
    }


    @ReactMethod
    public void encrypt(final ReadableMap passwordOrKey, final String data, final Promise p) {
        try {

            byte[] key = new byte[Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes()];
            byte[] salt = new byte[Sodium.crypto_pwhash_salt_bytes()];
            if (passwordOrKey.hasKey("key") && passwordOrKey.hasKey("salt")) {
                key = Base64.decode(passwordOrKey.getString("key"), Base64.NO_WRAP);
                salt = Base64.decode(passwordOrKey.getString("salt"), Base64.NO_WRAP);
            } else if (passwordOrKey.hasKey("password")) {
                Pair<byte[], byte[]> pair = crypto_pwhash(passwordOrKey.getString("password"), null);
                key = pair.first;
                salt = pair.second;
            }

            byte[] datab = data.getBytes();

            int length = datab.length + Sodium.crypto_aead_xchacha20poly1305_ietf_abytes();
            byte[] cipher = new byte[length];
            byte[] iv = randombytes_buf(Sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes());

            int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, length, datab, datab.length, iv, key);
            if (result != 0) {
                p.reject(ESODIUM, ERR_FAILURE);
                return;
            }
            WritableMap args = new Arguments().createMap();

            args.putString("cipher", Base64.encodeToString(cipher, Base64.NO_WRAP));
            args.putString("iv", Base64.encodeToString(iv, Base64.NO_WRAP));
            args.putString("salt", Base64.encodeToString(salt, Base64.NO_WRAP));
            args.putInt("length", datab.length);
            p.resolve(args);

        } catch (Exception e) {
            p.reject(e);
        }
    }

    @ReactMethod
    public void decrypt(final ReadableMap passwordOrKey, final ReadableMap cipher, final Promise p) {
        try {
            byte[] key = new byte[Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes()];
            if (passwordOrKey.hasKey("key") && passwordOrKey.hasKey("salt")) {
                key = Base64.decode(passwordOrKey.getString("key"), Base64.NO_WRAP);
            } else if (passwordOrKey.hasKey("password") && cipher.hasKey("salt")) {
                Pair<byte[], byte[]> pair = crypto_pwhash(passwordOrKey.getString("password"), cipher.getString("salt"));
                key = pair.first;
            }
            byte[] cipherb = Base64.decode(cipher.getString("cipher"), Base64.NO_WRAP);
            byte[] iv = Base64.decode(cipher.getString("iv"), Base64.NO_WRAP);
            byte[] plainText = new byte[cipher.getInt("length")];
            int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(plainText, plainText.length, cipherb, cipherb.length, iv, key);
            if (result != 0) {
                p.reject(ESODIUM, ERR_FAILURE);
                return;
            }
            p.resolve(new String(plainText));
        } catch (Exception e) {
            p.reject(e);
        }
    }

    @ReactMethod
    public void deriveKey(final String password, final Promise p) {
        try {
            Pair<byte[], byte[]> pair = crypto_pwhash(password, null);
            WritableMap map = new Arguments().createMap();
            map.putString("key", Base64.encodeToString(pair.first, Base64.NO_WRAP));
            map.putString("salt", Base64.encodeToString(pair.second, Base64.NO_WRAP));
            p.resolve(map);
        } catch (Throwable t) {
            p.reject(ESODIUM, ERR_FAILURE, t);
        }
    }
}
