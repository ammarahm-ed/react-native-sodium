package org.libsodium.rn;

import androidx.annotation.Nullable;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;

/**
 * Stand-in for the class codegen generates from spec/NativeSodium.ts.
 * Only compiled when the New Architecture is disabled. Keep in sync with the spec.
 */
public abstract class NativeSodiumSpec extends ReactContextBaseJavaModule {
    public NativeSodiumSpec(ReactApplicationContext context) {
        super(context);
    }

    @ReactMethod public abstract void sodium_version_string(Promise promise);
    @ReactMethod public abstract void encrypt(ReadableMap password, ReadableMap data, Promise promise);
    @ReactMethod public abstract void decrypt(ReadableMap password, ReadableMap cipher, Promise promise);
    @ReactMethod public abstract void encryptMulti(ReadableMap password, ReadableArray data, Promise promise);
    @ReactMethod public abstract void decryptMulti(ReadableMap password, ReadableArray data, Promise promise);
    @ReactMethod public abstract void hashPassword(String password, String email, Promise promise);
    @ReactMethod public abstract void deriveKey(String password, @Nullable String salt, Promise promise);
    @ReactMethod public abstract void encryptFile(ReadableMap password, ReadableMap data, Promise promise);
    @ReactMethod public abstract void decryptFile(ReadableMap password, ReadableMap cipher, String type, Promise promise);
    @ReactMethod public abstract void hashFile(ReadableMap data, Promise promise);
    @ReactMethod public abstract void addListener(String eventName);
    @ReactMethod public abstract void removeListeners(double count);
}
