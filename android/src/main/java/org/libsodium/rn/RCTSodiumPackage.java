package org.libsodium.rn;

import androidx.annotation.Nullable;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.facebook.react.BaseReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.module.model.ReactModuleInfoProvider;
import com.facebook.react.uimanager.ViewManager;

public class RCTSodiumPackage extends BaseReactPackage {

    @Nullable
    @Override
    public NativeModule getModule(String name, ReactApplicationContext reactContext) {
        if (name.equals("Sodium")) {
            return new RCTSodiumModule(reactContext);
        }
        return null;
    }

    @Override
    public ReactModuleInfoProvider getReactModuleInfoProvider() {
        return () -> {
            Map<String, ReactModuleInfo> infos = new HashMap<>();
            infos.put("Sodium", new ReactModuleInfo(
                    "Sodium",
                    "Sodium",
                    false, // canOverrideExistingModule
                    false, // needsEagerInit
                    false, // isCxxModule
                    BuildConfig.IS_NEW_ARCHITECTURE_ENABLED // isTurboModule
            ));
            return infos;
        };
    }

    @Override
    public List<ViewManager> createViewManagers(ReactApplicationContext reactContext) {
        return Collections.emptyList();
    }
}
