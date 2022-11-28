import { NativeModules } from "react-native";

import {
  CameraOptions,
  ImageLibraryOptions,
  Callback,
  CIPHER,
  PASSWORD,
  FileCipher,
} from "react-native-sodium/types";
export * from "react-native-sodium/types";

const DEFAULT_OPTIONS: CameraOptions = {
  mediaType: "photo",
  videoQuality: "high",
  quality: 1,
  maxWidth: 0,
  maxHeight: 0,
  includeBase64: false,
  cameraType: "back",
  selectionLimit: 1,
  saveToPhotos: false,
  durationLimit: 0,
  encryptToFile: false,
};

export function launchCamera(options: CameraOptions, callback: Callback) {
  if (typeof callback !== "function") {
    console.error("Send proper callback function, check API");
    return;
  }

  NativeModules.ImagePickerManager.launchCamera(
    { ...DEFAULT_OPTIONS, ...options },
    callback
  );
}

export function launchImageLibrary(
  options: ImageLibraryOptions,
  callback: Callback
) {
  if (typeof callback !== "function") {
    console.error("Send proper callback function, check API");
    return;
  }
  NativeModules.ImagePickerManager.launchImageLibrary(
    { ...DEFAULT_OPTIONS, ...options },
    callback
  );
}

const Sodium: {
  sodium_version_string(): Promise<string>;
  encrypt(password: string, data: string): Promise<CIPHER>;
  decrypt(password: string, data: object): Promise<string>;
  deriveKey(password: string, salt: string): Promise<PASSWORD>;
  decryptFile(
    password: { key?: string; salt?: string; password?: string },
    cipher: FileCipher,
    type: "text" | "file" | "base64"
  ): Promise<string>;
  hashFile(data: {
    uri: string;
    type: "base64" | "url";
    data?: string;
  }): string;
  encryptFile(
    password: { key?: string; salt?: string; password?: string },
    data: {
      uri: string;
      type: "base64" | "url";
      data?: string;
    }
  ): Promise<FileCipher>;
} = NativeModules.Sodium;

export default Sodium;
