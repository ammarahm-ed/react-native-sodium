import { NativeModules } from "react-native";
import { CIPHER, FileCipher, PASSWORD } from "./types";
export * from "./types";

const Sodium: {
  sodium_version_string(): Promise<string>;
  encrypt(password: string, data: string): Promise<CIPHER>;
  decrypt(password: string, data: object): Promise<string>;
  deriveKey(password: string, salt: string): Promise<PASSWORD>;
  decryptFile(
    password: { key?: string; salt?: string; password?: string },
    cipher: FileCipher,
    type: "text" | "file" | "base64" | "cache"
  ): Promise<string>;
  hashFile(data: {
    uri: string;
    type: "base64" | "url" | "cache";
    data?: string;
  }): Promise<string>;
  encryptFile(
    password: { key?: string; salt?: string; password?: string },
    data: {
      uri: string;
      type: "base64" | "url" | "cache";
      data?: string;
      appGroupId?: string;
    }
  ): Promise<FileCipher>;
} = NativeModules.Sodium;

export default Sodium;
