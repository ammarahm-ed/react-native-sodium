import { NativeModules } from "react-native";
import { Cipher, FileCipher, Password } from "./types";
export * from "./types";

const Sodium: {
  sodium_version_string(): Promise<string>;
  encrypt(password: Password, data: string): Promise<Cipher>;
  decrypt(password: Password, data: object): Promise<string>;

  decryptMulti(password: Password, data: object[]): Promise<string[]>;
  encryptMulti(password: Password, data: object[]): Promise<Cipher[]>;

  deriveKey(password: string, salt: string): Promise<Password>;
  decryptFile(
    password: Password,
    cipher: FileCipher,
    type: "text" | "file" | "base64" | "cache"
  ): Promise<string>;
  hashFile(data: {
    uri: string;
    type: "base64" | "url" | "cache";
    data?: string;
  }): Promise<string>;
  encryptFile(
    password: Password,
    data: {
      uri: string;
      type: "base64" | "url" | "cache";
      data?: string;
      appGroupId?: string;
    }
  ): Promise<FileCipher>;
} = NativeModules.Sodium;

export default Sodium;
