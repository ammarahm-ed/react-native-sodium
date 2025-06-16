import { NativeModules } from "react-native";
import { Cipher, FileCipher, Password } from "./types";
export * from "./types";

const Sodium: {
  sodium_version_string(): Promise<string>;
  encrypt<OutputType>(password: Password, data: {
    type: 'b64' | "plain",
    data: string
  }): Promise<Cipher<OutputType>>;
  decrypt(password: Password, Cipher: Cipher): Promise<string>;

  decryptMulti(password: Password, data: Cipher[]): Promise<string[]>;
  encryptMulti<OutputType>(password: Password, data: {
    type: 'b64' | "plain",
    data: string
  }[]): Promise<Cipher<OutputType>[]>;

  hashPassword(password: string, email: string): Promise<string>;
  hashPasswordFallback?(password: string, email: string): Promise<string>;

  deriveKey(password: string, salt?: string): Promise<Password>;
  deriveKeyFallback?(password: string, salt: string): Promise<Password | null>;
  
  decryptFile(
    password: Password,
    cipher: Partial<FileCipher>,
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
  ): Promise<Omit<FileCipher, "appGroupId" | "fileName" | "uri">>;
} = NativeModules.Sodium;

export default Sodium;
