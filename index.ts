import { NativeModules } from "react-native";
import { Cipher, FileCipher, Password } from "./types";
export * from "./types";

const Native = NativeModules.Sodium;

function requireNative() {
  if (!Native) {
    throw new Error(
      "@ammarahmed/react-native-sodium: the native module is not linked. " +
        "Rebuild the app after installing the package (and run pod install on iOS)."
    );
  }
  return Native;
}

/**
 * The native methods are exported with a fixed arity. Under the New
 * Architecture the TurboModule interop layer validates the argument count and
 * throws
 *
 *   TurboModule method "deriveKey" called with 1 arguments (expected argument count: 2)
 *
 * instead of padding the call with null the way the old bridge did. Optional
 * parameters in the signatures below therefore have to be passed explicitly
 * here, or the declared API would be a lie for anyone who omits them.
 */
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
} = {
  sodium_version_string: () => requireNative().sodium_version_string(),

  encrypt: (password, data) => requireNative().encrypt(password, data),
  decrypt: (password, cipher) => requireNative().decrypt(password, cipher),

  encryptMulti: (password, data) => requireNative().encryptMulti(password, data),
  decryptMulti: (password, data) => requireNative().decryptMulti(password, data),

  hashPassword: (password, email) => requireNative().hashPassword(password, email),

  deriveKey: (password, salt) => requireNative().deriveKey(password, salt ?? null),

  decryptFile: (password, cipher, type) =>
    requireNative().decryptFile(password, cipher, type),
  hashFile: (data) => requireNative().hashFile(data),
  encryptFile: (password, data) => requireNative().encryptFile(password, data),

  // iOS only. These must stay absent elsewhere so that callers written as
  // `Sodium.deriveKeyFallback?.(...)` keep short-circuiting on Android.
  ...(Native?.deriveKeyFallback
    ? {
        deriveKeyFallback: (password: string, salt: string) =>
          Native.deriveKeyFallback(password, salt ?? null)
      }
    : {}),
  ...(Native?.hashPasswordFallback
    ? {
        hashPasswordFallback: (password: string, email: string) =>
          Native.hashPasswordFallback(password, email)
      }
    : {})
};

export default Sodium;
