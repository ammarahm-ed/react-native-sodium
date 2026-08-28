/**
 * A faithful port of the crypto surface of
 * notesnook/apps/mobile/app/common/database/encryption.ts.
 *
 * The MMKV and Keychain plumbing is left out because it is not what exercises
 * the native module, but every call into Sodium, every argument shape and the
 * iOS fallback-key control flow are reproduced exactly. If a change to the
 * native module breaks Notesnook, it should break here first.
 */
import Sodium, {Cipher, Password} from '@ammarahmed/react-native-sodium';
import {Platform} from 'react-native';

export type SerializedKey = {
  key?: string;
  salt?: string;
  password?: string;
};

export const NOTESNOOK_DB_KEY_SALT = 'notesnookDbKeySalt';
export const NOTESNOOK_APPLOCK_KEY_SALT = 'notesnookAppLockKeySalt';

export function getAlgorithm(base64Variant: number) {
  return `xcha-argon2i13-${base64Variant}`;
}

export function parseAlgorithm(alg: string) {
  if (!alg) return {};
  const [enc, kdf, compressed, compressionAlg, base64variant] = alg.split('-');
  return {
    encryptionAlgorithm: enc,
    kdfAlgorithm: kdf,
    compressionAlgorithm: compressionAlg,
    isCompress: compressed === '1',
    base64_variant: base64variant,
  };
}

export async function generateCryptoKey(password: string, salt?: string) {
  return Sodium.deriveKey(password, salt) as Promise<SerializedKey>;
}

export async function generateCryptoKeyFallback(
  password: string,
  salt?: string,
): Promise<SerializedKey | null | undefined> {
  return Sodium.deriveKeyFallback?.(password, salt as string) as Promise<
    SerializedKey | null | undefined
  >;
}

export async function hash(
  password: string,
  email: string,
  options?: {usesFallback?: boolean},
) {
  if (options?.usesFallback && Platform.OS !== 'ios') {
    return '';
  }
  return (
    options?.usesFallback
      ? await Sodium.hashPasswordFallback?.(password, email)
      : await Sodium.hashPassword(password, email)
  ) as string;
}

export async function encrypt(password: SerializedKey, plainText: string) {
  const result = await Sodium.encrypt<'base64'>(password, {
    type: 'plain',
    data: plainText,
  });

  return {
    ...result,
    alg: getAlgorithm(7),
  };
}

export async function encryptMulti(password: SerializedKey, plainText: string[]) {
  const results = await Sodium.encryptMulti<'base64'>(
    password,
    plainText.map(item => ({
      type: 'plain' as const,
      data: item,
    })),
  );

  return !results
    ? []
    : results.map(result => ({
        ...result,
        alg: getAlgorithm(7),
      }));
}

export async function decrypt(password: SerializedKey, data: Cipher<'base64'>) {
  const _data = {...data};
  _data.output = 'plain';

  if (!password.salt) password.salt = data.salt;

  if (Platform.OS === 'ios' && !password.key && password.password) {
    const key = await Sodium.deriveKey(password.password, password.salt);
    try {
      return await Sodium.decrypt(key, _data);
    } catch (e) {
      const fallbackKey = await Sodium.deriveKeyFallback?.(
        password.password,
        password.salt as string,
      );
      if (fallbackKey) {
        return await Sodium.decrypt(fallbackKey, _data);
      } else {
        throw e;
      }
    }
  }

  return await Sodium.decrypt(password as Password, _data);
}

export async function decryptMulti(
  password: Password,
  data: Cipher<'base64'>[],
) {
  data = data.map(d => {
    d.output = 'plain';
    return d;
  });

  if (data.length && !password.salt) {
    password.salt = data[0].salt;
  }

  if (Platform.OS === 'ios' && !password.key && password.password) {
    const key = await Sodium.deriveKey(password.password, password.salt);
    try {
      return await Sodium.decryptMulti(key, data);
    } catch (e) {
      const fallbackKey = await Sodium.deriveKeyFallback?.(
        password.password,
        password.salt as string,
      );
      if (fallbackKey) {
        return await Sodium.decryptMulti(fallbackKey, data);
      } else {
        throw e;
      }
    }
  }

  return await Sodium.decryptMulti(password, data);
}
