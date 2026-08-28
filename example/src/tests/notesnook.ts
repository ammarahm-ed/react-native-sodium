/**
 * The Notesnook flows, driven through the app's own API layer rather than the
 * native module directly. If a change here breaks, the app breaks.
 */
import Sodium, {Cipher} from '@ammarahmed/react-native-sodium';
import {Platform} from 'react-native';
import {describe, expect, it, rejects, within} from '../harness';
import {
  decrypt,
  decryptMulti,
  encrypt,
  encryptMulti,
  generateCryptoKey,
  getAlgorithm,
  hash,
  NOTESNOOK_DB_KEY_SALT,
  parseAlgorithm,
  SerializedKey,
} from '../notesnook/encryption';
import {hashBase64, readEncrypted, writeEncryptedBase64} from '../notesnook/io';
import {
  bytesEqual,
  fromBase64,
  nativeUri,
  pseudoRandomBytes,
  removeQuietly,
  toBase64,
  writeScratchFile,
} from '../util';

const USER_PASSWORD = 'notesnook-user-password';
const USER_EMAIL = 'user@notesnook.com';

describe('notesnook: database key', () => {
  it('derives a database key from a generated password and fixed salt', async () => {
    const derived = await generateCryptoKey('a-generated-password', NOTESNOOK_DB_KEY_SALT);
    expect(derived.key).toHaveLength(43);
    expect(derived.salt).toBeDefined();

    const again = await generateCryptoKey('a-generated-password', NOTESNOOK_DB_KEY_SALT);
    expect(again.key).toBe(derived.key);
  });

  it('wraps and unwraps a user key with the database key, as getCryptoKey does', async () => {
    const databaseKey = await generateCryptoKey(
      'db-password',
      NOTESNOOK_DB_KEY_SALT,
    );
    const userKey = 'the-user-key-material';

    const keyCipher = await encrypt(
      {key: databaseKey.key as string, salt: NOTESNOOK_DB_KEY_SALT},
      userKey,
    );

    const recovered = await decrypt(
      {key: databaseKey.key as string, salt: keyCipher.salt},
      keyCipher as unknown as Cipher<'base64'>,
    );
    expect(recovered).toBe(userKey);
  });

  it('tags ciphers with the algorithm the app records', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const cipher = await encrypt(key, 'hello');
    expect(cipher.alg).toBe('xcha-argon2i13-7');
    expect(parseAlgorithm(cipher.alg)).toEqual({
      encryptionAlgorithm: 'xcha',
      kdfAlgorithm: 'argon2i13',
      compressionAlgorithm: undefined,
      isCompress: false,
      base64_variant: undefined,
    });
    expect(getAlgorithm(7)).toBe('xcha-argon2i13-7');
  });
});

describe('notesnook: login', () => {
  it('hashes the password for the server deterministically', async () => {
    const a = await hash(USER_PASSWORD, USER_EMAIL);
    const b = await hash(USER_PASSWORD, USER_EMAIL);
    expect(a).toBe(b);
    expect(a).toHaveLength(43);
  });

  it('returns an empty string for the fallback hash off iOS', async () => {
    const result = await hash(USER_PASSWORD, USER_EMAIL, {usesFallback: true});
    if (Platform.OS === 'ios') {
      // ascii password, so there is nothing to fall back to
      expect(result).toBeNull();
    } else {
      expect(result).toBe('');
    }
  });
});

describe('notesnook: note content', () => {
  it('encrypts and decrypts a note through the app layer', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const content = JSON.stringify({
      type: 'tiptap',
      data: '<p>a note body with <strong>markup</strong></p>',
    });

    const cipher = await encrypt(key, content);
    const plain = await decrypt(key, cipher as unknown as Cipher<'base64'>);
    expect(plain).toBe(content);
    expect(JSON.parse(plain as string).type).toBe('tiptap');
  });

  it('encrypts and decrypts with only a password, as the applock flow does', async () => {
    const content = 'the database key material';
    const cipher = await encrypt({password: USER_PASSWORD}, content);
    const plain = await decrypt(
      {password: USER_PASSWORD},
      cipher as unknown as Cipher<'base64'>,
    );
    expect(plain).toBe(content);
  });

  it('reports a wrong password as exactly "FAILURE"', async () => {
    // packages/core/src/database/backup.ts matches e.message === "FAILURE" to
    // turn this into "Incorrect password". Changing the wording changes what
    // the user sees when importing a backup.
    const key = await generateCryptoKey(USER_PASSWORD);
    const wrong = await generateCryptoKey('the wrong password');
    const cipher = await encrypt(key, 'a note');

    const error = await rejects(() =>
      decrypt(wrong, cipher as unknown as Cipher<'base64'>),
    );
    expect(error.message).toBe('FAILURE');
  });

  it('round trips a batch of notes the way sync collects them', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const notes = Array.from({length: 50}, (_, i) =>
      JSON.stringify({id: `note_${i}`, title: `Note ${i}`}),
    );

    const ciphers = await encryptMulti(key, notes);
    const plains = await decryptMulti(
      key as any,
      ciphers as unknown as Cipher<'base64'>[],
    );
    expect(plains).toEqual(notes);
  });
});

describe('notesnook: sync decryption path', () => {
  it('takes the salt from the first cipher when the key has none', async () => {
    // This is the exact shape from the crash report: Sync passes keyInfo.key,
    // which may carry no salt, and the app layer fills it in from data[0].
    const key = await generateCryptoKey(USER_PASSWORD);
    const items = ['one', 'two', 'three'];
    const ciphers = (await encryptMulti(key, items)) as unknown as Cipher<'base64'>[];

    const keyWithoutSalt: SerializedKey = {key: key.key};
    const plains = await decryptMulti(keyWithoutSalt as any, ciphers);
    expect(plains).toEqual(items);
  });

  it('rejects with a described error when the key salt is explicitly null', async () => {
    // hasKey("salt") is true for a JS null while getString returns null, which
    // is what produced "Attempt to read from field Pair.first on a null object
    // reference" instead of anything useful.
    const key = await generateCryptoKey(USER_PASSWORD);
    const ciphers = (await encryptMulti(key, ['one'])) as unknown as Cipher<'base64'>[];

    const error = await rejects(() =>
      within(
        20000,
        Sodium.decryptMulti({key: null, salt: null} as any, ciphers),
      ),
    );
    expect(error.message).notToBe('promise did not settle within 20000ms');
    expect(error.message).notToBe('null');
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('does not crash when one item in a sync batch is corrupt', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const ciphers = (await encryptMulti(key, [
      'good one',
      'good two',
      'good three',
    ])) as any[];

    const corrupted = fromBase64(ciphers[1].cipher);
    corrupted[0] ^= 0xff;
    ciphers[1] = {
      ...ciphers[1],
      cipher: toBase64(corrupted).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    };

    const error = await rejects(() =>
      within(20000, decryptMulti(key as any, ciphers as Cipher<'base64'>[])),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });
});

describe('notesnook: attachments', () => {
  it('hashes a base64 attachment the way hashBase64 does', async () => {
    const bytes = pseudoRandomBytes(8192, 83);
    const result = await hashBase64(toBase64(bytes));
    expect(result.type).toBe('xxh64');
    expect(result.hash).toMatch(/^[0-9a-f]{1,16}$/);

    const again = await hashBase64(toBase64(bytes));
    expect(again.hash).toBe(result.hash);
  });

  it('writes and reads an encrypted attachment', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const bytes = pseudoRandomBytes(64 * 1024, 89);
    const base64 = toBase64(bytes);

    const metadata: any = await writeEncryptedBase64(
      base64,
      key,
      'application/octet-stream',
    );
    expect(metadata.alg).toBe('xcha-stream');
    expect(metadata.size).toBe(bytes.length);
    expect(metadata.hashType).toBe('xxh64');

    const output = await readEncrypted(metadata.hash, key, {
      ...metadata,
      outputType: 'base64',
    });
    expect(bytesEqual(fromBase64(output as string), bytes)).toBe(true);
  });

  it('writes and reads a multi chunk attachment', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const bytes = pseudoRandomBytes(512 * 1024 * 2 + 4096, 97);

    const metadata: any = await writeEncryptedBase64(
      toBase64(bytes),
      key,
      'application/octet-stream',
    );
    expect(metadata.size).toBe(bytes.length);

    const output = await readEncrypted(metadata.hash, key, {
      ...metadata,
      outputType: 'base64',
    });
    expect(bytesEqual(fromBase64(output as string), bytes)).toBe(true);
  });

  it('hashes an attachment identically before and after it is written', async () => {
    // The attachment picker hashes the source file, then encryptFile hashes it
    // again internally. A mismatch makes the blob unfindable later.
    const bytes = pseudoRandomBytes(100000, 101);
    const path = await writeScratchFile(bytes);
    try {
      const pickerHash = await Sodium.hashFile({
        uri: nativeUri(path),
        type: 'url',
      });
      const key = await generateCryptoKey(USER_PASSWORD);
      const metadata: any = await Sodium.encryptFile(key, {
        uri: nativeUri(path),
        type: 'url',
      });
      expect(metadata.hash).toBe(pickerHash);
    } finally {
      await removeQuietly(path);
    }
  });

  it('reports a wrong key when reading an attachment', async () => {
    const key = await generateCryptoKey(USER_PASSWORD);
    const wrong = await generateCryptoKey('a different password');
    const bytes = pseudoRandomBytes(4096, 103);

    const metadata: any = await writeEncryptedBase64(
      toBase64(bytes),
      key,
      'application/octet-stream',
    );

    const error = await rejects(() =>
      within(
        20000,
        readEncrypted(metadata.hash, wrong, {
          ...metadata,
          outputType: 'base64',
        }) as Promise<unknown>,
      ),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });
});
