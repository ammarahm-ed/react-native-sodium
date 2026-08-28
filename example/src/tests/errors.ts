/**
 * These are the regression guards for the diagnosability work. Nearly every
 * user report that motivated it looked like "the app just says FAILURE", or an
 * NPE pointing at a line that had nothing to do with the real cause.
 *
 * The rule this suite enforces: every rejection carries a non-empty message
 * that names the thing that was actually wrong.
 */
import Sodium, {Cipher} from '@ammarahmed/react-native-sodium';
import {describe, expect, it, rejects, within} from '../harness';
import {
  fromBase64,
  nativeUri,
  pseudoRandomBytes,
  removeQuietly,
  toUrlSafeBase64,
  writeScratchFile,
} from '../util';

const PASSWORD = 'error-surface-password';

function asCipher(result: any, output?: 'plain'): Cipher<'base64'> {
  return {...result, output} as Cipher<'base64'>;
}

async function sampleCipher() {
  const key = await Sodium.deriveKey(PASSWORD);
  const cipher: any = await Sodium.encrypt(key, {
    type: 'plain',
    data: 'a message',
  });
  return {key, cipher};
}

describe('error surface', () => {
  it('names the problem when no key material is supplied at all', async () => {
    // This used to hand back a 32 byte all-zero key on Android and encrypt real
    // user data with it, and pass a NULL key pointer to libsodium on iOS.
    const {cipher} = await sampleCipher();
    const error = await rejects(
      () => Sodium.decrypt({} as any, asCipher(cipher, 'plain')),
      /expected \{ key, salt \} or \{ password \}/,
    );
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('names the field when the key is not valid base64', async () => {
    const {cipher} = await sampleCipher();
    await rejects(
      () =>
        Sodium.decrypt(
          {key: 'this is not base64 at all!!!', salt: cipher.salt},
          asCipher(cipher, 'plain'),
        ),
      /not valid url-safe base64|'key'/,
    );
  });

  it('reports a key of the wrong length rather than reading past it', async () => {
    const {cipher} = await sampleCipher();
    await rejects(
      () =>
        Sodium.decrypt(
          {key: toUrlSafeBase64(pseudoRandomBytes(16, 2)), salt: cipher.salt},
          asCipher(cipher, 'plain'),
        ),
      /32 bytes|decode/,
    );
  });

  it('rejects rather than hanging when the key field is null', async () => {
    // hasKey() is true for an explicit JS null while getString() returns null,
    // so Base64.decode(null) threw an NPE inside a helper that swallowed it and
    // returned null, and the caller then dereferenced that null.
    const {cipher} = await sampleCipher();
    const error = await rejects(() =>
      within(
        20000,
        Sodium.decrypt(
          {key: null, salt: null} as any,
          asCipher(cipher, 'plain'),
        ) as Promise<unknown>,
      ),
    );
    expect(error.message).notToBe('promise did not settle within 20000ms');
  });

  it('names the missing field when the cipher has no ciphertext', async () => {
    const {key, cipher} = await sampleCipher();
    await rejects(
      () =>
        Sodium.decrypt(
          key,
          asCipher({...cipher, cipher: undefined}, 'plain'),
        ),
      /'cipher'|cipher.*missing|missing.*cipher/i,
    );
  });

  it('names the missing field when the cipher has no iv', async () => {
    const {key, cipher} = await sampleCipher();
    await rejects(
      () => Sodium.decrypt(key, asCipher({...cipher, iv: undefined}, 'plain')),
      /'iv'|iv.*missing|missing.*iv/i,
    );
  });

  it('rejects a truncated ciphertext with a description', async () => {
    const {key, cipher} = await sampleCipher();
    const truncated = toUrlSafeBase64(fromBase64(cipher.cipher).slice(0, 4));
    const error = await rejects(() =>
      Sodium.decrypt(key, asCipher({...cipher, cipher: truncated}, 'plain')),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('rejects hashFile for a file that does not exist', async () => {
    // This used to resolve the hash of an uninitialised buffer on iOS, giving a
    // plausible looking identity for a file that was never there.
    const error = await rejects(() =>
      Sodium.hashFile({
        uri: nativeUri('/definitely/not/a/real/path/nothing.bin'),
        type: 'url',
      }),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('rejects hashFile when a base64 payload is missing', async () => {
    const error = await rejects(() =>
      Sodium.hashFile({uri: '', type: 'base64'} as any),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('rejects encryptFile for a file that does not exist', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const error = await rejects(() =>
      Sodium.encryptFile(key, {
        uri: nativeUri('/definitely/not/a/real/path/nothing.bin'),
        type: 'url',
      }),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('rejects decryptFile when the encrypted blob is not in the cache', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const error = await rejects(() =>
      within(
        20000,
        Sodium.decryptFile(
          key,
          {
            iv: toUrlSafeBase64(pseudoRandomBytes(24, 3)),
            salt: key.salt,
            hash: 'a-hash-that-was-never-written',
            chunkSize: 512 * 1024,
          },
          'base64',
        ),
      ),
    );
    expect(error.message).notToBe('promise did not settle within 20000ms');
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('rejects decryptFile without a hash instead of crashing', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const error = await rejects(() =>
      within(
        20000,
        Sodium.decryptFile(
          key,
          {
            iv: toUrlSafeBase64(pseudoRandomBytes(24, 3)),
            salt: key.salt,
            chunkSize: 512 * 1024,
          },
          'base64',
        ),
      ),
    );
    expect(error.message).notToBe('promise did not settle within 20000ms');
  });

  it('rejects encryptFile when key derivation cannot proceed', async () => {
    // encryptFile used to return without resolving or rejecting here, leaving
    // the promise pending forever.
    const path = await writeScratchFile(pseudoRandomBytes(128, 5));
    try {
      const error = await rejects(() =>
        within(
          20000,
          Sodium.encryptFile({} as any, {
            uri: nativeUri(path),
            type: 'url',
          }) as Promise<unknown>,
        ),
      );
      expect(error.message).notToBe('promise did not settle within 20000ms');
    } finally {
      await removeQuietly(path);
    }
  });

  it('never rejects with an empty or null message', async () => {
    const {key, cipher} = await sampleCipher();
    const cases: (() => Promise<unknown>)[] = [
      () => Sodium.decrypt({} as any, asCipher(cipher, 'plain')),
      () => Sodium.decrypt({key: 'nope', salt: 'nope'}, asCipher(cipher, 'plain')),
      () => Sodium.decrypt(key, asCipher({...cipher, cipher: undefined}, 'plain')),
      () => Sodium.decryptMulti({} as any, [asCipher(cipher, 'plain')]),
      () => Sodium.hashFile({uri: nativeUri('/nope/nope'), type: 'url'}),
      () =>
        Sodium.encryptFile({} as any, {uri: nativeUri('/nope/nope'), type: 'url'}),
    ];

    for (const [index, run] of cases.entries()) {
      let message: string | undefined;
      try {
        await within(20000, run());
      } catch (e) {
        message = (e as Error)?.message;
      }
      if (message === undefined) {
        throw new Error(`case ${index} resolved instead of rejecting`);
      }
      if (!message || message === 'null' || message === 'undefined') {
        throw new Error(`case ${index} rejected with an unusable message`);
      }
    }
  });
});
