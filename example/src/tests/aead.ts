import Sodium, {Cipher} from '@ammarahmed/react-native-sodium';
import {describe, expect, it, rejects} from '../harness';
import {
  fromBase64,
  pseudoRandomBytes,
  repeatString,
  toBase64,
  toUrlSafeBase64,
} from '../util';

const PASSWORD = 'a-very-secret-password';

async function freshKey() {
  return Sodium.deriveKey(PASSWORD);
}

function asCipher(result: any, output?: 'plain'): Cipher<'base64'> {
  return {...result, output} as Cipher<'base64'>;
}

describe('encrypt and decrypt', () => {
  it('round trips plain text with a derived key', async () => {
    const key = await freshKey();
    const message = 'the quick brown fox jumps over the lazy dog';
    const cipher = await Sodium.encrypt(key, {type: 'plain', data: message});

    expect(cipher.iv).toBeDefined();
    expect(cipher.salt).toBe(key.salt);
    expect(cipher.cipher).toBeDefined();
    expect(cipher.length).toBe(message.length);

    const plain = await Sodium.decrypt(key, asCipher(cipher, 'plain'));
    expect(plain).toBe(message);
  });

  it('round trips with a password instead of a key', async () => {
    const message = 'password based round trip';
    const cipher = await Sodium.encrypt(
      {password: PASSWORD},
      {type: 'plain', data: message},
    );
    expect(cipher.salt).toBeDefined();

    const plain = await Sodium.decrypt(
      {password: PASSWORD},
      asCipher(cipher, 'plain'),
    );
    expect(plain).toBe(message);
  });

  it('round trips an empty string', async () => {
    const key = await freshKey();
    const cipher = await Sodium.encrypt(key, {type: 'plain', data: ''});
    const plain = await Sodium.decrypt(key, asCipher(cipher, 'plain'));
    expect(plain).toBe('');
  });

  it('round trips multi-byte utf8 without mangling bytes', async () => {
    const key = await freshKey();
    const message = 'hello - cafe latte - Grusse - 日本語テスト - emoji';
    const cipher = await Sodium.encrypt(key, {type: 'plain', data: message});
    const plain = await Sodium.decrypt(key, asCipher(cipher, 'plain'));
    expect(plain).toBe(message);
  });

  it('round trips a one megabyte payload', async () => {
    const key = await freshKey();
    const message = repeatString('0123456789abcdef', 1024 * 1024);
    const cipher = await Sodium.encrypt(key, {type: 'plain', data: message});
    const plain = await Sodium.decrypt(key, asCipher(cipher, 'plain'));
    expect(plain).toHaveLength(message.length);
    expect(plain).toBe(message);
  });

  it('accepts standard base64 input for type b64', async () => {
    const key = await freshKey();
    const bytes = pseudoRandomBytes(512, 7);
    const cipher = await Sodium.encrypt(key, {
      type: 'b64',
      data: toBase64(bytes),
    });
    const out = await Sodium.decrypt(key, asCipher(cipher));
    expect(Array.from(fromBase64(out))).toEqual(Array.from(bytes));
  });

  it('accepts url-safe base64 input for type b64', async () => {
    // Android decoded this alphabet and iOS decoded the standard one, so the
    // same payload used to work on one platform and fail on the other.
    const key = await freshKey();
    const bytes = pseudoRandomBytes(512, 9);
    const cipher = await Sodium.encrypt(key, {
      type: 'b64',
      data: toUrlSafeBase64(bytes),
    });
    const out = await Sodium.decrypt(key, asCipher(cipher));
    expect(Array.from(fromBase64(out))).toEqual(Array.from(bytes));
  });

  it('rejects with exactly "FAILURE" when the key is wrong', async () => {
    // Notesnook's backup import matches on this exact message to report
    // "Incorrect password", so the wording is a contract.
    const key = await freshKey();
    const other = await Sodium.deriveKey('a different password');
    const cipher = await Sodium.encrypt(key, {type: 'plain', data: 'secret'});

    const error = await rejects(() =>
      Sodium.decrypt(other, asCipher(cipher, 'plain')),
    );
    expect(error.message).toBe('FAILURE');
  });

  it('rejects when the ciphertext has been tampered with', async () => {
    const key = await freshKey();
    const cipher: any = await Sodium.encrypt(key, {
      type: 'plain',
      data: 'tamper me',
    });
    const bytes = fromBase64(cipher.cipher);
    bytes[0] ^= 0xff;
    const error = await rejects(() =>
      Sodium.decrypt(
        key,
        asCipher({...cipher, cipher: toUrlSafeBase64(bytes)}, 'plain'),
      ),
    );
    expect(error.message).toBe('FAILURE');
  });

  it('ignores a wrong length field on the cipher', async () => {
    // Android used to allocate the plaintext buffer from this field, so a value
    // that was too large left trailing NUL bytes on the decrypted string and a
    // value that was too small overflowed the buffer libsodium wrote into.
    const key = await freshKey();
    const message = 'length field should not matter';
    const cipher: any = await Sodium.encrypt(key, {
      type: 'plain',
      data: message,
    });

    const tooLong = await Sodium.decrypt(
      key,
      asCipher({...cipher, length: message.length + 64}, 'plain'),
    );
    expect(tooLong).toBe(message);

    const tooShort = await Sodium.decrypt(
      key,
      asCipher({...cipher, length: 1}, 'plain'),
    );
    expect(tooShort).toBe(message);
  });

  it('produces a different nonce for every encryption', async () => {
    const key = await freshKey();
    const ivs = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const cipher = await Sodium.encrypt(key, {type: 'plain', data: 'same'});
      ivs.add(cipher.iv);
    }
    expect(ivs.size).toBe(10);
  });
});

describe('encryptMulti and decryptMulti', () => {
  it('round trips a batch and preserves order', async () => {
    const key = await freshKey();
    const messages = ['first', 'second', 'third', '', 'fifth'];
    const ciphers = await Sodium.encryptMulti(
      key,
      messages.map(data => ({type: 'plain' as const, data})),
    );
    expect(ciphers).toHaveLength(messages.length);

    const plains = await Sodium.decryptMulti(
      key,
      ciphers.map(c => asCipher(c, 'plain')),
    );
    expect(plains).toEqual(messages);
  });

  it('round trips a batch keyed by password', async () => {
    const messages = ['alpha', 'beta', 'gamma'];
    const ciphers = await Sodium.encryptMulti(
      {password: PASSWORD},
      messages.map(data => ({type: 'plain' as const, data})),
    );
    const plains = await Sodium.decryptMulti(
      {password: PASSWORD},
      ciphers.map(c => asCipher(c, 'plain')),
    );
    expect(plains).toEqual(messages);
  });

  it('handles an empty batch', async () => {
    const key = await freshKey();
    expect(await Sodium.encryptMulti(key, [])).toEqual([]);
    expect(await Sodium.decryptMulti(key, [])).toEqual([]);
  });

  it('produces ciphers that the single-item API can decrypt', async () => {
    const key = await freshKey();
    const [cipher] = await Sodium.encryptMulti(key, [
      {type: 'plain', data: 'cross compatible'},
    ]);
    const plain = await Sodium.decrypt(key, asCipher(cipher, 'plain'));
    expect(plain).toBe('cross compatible');
  });

  it('decrypts ciphers produced by the single-item API', async () => {
    const key = await freshKey();
    const cipher = await Sodium.encrypt(key, {
      type: 'plain',
      data: 'also cross compatible',
    });
    const plains = await Sodium.decryptMulti(key, [asCipher(cipher, 'plain')]);
    expect(plains).toEqual(['also cross compatible']);
  });

  it('rejects once, without crashing, when an item in the batch is corrupt', async () => {
    // On iOS this used to reject and keep looping, and the next successful item
    // assigned past the end of the results array, raising NSRangeException.
    const key = await freshKey();
    const ciphers: any[] = await Sodium.encryptMulti(key, [
      {type: 'plain', data: 'one'},
      {type: 'plain', data: 'two'},
      {type: 'plain', data: 'three'},
    ]);

    const corrupted = fromBase64(ciphers[0].cipher);
    corrupted[0] ^= 0xff;
    ciphers[0] = {...ciphers[0], cipher: toUrlSafeBase64(corrupted)};

    const error = await rejects(() =>
      Sodium.decryptMulti(
        key,
        ciphers.map(c => asCipher(c, 'plain')),
      ),
    );
    expect(error.message.length).toBeGreaterThan(0);
  });

  it('stays consistent across a large batch', async () => {
    const key = await freshKey();
    const messages = Array.from({length: 200}, (_, i) => `item ${i}`);
    const ciphers = await Sodium.encryptMulti(
      key,
      messages.map(data => ({type: 'plain' as const, data})),
    );
    const plains = await Sodium.decryptMulti(
      key,
      ciphers.map(c => asCipher(c, 'plain')),
    );
    expect(plains).toEqual(messages);
  });
});
