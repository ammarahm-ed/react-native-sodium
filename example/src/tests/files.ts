import Sodium from '@ammarahmed/react-native-sodium';
import {NativeEventEmitter, NativeModules} from 'react-native';
import {describe, expect, it, rejects} from '../harness';
import {
  bytesEqual,
  cacheFileSize,
  fromBase64,
  nativeUri,
  pseudoRandomBytes,
  randomId,
  removeQuietly,
  toBase64,
  writeScratchFile,
} from '../util';

const CHUNK = 512 * 1024;
const PASSWORD = 'file-encryption-password';

type FileCipherOut = {
  iv: string;
  salt: string;
  hash: string;
  hashType: string;
  chunkSize: number;
  size: number;
};

async function encryptBytes(bytes: Uint8Array) {
  const key = await Sodium.deriveKey(PASSWORD);
  const path = await writeScratchFile(bytes);
  const output = (await Sodium.encryptFile(key, {
    uri: nativeUri(path),
    type: 'url',
  })) as unknown as FileCipherOut;
  return {key, path, output};
}

/** Encrypts `bytes`, decrypts them straight back and compares. */
async function roundTrip(bytes: Uint8Array) {
  const {key, path, output} = await encryptBytes(bytes);
  try {
    expect(output.size).toBe(bytes.length);

    const b64 = await Sodium.decryptFile(
      key,
      {
        iv: output.iv,
        salt: output.salt,
        hash: output.hash,
        chunkSize: output.chunkSize,
      },
      'base64',
    );
    expect(bytesEqual(fromBase64(b64), bytes)).toBe(true);
  } finally {
    await removeQuietly(path);
  }
}

describe('file encryption', () => {
  it('round trips a small file', async () => {
    await roundTrip(pseudoRandomBytes(1024, 3));
  });

  it('reports the exact plaintext size', async () => {
    // available() used to stand in for the file length, and on a pipe backed
    // content provider it can be far short of the real thing.
    const bytes = pseudoRandomBytes(300000, 11);
    const {path, output} = await encryptBytes(bytes);
    try {
      expect(output.size).toBe(bytes.length);
    } finally {
      await removeQuietly(path);
    }
  });

  it('reports hashType as xxh64 on both platforms', async () => {
    // Android reported "xxh3" while computing xxhash64.
    const {path, output} = await encryptBytes(pseudoRandomBytes(64, 5));
    try {
      expect(output.hashType).toBe('xxh64');
    } finally {
      await removeQuietly(path);
    }
  });

  it('reports a chunk size of 512 KiB', async () => {
    const {path, output} = await encryptBytes(pseudoRandomBytes(64, 5));
    try {
      expect(output.chunkSize).toBe(CHUNK);
    } finally {
      await removeQuietly(path);
    }
  });

  it('round trips an empty file', async () => {
    // A zero length input must still produce one final-tagged chunk.
    await roundTrip(new Uint8Array(0));
  });

  it('round trips a single byte file', async () => {
    await roundTrip(pseudoRandomBytes(1, 13));
  });

  it('round trips a file one byte under the chunk size', async () => {
    await roundTrip(pseudoRandomBytes(CHUNK - 1, 17));
  });

  it('round trips a file exactly one chunk long', async () => {
    await roundTrip(pseudoRandomBytes(CHUNK, 19));
  });

  it('round trips a file one byte over the chunk size', async () => {
    await roundTrip(pseudoRandomBytes(CHUNK + 1, 23));
  });

  it('round trips a file exactly two chunks long', async () => {
    await roundTrip(pseudoRandomBytes(CHUNK * 2, 29));
  });

  it('round trips a multi chunk file with a partial tail', async () => {
    await roundTrip(pseudoRandomBytes(CHUNK * 3 + 12345, 31));
  });

  it('writes a ciphertext of the expected length', async () => {
    const bytes = pseudoRandomBytes(CHUNK + 1000, 37);
    const {path, output} = await encryptBytes(bytes);
    try {
      // Two chunks, each carrying a 17 byte tag.
      const expected = bytes.length + 2 * 17;
      expect(await cacheFileSize(output.hash)).toBe(expected);
    } finally {
      await removeQuietly(path);
    }
  });

  it('decrypts to text', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const message = 'a text payload that survives a round trip';
    const path = await writeScratchFile(
      Uint8Array.from(message.split('').map(c => c.charCodeAt(0))),
    );
    try {
      const output = (await Sodium.encryptFile(key, {
        uri: nativeUri(path),
        type: 'url',
      })) as unknown as FileCipherOut;

      const text = await Sodium.decryptFile(
        key,
        {
          iv: output.iv,
          salt: output.salt,
          hash: output.hash,
          chunkSize: output.chunkSize,
        },
        'text',
      );
      expect(text).toBe(message);
    } finally {
      await removeQuietly(path);
    }
  });

  it('encrypts from a base64 payload', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const bytes = pseudoRandomBytes(4096, 41);
    const output = (await Sodium.encryptFile(key, {
      uri: '',
      type: 'base64',
      data: toBase64(bytes),
    })) as unknown as FileCipherOut;

    expect(output.size).toBe(bytes.length);

    const b64 = await Sodium.decryptFile(
      key,
      {
        iv: output.iv,
        salt: output.salt,
        hash: output.hash,
        chunkSize: output.chunkSize,
      },
      'base64',
    );
    expect(bytesEqual(fromBase64(b64), bytes)).toBe(true);
  });

  it('round trips using a password rather than a key', async () => {
    const bytes = pseudoRandomBytes(2048, 43);
    const path = await writeScratchFile(bytes);
    try {
      const output = (await Sodium.encryptFile(
        {password: PASSWORD},
        {uri: nativeUri(path), type: 'url'},
      )) as unknown as FileCipherOut;

      const b64 = await Sodium.decryptFile(
        {password: PASSWORD},
        {
          iv: output.iv,
          salt: output.salt,
          hash: output.hash,
          chunkSize: output.chunkSize,
        },
        'base64',
      );
      expect(bytesEqual(fromBase64(b64), bytes)).toBe(true);
    } finally {
      await removeQuietly(path);
    }
  });

  it('rejects decryption with the wrong key', async () => {
    const bytes = pseudoRandomBytes(1024, 47);
    const {path, output} = await encryptBytes(bytes);
    const wrong = await Sodium.deriveKey('not the right password');
    try {
      const error = await rejects(() =>
        Sodium.decryptFile(
          wrong,
          {
            iv: output.iv,
            salt: output.salt,
            hash: output.hash,
            chunkSize: output.chunkSize,
          },
          'base64',
        ),
      );
      expect(error.message.length).toBeGreaterThan(0);
    } finally {
      await removeQuietly(path);
    }
  });

  it('falls back to the default chunk size when the cipher omits one', async () => {
    const bytes = pseudoRandomBytes(1024, 53);
    const {key, path, output} = await encryptBytes(bytes);
    try {
      const b64 = await Sodium.decryptFile(
        key,
        {iv: output.iv, salt: output.salt, hash: output.hash},
        'base64',
      );
      expect(bytesEqual(fromBase64(b64), bytes)).toBe(true);
    } finally {
      await removeQuietly(path);
    }
  });

  it('emits progress while encrypting a multi chunk file', async () => {
    const emitter = new NativeEventEmitter(NativeModules.Sodium);
    const events: {total: number; progress: number}[] = [];
    const subscription = emitter.addListener('onSodiumProgress', e =>
      events.push(e),
    );
    try {
      const {path} = await encryptBytes(pseudoRandomBytes(CHUNK * 3, 59));
      await removeQuietly(path);
      expect(events.length).toBeGreaterThan(1);
      expect(events[0].total).toBeGreaterThan(1);
    } finally {
      subscription.remove();
    }
  });
});

describe('file hashing', () => {
  it('hashes a file to a stable value', async () => {
    const bytes = pseudoRandomBytes(10000, 61);
    const path = await writeScratchFile(bytes);
    try {
      const first = await Sodium.hashFile({uri: nativeUri(path), type: 'url'});
      const second = await Sodium.hashFile({uri: nativeUri(path), type: 'url'});
      expect(first).toBe(second);
      expect(first).toMatch(/^[0-9a-f]{1,16}$/);
    } finally {
      await removeQuietly(path);
    }
  });

  it('agrees between the file path and base64 code paths', async () => {
    // Two separate implementations inside the module, so this is a real check.
    const bytes = pseudoRandomBytes(20000, 67);
    const path = await writeScratchFile(bytes);
    try {
      const fromFile = await Sodium.hashFile({uri: nativeUri(path), type: 'url'});
      const fromB64 = await Sodium.hashFile({
        uri: '',
        type: 'base64',
        data: toBase64(bytes),
      });
      expect(fromFile).toBe(fromB64);
    } finally {
      await removeQuietly(path);
    }
  });

  it('separates different content', async () => {
    const a = await Sodium.hashFile({
      uri: '',
      type: 'base64',
      data: toBase64(pseudoRandomBytes(4096, 71)),
    });
    const b = await Sodium.hashFile({
      uri: '',
      type: 'base64',
      data: toBase64(pseudoRandomBytes(4096, 73)),
    });
    expect(a).notToBe(b);
  });

  it('hashes a multi chunk file consistently', async () => {
    const bytes = pseudoRandomBytes(CHUNK * 2 + 777, 79);
    const path = await writeScratchFile(bytes);
    try {
      const fromFile = await Sodium.hashFile({uri: nativeUri(path), type: 'url'});
      const fromB64 = await Sodium.hashFile({
        uri: '',
        type: 'base64',
        data: toBase64(bytes),
      });
      expect(fromFile).toBe(fromB64);
    } finally {
      await removeQuietly(path);
    }
  });

  it('hashes an empty input', async () => {
    const path = await writeScratchFile(new Uint8Array(0), randomId('empty_'));
    try {
      const hash = await Sodium.hashFile({uri: nativeUri(path), type: 'url'});
      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    } finally {
      await removeQuietly(path);
    }
  });
});
