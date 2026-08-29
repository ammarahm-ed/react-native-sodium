/**
 * Opt-in benchmarks. "Run all" skips this group; tap its chip to run it.
 *
 * The harness already records wall time per test, so each `it` here is one
 * measurement. Throughput is logged so it shows up alongside the results.
 */
import Sodium, {Cipher} from '@ammarahmed/react-native-sodium';
import {describe, expect, it} from '../harness';
import {
  nativeUri,
  pseudoRandomBytes,
  removeQuietly,
  repeatString,
  toBase64,
  writeScratchFile,
} from '../util';

const PASSWORD = 'benchmark-password';

const WARMUP = 1;
const RUNS = 5;

/**
 * A cold first call measures dex verification, JNA registration and JIT warmup
 * rather than the operation, and on Android that is an order of magnitude more
 * than the work itself. So: discard warmup runs, then report the median of
 * several, which is also stable against a scheduler hiccup.
 */
async function measure<T>(
  label: string,
  bytes: number,
  fn: () => Promise<T>,
): Promise<T> {
  let out!: T;
  for (let i = 0; i < WARMUP; i++) out = await fn();

  const samples: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const started = Date.now();
    out = await fn();
    samples.push(Date.now() - started);
  }
  samples.sort((a, b) => a - b);
  const median = samples[Math.floor(samples.length / 2)];

  const detail =
    bytes > 0
      ? ` | ${(bytes / 1024 / 1024).toFixed(2)} MiB | ${(
          bytes /
          1024 /
          1024 /
          (median / 1000)
        ).toFixed(1)} MiB/s`
      : '';
  console.log(
    `SODIUM_BENCH ${label} | median ${median}ms of [${samples.join(', ')}]${detail}`,
  );
  return out;
}

const timed = measure;

describe.manual('benchmarks', () => {
  it('deriveKey (argon2i, 8 MiB, 3 passes)', async () => {
    await measure('deriveKey', 0, () => Sodium.deriveKey(PASSWORD));
  });

  it('hashPassword (argon2id, 64 MiB, 3 passes)', async () => {
    await measure('hashPassword', 0, () =>
      Sodium.hashPassword(PASSWORD, 'bench@example.com'),
    );
  });

  it('encrypt+decrypt 1 MiB string', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const data = repeatString('0123456789abcdef', 1024 * 1024);
    const cipher = await timed('encrypt 1MiB', data.length, () =>
      Sodium.encrypt(key, {type: 'plain', data}),
    );
    const plain = await timed('decrypt 1MiB', data.length, () =>
      Sodium.decrypt(key, {...cipher, output: 'plain'} as Cipher<'base64'>),
    );
    expect(plain.length).toBe(data.length);
  });

  it('encryptMulti+decryptMulti 500 small items (the sync path)', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const items = Array.from({length: 500}, (_, i) =>
      JSON.stringify({id: `note_${i}`, title: `Note ${i}`, body: 'x'.repeat(400)}),
    );
    const bytes = items.reduce((n, s) => n + s.length, 0);

    const ciphers = await timed('encryptMulti x500', bytes, () =>
      Sodium.encryptMulti(
        key,
        items.map(data => ({type: 'plain' as const, data})),
      ),
    );
    const plains = await timed('decryptMulti x500', bytes, () =>
      Sodium.decryptMulti(
        key,
        ciphers.map(c => ({...c, output: 'plain'}) as Cipher<'base64'>),
      ),
    );
    expect(plains.length).toBe(items.length);
  });

  it('encryptFile+decryptFile 10 MiB', async () => {
    const key = await Sodium.deriveKey(PASSWORD);
    const bytes = pseudoRandomBytes(10 * 1024 * 1024, 5);
    const path = await writeScratchFile(bytes);
    try {
      const out: any = await timed('encryptFile 10MiB', bytes.length, () =>
        Sodium.encryptFile(key, {uri: nativeUri(path), type: 'url'}),
      );
      await timed('decryptFile 10MiB -> base64', bytes.length, () =>
        Sodium.decryptFile(
          key,
          {iv: out.iv, salt: out.salt, hash: out.hash, chunkSize: out.chunkSize},
          'base64',
        ),
      );
      await timed('decryptFile 10MiB -> cache', bytes.length, () =>
        Sodium.decryptFile(
          key,
          {iv: out.iv, salt: out.salt, hash: out.hash, chunkSize: out.chunkSize},
          'cache',
        ),
      );
    } finally {
      await removeQuietly(path);
    }
  });

  it('hashFile 10 MiB from a path', async () => {
    const bytes = pseudoRandomBytes(10 * 1024 * 1024, 7);
    const path = await writeScratchFile(bytes);
    try {
      await timed('hashFile 10MiB (path)', bytes.length, () =>
        Sodium.hashFile({uri: nativeUri(path), type: 'url'}),
      );
    } finally {
      await removeQuietly(path);
    }
  });

  it('hashFile 10 MiB from base64', async () => {
    const bytes = pseudoRandomBytes(10 * 1024 * 1024, 11);
    const b64 = toBase64(bytes);
    await timed('hashFile 10MiB (base64)', bytes.length, () =>
      Sodium.hashFile({uri: '', type: 'base64', data: b64}),
    );
  });
});
