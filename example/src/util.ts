import {Platform} from 'react-native';
import ReactNativeBlobUtil from 'react-native-blob-util';

/**
 * Where the native module keeps encrypted blobs. Mirrors Notesnook's
 * apps/mobile/app/common/filesystem/utils.ts, which reconstructs the same path
 * the native side writes to:
 *   iOS     NSLibraryDirectory + "/.cache"   (SimpleFilesCache)
 *   Android filesDir           + "/.cache"   (getFilesFromFilesDirCache)
 */
export const cacheDir =
  Platform.OS === 'ios'
    ? ReactNativeBlobUtil.fs.dirs.LibraryDir + '/.cache'
    : ReactNativeBlobUtil.fs.dirs.DocumentDir + '/.cache';

export const scratchDir = ReactNativeBlobUtil.fs.dirs.CacheDir + '/sodium-tests';

export function randomId(prefix = 'test_') {
  return prefix + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export async function ensureScratchDir() {
  if (!(await ReactNativeBlobUtil.fs.exists(scratchDir))) {
    await ReactNativeBlobUtil.fs.mkdir(scratchDir);
  }
}

/** Deterministic pseudo random bytes, so a failure can be reproduced. */
export function pseudoRandomBytes(length: number, seed = 1): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    // xorshift32
    x ^= x << 13;
    x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

const B64 =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 with padding, implemented here to avoid a Buffer polyfill. */
export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)];
    out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)] : '=';
    out += i + 2 < bytes.length ? B64[b2 & 63] : '=';
  }
  return out;
}

export function fromBase64(value: string): Uint8Array {
  const clean = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of clean) {
    const v = B64.indexOf(ch);
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.slice(0, o);
}

export function toUrlSafeBase64(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Writes `bytes` to a scratch file and returns its plain filesystem path. */
export async function writeScratchFile(
  bytes: Uint8Array,
  name = randomId('file_'),
): Promise<string> {
  await ensureScratchDir();
  const path = `${scratchDir}/${name}`;
  await ReactNativeBlobUtil.fs.writeFile(path, toBase64(bytes), 'base64');
  return path;
}

/**
 * The native module wants a plain path on iOS and a file:// URI on Android,
 * which is exactly the split Notesnook's io.ts encodes.
 */
export function nativeUri(path: string): string {
  return Platform.OS === 'ios' ? path : 'file://' + path;
}

export async function readScratchFileBase64(path: string): Promise<string> {
  return ReactNativeBlobUtil.fs.readFile(path, 'base64');
}

export async function removeQuietly(path: string) {
  try {
    await ReactNativeBlobUtil.fs.unlink(path);
  } catch {
    /* already gone */
  }
}

export async function cacheFileSize(name: string): Promise<number> {
  try {
    const stat = await ReactNativeBlobUtil.fs.stat(`${cacheDir}/${name}`);
    return Number(stat.size);
  } catch {
    return -1;
  }
}

export function repeatString(unit: string, targetLength: number): string {
  let out = '';
  while (out.length < targetLength) out += unit;
  return out.slice(0, targetLength);
}
