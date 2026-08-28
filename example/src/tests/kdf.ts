import Sodium from '@ammarahmed/react-native-sodium';
import {Platform} from 'react-native';
import {describe, expect, it, rejects, within} from '../harness';
import {fromBase64} from '../util';

const PASSWORD = 'correct horse battery staple';
const EMAIL = 'someone@example.com';

describe('key derivation', () => {
  it('deriveKey returns a 32 byte key and a 16 byte salt', async () => {
    const result = await Sodium.deriveKey(PASSWORD);
    expect(typeof result.key).toBe('string');
    expect(typeof result.salt).toBe('string');
    // url-safe base64, unpadded: 32 bytes -> 43 chars, 16 bytes -> 22 chars
    expect(result.key).toHaveLength(43);
    expect(result.salt).toHaveLength(22);
    expect(result.key).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.salt).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('deriveKey without a salt generates a new one each time', async () => {
    const a = await Sodium.deriveKey(PASSWORD);
    const b = await Sodium.deriveKey(PASSWORD);
    expect(a.salt).notToBe(b.salt);
    expect(a.key).notToBe(b.key);
  });

  it('deriveKey is deterministic for a given password and salt', async () => {
    const first = await Sodium.deriveKey(PASSWORD);
    const second = await Sodium.deriveKey(PASSWORD, first.salt);
    expect(second.key).toBe(first.key);
    expect(second.salt).toBe(first.salt);
  });

  it('deriveKey separates different passwords under the same salt', async () => {
    const first = await Sodium.deriveKey(PASSWORD);
    const other = await Sodium.deriveKey(PASSWORD + '!', first.salt);
    expect(other.key).notToBe(first.key);
  });

  it('deriveKey handles a non-ascii password', async () => {
    const pw = 'pässwörd-🔐-日本語';
    const first = await Sodium.deriveKey(pw);
    const again = await Sodium.deriveKey(pw, first.salt);
    expect(again.key).toBe(first.key);
  });

  it('hashPassword is deterministic for a password and email', async () => {
    const a = await Sodium.hashPassword(PASSWORD, EMAIL);
    const b = await Sodium.hashPassword(PASSWORD, EMAIL);
    expect(a).toBe(b);
    expect(a).toHaveLength(43);
  });

  it('hashPassword separates different emails', async () => {
    const a = await Sodium.hashPassword(PASSWORD, EMAIL);
    const b = await Sodium.hashPassword(PASSWORD, 'other@example.com');
    expect(a).notToBe(b);
  });

  it('hashPassword separates different passwords', async () => {
    const a = await Sodium.hashPassword(PASSWORD, EMAIL);
    const b = await Sodium.hashPassword(PASSWORD + '!', EMAIL);
    expect(a).notToBe(b);
  });

  it('hashPassword handles a non-ascii password', async () => {
    const a = await Sodium.hashPassword('pässwörd-🔐', EMAIL);
    expect(a).toHaveLength(43);
  });

  it.if(Platform.OS === 'ios')(
    'deriveKeyFallback resolves null for an ascii-only password',
    async () => {
      // The fallback exists only to reproduce a historical bug where the byte
      // length was taken from [password length]. For ascii the two agree, so
      // there is nothing to fall back to.
      const result = await Sodium.deriveKeyFallback?.(PASSWORD, 'c2FsdHNhbHRzYWx0c2E');
      expect(result).toBeNull();
    },
  );

  it.if(Platform.OS === 'ios')(
    'deriveKeyFallback returns a different key for a non-ascii password',
    async () => {
      const pw = 'pässwörd-🔐';
      const normal = await Sodium.deriveKey(pw);
      const fallback = await Sodium.deriveKeyFallback?.(pw, normal.salt as string);
      expect(fallback).toBeDefined();
      expect(fallback?.key).notToBe(normal.key);
      expect(fallback?.salt).toBe(normal.salt);
    },
  );

  it('deriveKey rejects when the salt does not decode to 16 bytes', async () => {
    // crypto_pwhash always reads crypto_pwhash_SALTBYTES from the salt pointer,
    // so anything shorter reads past the end of the buffer.
    let resolved: unknown;
    try {
      resolved = await Sodium.deriveKey(PASSWORD, '!!!not base64!!!');
    } catch (e) {
      expect((e as Error).message.length).toBeGreaterThan(0);
      return;
    }
    const salt = (resolved as {salt?: string})?.salt ?? '';
    throw new Error(
      `resolved instead of rejecting: salt=${JSON.stringify(salt)} decodes to ${
        fromBase64(salt).length
      } bytes`,
    );
  });

  it('concurrent derivations do not interfere', async () => {
    // The iOS module now runs on a concurrent queue, so this is a real
    // thread-safety check rather than a formality.
    const salt = (await Sodium.deriveKey(PASSWORD)).salt;
    const results = await within(
      120000,
      Promise.all(
        Array.from({length: 6}, (_, i) =>
          Sodium.deriveKey(PASSWORD + i, salt).then(r => r.key),
        ),
      ),
    );
    expect(new Set(results).size).toBe(results.length);

    const repeat = await Sodium.deriveKey(PASSWORD + '0', salt);
    expect(repeat.key).toBe(results[0]);
  });
});
