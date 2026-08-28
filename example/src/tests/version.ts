import Sodium from '@ammarahmed/react-native-sodium';
import {describe, expect, it, within} from '../harness';

describe('module surface', () => {
  it('exposes the native module', () => {
    expect(Sodium).toBeDefined();
  });

  it('sodium_version_string resolves a version', async () => {
    // Declared in index.ts since forever but implemented on neither platform
    // until recently, so calling it used to be a TypeError.
    const version = await within(5000, Sodium.sodium_version_string());
    expect(typeof version).toBe('string');
    expect(version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('declares every method the typescript API promises', () => {
    const required = [
      'sodium_version_string',
      'encrypt',
      'decrypt',
      'encryptMulti',
      'decryptMulti',
      'hashPassword',
      'deriveKey',
      'encryptFile',
      'decryptFile',
      'hashFile',
    ];
    const missing = required.filter(
      name => typeof (Sodium as any)[name] !== 'function',
    );
    expect(missing).toEqual([]);
  });
});
