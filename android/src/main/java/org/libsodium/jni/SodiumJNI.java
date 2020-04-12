package org.libsodium.jni;

public class SodiumJNI {
  public final static native int sodium_init();

  public final static native void randombytes_buf(byte[] buf, int size);

  public final static native int crypto_pwhash(byte[] out, final long olen, final byte[] password, final long plen, byte[] salt, long opslimit, long memlimit, int algo);
  public final static native int crypto_pwhash_salt_bytes();
  public final static native int crypto_pwhash_opslimit_moderate();
  public final static native int crypto_pwhash_opslimit_min();
  public final static native int crypto_pwhash_opslimit_max();
  public final static native int crypto_pwhash_memlimit_moderate();
  public final static native int crypto_pwhash_memlimit_min();
  public final static native int crypto_pwhash_memlimit_max();
  public final static native int crypto_pwhash_algo_default();
  public final static native int crypto_pwhash_algo_argon2i13();
  public final static native int crypto_pwhash_algo_argon2id13();

  public final static native int crypto_aead_xchacha20poly1305_ietf_encrypt(byte[] cipher, int cipher_len, byte[] msg, int msg_len, byte[] nonce, byte[] key);
  public final static native int crypto_aead_xchacha20poly1305_ietf_decrypt(byte[] plainText, int plainText_len, byte[] cipher, int cipher_len, byte[] nonce, byte[] key);
  public final static native int crypto_aead_xchacha20poly1305_ietf_abytes();
  public final static native int crypto_aead_xchacha20poly1305_ietf_keybytes();
  public final static native int crypto_aead_xchacha20poly1305_ietf_npubbytes();

}
