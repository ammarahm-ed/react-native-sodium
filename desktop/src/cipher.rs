use rn_gpui_module::{ModuleError, Value};

use crate::kdf::get_key;
use crate::value::{self, error, A_BYTES, IV_LENGTH, KEY_LENGTH};

pub fn cipher_data(iv: &[u8], salt: &[u8], length: usize, cipher: Option<&[u8]>) -> Value {
    let mut fields = vec![
        ("iv".to_string(), Value::String(value::encode(iv))),
        ("salt".to_string(), Value::String(value::encode(salt))),
        ("length".to_string(), Value::Number(length as f64)),
    ];
    if let Some(cipher) = cipher {
        fields.push(("cipher".to_string(), Value::String(value::encode(cipher))));
    }
    Value::Object(fields)
}

fn seal(key: &[u8; KEY_LENGTH], salt: &[u8], data: &Value) -> Result<Value, ModuleError> {
    let plain = value::require_string(data, "data", "encrypt")?;
    let bytes = if value::opt_string(data, "type") == Some("b64") {
        value::decode_any(plain, "encrypt", "data")?
    } else {
        plain.as_bytes().to_vec()
    };
    let iv = value::random(IV_LENGTH);
    let mut cipher = vec![0u8; bytes.len() + A_BYTES];
    let mut cipher_length = 0u64;
    let result = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher.as_mut_ptr(),
            &mut cipher_length,
            bytes.as_ptr(),
            bytes.len() as u64,
            std::ptr::null(),
            0,
            std::ptr::null(),
            iv.as_ptr(),
            key.as_ptr(),
        )
    };
    if result != 0 {
        return Err(error("crypto_aead_xchacha20poly1305_ietf_encrypt failed"));
    }
    Ok(cipher_data(&iv, salt, bytes.len(), Some(&cipher)))
}

fn open(key: &[u8; KEY_LENGTH], cipher: &Value) -> Result<String, ModuleError> {
    let bytes = value::decode(value::require_string(cipher, "cipher", "decrypt")?, "cipher")?;
    let iv = value::decode(value::require_string(cipher, "iv", "decrypt")?, "iv")?;
    if bytes.len() < A_BYTES || iv.len() != IV_LENGTH {
        return Err(error("decrypt: malformed ciphertext"));
    }
    let mut plain = vec![0u8; bytes.len() - A_BYTES];
    let mut plain_length = 0u64;
    let result = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain.as_mut_ptr(),
            &mut plain_length,
            std::ptr::null_mut(),
            bytes.as_ptr(),
            bytes.len() as u64,
            std::ptr::null(),
            0,
            iv.as_ptr(),
            key.as_ptr(),
        )
    };
    if result != 0 {
        return Err(ModuleError::with_code("BAD_MAC", "FAILURE"));
    }
    if value::opt_string(cipher, "output") == Some("plain") {
        Ok(String::from_utf8_lossy(&plain).into_owned())
    } else {
        Ok(value::encode(&plain))
    }
}

pub fn encrypt(password: &Value, data: &Value) -> Result<Value, ModuleError> {
    let (key, salt) = get_key(password, None)?;
    seal(&key, &salt, data)
}

pub fn encrypt_multi(password: &Value, data: &[Value]) -> Result<Vec<Value>, ModuleError> {
    let (key, salt) = get_key(password, None)?;
    data.iter().map(|item| seal(&key, &salt, item)).collect()
}

pub fn decrypt(password: &Value, cipher: &Value) -> Result<String, ModuleError> {
    let (key, _) = get_key(password, value::opt_string(cipher, "salt"))?;
    open(&key, cipher)
}

pub fn decrypt_multi(password: &Value, data: &[Value]) -> Result<Vec<String>, ModuleError> {
    let mut cached: Option<(Option<String>, [u8; KEY_LENGTH])> = None;
    let mut results = Vec::with_capacity(data.len());
    for item in data {
        let salt = value::opt_string(item, "salt").map(str::to_string);
        let key = match &cached {
            Some((cached_salt, key)) if *cached_salt == salt => *key,
            _ => {
                let (key, _) = get_key(password, salt.as_deref())?;
                cached = Some((salt, key));
                key
            }
        };
        results.push(open(&key, item)?);
    }
    Ok(results)
}
