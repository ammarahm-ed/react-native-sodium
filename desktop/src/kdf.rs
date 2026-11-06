use rn_gpui_module::{ModuleError, Value};

use crate::value::{self, error, KEY_LENGTH, SALT_LENGTH};

const APP_SALT: &str = "oVzKtazBo7d8sb7TBvY9jw";

fn pwhash(
    password: &[u8],
    salt: &[u8],
    memlimit: usize,
    alg: u32,
) -> Result<[u8; KEY_LENGTH], ModuleError> {
    if salt.len() != SALT_LENGTH {
        return Err(error(format!(
            "crypto_pwhash: salt must decode to {SALT_LENGTH} bytes but decoded to {}",
            salt.len()
        )));
    }
    let mut key = [0u8; KEY_LENGTH];
    let result = unsafe {
        libsodium_sys::crypto_pwhash(
            key.as_mut_ptr(),
            KEY_LENGTH as u64,
            password.as_ptr().cast(),
            password.len() as u64,
            salt.as_ptr(),
            3,
            memlimit,
            alg as i32,
        )
    };
    if result != 0 {
        return Err(error("crypto_pwhash: failed"));
    }
    Ok(key)
}

pub fn key_from_password(
    password: &str,
    salt: Option<&[u8]>,
) -> Result<([u8; KEY_LENGTH], Vec<u8>), ModuleError> {
    let salt = match salt {
        Some(salt) => salt.to_vec(),
        None => value::random(SALT_LENGTH),
    };
    let key = pwhash(
        password.as_bytes(),
        &salt,
        8 * 1024 * 1024,
        libsodium_sys::crypto_pwhash_ALG_ARGON2I13,
    )?;
    Ok((key, salt))
}

pub fn derive_key(password: &str, salt: Option<&str>) -> Result<Value, ModuleError> {
    let salt = salt.map(|s| value::decode(s, "salt")).transpose()?;
    let (key, salt) = key_from_password(password, salt.as_deref())
        .map_err(|e| error(format!("deriveKey: {}", e.message)))?;
    Ok(Value::object([
        ("key", Value::String(value::encode(&key))),
        ("salt", Value::String(value::encode(&salt))),
    ]))
}

pub fn hash_password(password: &str, email: &str) -> Result<String, ModuleError> {
    let input = format!("{APP_SALT}{email}");
    let mut salt = [0u8; SALT_LENGTH];
    unsafe {
        libsodium_sys::crypto_generichash(
            salt.as_mut_ptr(),
            SALT_LENGTH,
            input.as_ptr(),
            input.len() as u64,
            std::ptr::null(),
            0,
        )
    };
    let key = pwhash(
        password.as_bytes(),
        &salt,
        64 * 1024 * 1024,
        libsodium_sys::crypto_pwhash_ALG_ARGON2ID13,
    )
    .map_err(|e| error(format!("hashPassword: {}", e.message)))?;
    Ok(value::encode(&key))
}

pub fn get_key(
    password: &Value,
    cipher_salt: Option<&str>,
) -> Result<([u8; KEY_LENGTH], Vec<u8>), ModuleError> {
    if let (Some(key), Some(salt)) = (
        value::opt_string(password, "key"),
        value::opt_string(password, "salt"),
    ) {
        let key = value::decode(key, "key")?;
        let salt = value::decode(salt, "salt")?;
        let key: [u8; KEY_LENGTH] = key.try_into().map_err(|k: Vec<u8>| {
            error(format!(
                "getKey: 'key' must decode to {KEY_LENGTH} bytes but decoded to {}",
                k.len()
            ))
        })?;
        return Ok((key, salt));
    }
    if let Some(password) = value::opt_string(password, "password") {
        let salt = cipher_salt.map(|s| value::decode(s, "salt")).transpose()?;
        return key_from_password(password, salt.as_deref());
    }
    Err(error("getKey: expected { key, salt } or { password }"))
}
