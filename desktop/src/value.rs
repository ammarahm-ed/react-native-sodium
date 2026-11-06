use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use rn_gpui_module::{ModuleError, Value};

pub const KEY_LENGTH: usize = 32;
pub const SALT_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 24;
pub const A_BYTES: usize = 16;

pub fn error(message: impl Into<String>) -> ModuleError {
    ModuleError::with_code("ESODIUM", message.into())
}

pub fn field<'a>(map: &'a Value, name: &str) -> Option<&'a Value> {
    match map {
        Value::Object(fields) => fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value),
        _ => None,
    }
}

pub fn opt_string<'a>(map: &'a Value, name: &str) -> Option<&'a str> {
    match field(map, name) {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}

pub fn require_string<'a>(map: &'a Value, name: &str, owner: &str) -> Result<&'a str, ModuleError> {
    opt_string(map, name).ok_or_else(|| error(format!("{owner}: '{name}' is missing")))
}

pub fn opt_number(map: &Value, name: &str) -> Option<f64> {
    match field(map, name) {
        Some(Value::Number(value)) => Some(*value),
        _ => None,
    }
}

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(value: &str, field: &str) -> Result<Vec<u8>, ModuleError> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|e| error(format!("'{field}' is not valid url-safe base64: {e}")))
}

pub fn decode_any(value: &str, owner: &str, field: &str) -> Result<Vec<u8>, ModuleError> {
    let normalized = value.trim_end_matches('=').replace('-', "+").replace('_', "/");
    STANDARD_NO_PAD
        .decode(normalized)
        .map_err(|e| error(format!("{owner}: '{field}' is not valid base64: {e}")))
}

pub fn encode_standard(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn random(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    unsafe { libsodium_sys::randombytes_buf(buf.as_mut_ptr().cast(), size) };
    buf
}
