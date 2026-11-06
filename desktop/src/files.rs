use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use rn_gpui_module::{ModuleError, Value};
use xxhash_rust::xxh64::Xxh64;

use crate::kdf::get_key;
use crate::value::{self, error, IV_LENGTH};
use crate::Sodium;

const CHUNK_SIZE: usize = 512 * 1024;
const A_BYTES: usize = 17;
const TAG_MESSAGE: u8 = 0;
const TAG_FINAL: u8 = 3;

fn cache_file(name: &str) -> Result<PathBuf, ModuleError> {
    let dir = dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("react-native-sodium")
        .join(".cache");
    fs::create_dir_all(&dir).map_err(|e| error(format!("cache directory: {e}")))?;
    Ok(dir.join(name))
}

fn local_path(uri: &str) -> PathBuf {
    PathBuf::from(uri.strip_prefix("file://").unwrap_or(uri))
}

fn open_input(data: &Value) -> Result<Box<dyn Read>, ModuleError> {
    if value::opt_string(data, "type") == Some("base64") {
        let b64 = value::require_string(data, "data", "getInputStream")?;
        return Ok(Box::new(std::io::Cursor::new(value::decode_any(
            b64,
            "getInputStream",
            "data",
        )?)));
    }
    let uri = value::require_string(data, "uri", "getInputStream")?;
    let file = File::open(local_path(uri)).map_err(|e| error(format!("{uri}: {e}")))?;
    Ok(Box::new(file))
}

fn read_full(input: &mut dyn Read, buffer: &mut [u8]) -> Result<usize, ModuleError> {
    let mut total = 0;
    while total < buffer.len() {
        let read = input
            .read(&mut buffer[total..])
            .map_err(|e| error(e.to_string()))?;
        if read == 0 {
            break;
        }
        total += read;
    }
    Ok(total)
}

pub fn hash_file(data: &Value) -> Result<String, ModuleError> {
    let mut input = open_input(data)?;
    let mut hash = Xxh64::new(0);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read = read_full(&mut *input, &mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.digest()))
}

fn transform(
    module: &Sodium,
    state: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
    input: &mut dyn Read,
    output: &mut dyn Write,
    chunk_size: usize,
    decrypt: bool,
    total_chunks: f64,
) -> Result<usize, ModuleError> {
    let mut current = vec![0u8; chunk_size];
    let mut next = vec![0u8; chunk_size];
    let mut out = vec![0u8; chunk_size + A_BYTES];
    let mut processed = 0;
    let mut index = 0usize;
    let mut current_length = read_full(input, &mut current)?;
    loop {
        let next_length = read_full(input, &mut next)?;
        let is_final = next_length == 0;
        let mut out_length = 0u64;
        let result = if decrypt {
            if current_length < A_BYTES {
                return Err(error("truncated ciphertext"));
            }
            let mut tag = 0u8;
            unsafe {
                libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
                    state,
                    out.as_mut_ptr(),
                    &mut out_length,
                    &mut tag,
                    current.as_ptr(),
                    current_length as u64,
                    std::ptr::null(),
                    0,
                )
            }
        } else {
            unsafe {
                libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
                    state,
                    out.as_mut_ptr(),
                    &mut out_length,
                    current.as_ptr(),
                    current_length as u64,
                    std::ptr::null(),
                    0,
                    if is_final { TAG_FINAL } else { TAG_MESSAGE },
                )
            }
        };
        if result != 0 {
            return Err(error(format!("secretstream failed on chunk {}", index + 1)));
        }
        output
            .write_all(&out[..out_length as usize])
            .map_err(|e| error(e.to_string()))?;
        processed += if decrypt { out_length as usize } else { current_length };
        module.progress(total_chunks.max((index + 1) as f64), index as f64);
        index += 1;
        std::mem::swap(&mut current, &mut next);
        current_length = next_length;
        if current_length == 0 {
            break;
        }
    }
    output.flush().map_err(|e| error(e.to_string()))?;
    Ok(processed)
}

fn total_chunks(data: &Value, chunk_size: usize) -> f64 {
    let size = match value::opt_string(data, "type") {
        Some("base64") => value::opt_string(data, "data").map_or(0, |d| d.len() * 3 / 4),
        _ => value::opt_string(data, "uri")
            .and_then(|uri| fs::metadata(local_path(uri)).ok())
            .map_or(0, |m| m.len() as usize),
    };
    (size as f64 / chunk_size as f64).ceil().max(1.0)
}

pub fn encrypt_file(
    module: &Sodium,
    password: &Value,
    data: &Value,
) -> Result<Value, ModuleError> {
    let (key, salt) = get_key(password, None)?;
    let hash = match value::opt_string(data, "hash") {
        Some(hash) => hash.to_string(),
        None => hash_file(data)?,
    };
    let total = total_chunks(data, CHUNK_SIZE);
    let mut input = open_input(data)?;
    let mut header = [0u8; IV_LENGTH];
    let mut state = unsafe { std::mem::zeroed() };
    unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
            &mut state,
            header.as_mut_ptr(),
            key.as_ptr(),
        )
    };
    let mut output = File::create(cache_file(&hash)?).map_err(|e| error(e.to_string()))?;
    let length = transform(module, &mut state, &mut *input, &mut output, CHUNK_SIZE, false, total)?;
    Ok(Value::object([
        ("iv", Value::String(value::encode(&header))),
        ("salt", Value::String(value::encode(&salt))),
        ("length", Value::Number(length as f64)),
        ("hash", Value::String(hash)),
        ("hashType", Value::String("xxh64".into())),
        ("chunkSize", Value::Number(CHUNK_SIZE as f64)),
        ("size", Value::Number(length as f64)),
    ]))
}

pub fn decrypt_file(
    module: &Sodium,
    password: &Value,
    cipher: &Value,
    kind: &str,
) -> Result<String, ModuleError> {
    let chunk_size = value::opt_number(cipher, "chunkSize").map_or(CHUNK_SIZE, |c| c as usize);
    let (key, _) = get_key(password, value::opt_string(cipher, "salt"))?;
    let hash = value::require_string(cipher, "hash", "decryptFile")?;
    let header = value::decode(value::require_string(cipher, "iv", "decryptFile")?, "iv")?;
    if header.len() != IV_LENGTH {
        return Err(error("decryptFile: malformed iv"));
    }
    let mut state = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
            &mut state,
            header.as_ptr(),
            key.as_ptr(),
        )
    };
    if result != 0 {
        return Err(error("decryptFile: invalid header"));
    }
    let source = cache_file(hash)?;
    let size = fs::metadata(&source).map_or(0, |m| m.len() as usize);
    let step = chunk_size + A_BYTES;
    let total = (size as f64 / step as f64).ceil().max(1.0);
    let mut input = File::open(&source).map_err(|e| error(format!("{}: {e}", source.display())))?;

    let (mut sink, destination): (Box<dyn Write>, Option<PathBuf>) = match kind {
        "base64" | "text" => (Box::new(std::io::sink()), None),
        "cache" => {
            let path = cache_file(&format!("{hash}_dcache"))?;
            (
                Box::new(File::create(&path).map_err(|e| error(e.to_string()))?),
                Some(path),
            )
        }
        _ => {
            let dir = local_path(value::require_string(cipher, "uri", "decryptFile")?);
            let name = value::require_string(cipher, "fileName", "decryptFile")?;
            let path = dir.join(name);
            (
                Box::new(File::create(&path).map_err(|e| error(e.to_string()))?),
                Some(path),
            )
        }
    };

    if destination.is_some() {
        transform(module, &mut state, &mut input, &mut *sink, step, true, total)?;
        return Ok(destination.unwrap().to_string_lossy().into_owned());
    }
    let mut buffer = Vec::new();
    {
        let mut writer = std::io::Cursor::new(&mut buffer);
        transform(module, &mut state, &mut input, &mut writer, step, true, total)?;
    }
    if kind == "base64" {
        Ok(value::encode_standard(&buffer))
    } else {
        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }
}
