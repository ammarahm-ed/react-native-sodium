rn_gpui_module::include_specs!();

mod cipher;
mod files;
mod kdf;
mod value;

use rn_gpui_module::{ModuleError, Value};

pub struct Sodium {
    events: NativeSodiumEvents,
}

impl Sodium {
    pub(crate) fn progress(&self, total: f64, progress: f64) {
        self.events.send_event(
            "onSodiumProgress",
            Value::object([
                ("total", Value::Number(total)),
                ("progress", Value::Number(progress)),
            ]),
        );
    }
}

impl NativeSodiumSpec for Sodium {
    fn new(events: NativeSodiumEvents) -> Self {
        unsafe { libsodium_sys::sodium_init() };
        Self { events }
    }

    async fn sodium_version_string(&self) -> Result<String, ModuleError> {
        let version = unsafe { std::ffi::CStr::from_ptr(libsodium_sys::sodium_version_string()) };
        Ok(version.to_string_lossy().into_owned())
    }

    async fn encrypt(&self, password: Value, data: Value) -> Result<Value, ModuleError> {
        cipher::encrypt(&password, &data)
    }

    async fn decrypt(&self, password: Value, cipher: Value) -> Result<String, ModuleError> {
        cipher::decrypt(&password, &cipher)
    }

    async fn encrypt_multi(
        &self,
        password: Value,
        data: Vec<Value>,
    ) -> Result<Vec<Value>, ModuleError> {
        cipher::encrypt_multi(&password, &data)
    }

    async fn decrypt_multi(
        &self,
        password: Value,
        data: Vec<Value>,
    ) -> Result<Vec<String>, ModuleError> {
        cipher::decrypt_multi(&password, &data)
    }

    async fn hash_password(&self, password: String, email: String) -> Result<String, ModuleError> {
        kdf::hash_password(&password, &email)
    }

    async fn derive_key(
        &self,
        password: String,
        salt: Option<String>,
    ) -> Result<Value, ModuleError> {
        kdf::derive_key(&password, salt.as_deref())
    }

    async fn encrypt_file(&self, password: Value, data: Value) -> Result<Value, ModuleError> {
        files::encrypt_file(self, &password, &data)
    }

    async fn decrypt_file(
        &self,
        password: Value,
        cipher: Value,
        r#type: String,
    ) -> Result<String, ModuleError> {
        files::decrypt_file(self, &password, &cipher, &r#type)
    }

    async fn hash_file(&self, data: Value) -> Result<String, ModuleError> {
        files::hash_file(&data)
    }

    fn add_listener(&self, _event_name: String) {}

    fn remove_listeners(&self, _count: f64) {}
}

pub fn rn_gpui_register() {
    rn_gpui_module::register(native_sodium_module::<Sodium>());
}
