use std::path::PathBuf;

fn main() {
    #[cfg(feature = "uniffi")]
    uniffi_bindgen::generate_scaffolding(
        PathBuf::from("nexapipe_client.udl"),
        uniffi_bindgen::Config::default(),
    );
}
