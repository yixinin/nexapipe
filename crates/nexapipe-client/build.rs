fn main() {
    #[cfg(feature = "uniffi")]
    uniffi_bindgen::generate_scaffolding(
        std::path::PathBuf::from("nexapipe_client.udl"),
        uniffi_bindgen::Config::default(),
    );
}
