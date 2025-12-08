pub mod core {
    pub mod capture;
    pub mod parser;
    pub mod classifier;
    pub mod enrichment;
    pub mod alerts;
    pub mod models;
}

/// Public API pour WireFish
///
/// Exemple d’utilisation (depuis Tauri plus tard) :
/// let devices = wirefish::devices();
///
pub fn devices() -> Vec<String> {
    core::capture::list_devices()
}
