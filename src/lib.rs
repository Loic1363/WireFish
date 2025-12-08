pub mod core {
    pub mod capture;
    pub mod parser;
    pub mod classifier;
    pub mod enrichment;
    pub mod alerts;
    pub mod models;
}

/// Public API surface for embedders (e.g., Tauri)
pub fn devices() -> Vec<String> {
    core::capture::list_devices()
}
