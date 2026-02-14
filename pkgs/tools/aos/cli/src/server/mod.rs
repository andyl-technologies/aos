pub mod auth;
pub mod bootstrap;
pub mod build;
pub mod compress;
pub mod config;
pub mod drain;
pub mod evict;
pub mod narinfo;
pub mod pack;
pub mod routes;
pub mod store;
pub mod tokens;
pub mod views;

use std::path::PathBuf;

/// AOS root directory. Override at runtime via AOS_ROOT env var.
/// Default: /var/lib/aos
pub fn aos_root() -> PathBuf {
    std::env::var("AOS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/aos"))
}
