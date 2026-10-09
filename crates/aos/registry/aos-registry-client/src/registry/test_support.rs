//! Registry test fixtures shared by consumers and authoring suites.

use super::*;
use std::fs;
use tempfile::TempDir;

/// A 52-char nixbase32 SHA-256 digest for store-record fixtures.
pub const FIX_NAR: &str = "1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";

/// curl's store record: depends on zlib (`r4q1m2kp8v3x`) plus three
/// store paths not published as packages.
pub fn curl_store_record() -> (&'static str, String) {
    (
        "h7j3k8l2m9n4",
        format!(
            "nar:sha256:{FIX_NAR}:3145728\n\
             \tia:sha256:r4q1m2kp8v3x\n\
             \tia:sha256:xr5is7by89v3q\n\
             \tia:sha256:q8mn2pv73w0x\n\
             \tia:sha256:kl9m3n0p5p6q\n"
        ),
    )
}

/// zlib's store record: a leaf.
pub fn zlib_store_record() -> (&'static str, String) {
    ("r4q1m2kp8v3x", format!("nar:sha256:{FIX_NAR}:524288\n"))
}

/// Creates a registry in a temporary directory from package TOML fixtures.
///
/// # Panics
///
/// Panics for invalid fixture names or metadata, or when fixture files cannot be written.
pub fn make_registry(
    tmp: &TempDir,
    name: &str,
    priority: u32,
    toml_files: &[(&str, &str)],
) -> Registry {
    make_registry_with_store(tmp, name, priority, toml_files, &[])
}

/// Creates a registry with package TOML fixtures and signed store records.
///
/// # Panics
///
/// Panics for invalid fixture names, store identities, or metadata, or when
/// fixture files cannot be written.
pub fn make_registry_with_store(
    tmp: &TempDir,
    name: &str,
    priority: u32,
    toml_files: &[(&str, &str)],
    store_records: &[(&str, String)],
) -> Registry {
    let reg_dir = tmp.path().join(name);
    let pkg_dir = reg_dir.join("packages");
    for (pkg_name, content) in toml_files {
        let first_letter = &pkg_name[..1];
        let dir = pkg_dir.join(first_letter);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{pkg_name}.toml")), content).unwrap();
    }

    for (ia, content) in store_records {
        let dir = reg_dir.join(store::STORE_DIR).join(&ia[..2]);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(ia), content).unwrap();
    }

    let config = registry_config(name, priority);

    Registry::load(tmp.path(), &config, "x86_64-linux").unwrap()
}

/// Builds an enabled fixture registry configuration with the requested priority.
pub fn registry_config(name: &str, priority: u32) -> RegistryConfig {
    RegistryConfig {
        name: name.to_string(),
        url: format!("https://registry.example.com/{name}"),
        priority,
        enabled: true,
        commit: None,
        branch: None,
        channel: None,
        tag: None,
        version: None,
        pin: None,
        max_staleness_seconds: None,
        caches: Vec::new(),
        cache: Default::default(),
        upload_auth: None,
        signing_keys: Default::default(),
        signing: None,
    }
}
