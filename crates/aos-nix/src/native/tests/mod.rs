//! Unit and oracle-differential tests for the native evaluator shim.

use super::*;
use crate::cache::DurableBlake3Hash;
use crate::eval::IfdRealizationError;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

mod attr_path;
mod expr_eval;
mod fallback;
mod ifd;
mod instantiate_expr;

fn native_with_temp_store(prefix: &str) -> Result<(NixNative, PathBuf, PathBuf)> {
    let root = unique_temp_dir(prefix);
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    Ok((NixNative::with_options(0, options)?, root, store))
}

fn assert_materialized_drv(path: &Path) -> Result<Vec<u8>> {
    assert!(
        path.exists(),
        "derivation was not written: {}",
        path.display()
    );
    let bytes = fs::read(path)?;
    assert!(
        bytes.starts_with(b"Derive("),
        "materialized derivation did not start with an ATerm Derive node: {}",
        path.display()
    );
    Ok(bytes)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(unique_store_name(prefix))
}

fn unique_store_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn durable_hash_surface_canaries(label: &str, hash: DurableBlake3Hash) -> Vec<(String, Vec<u8>)> {
    vec![
        (format!("{label} hex"), hash.to_hex().into_bytes()),
        (format!("{label} raw bytes"), hash.as_bytes().to_vec()),
        (
            format!("{label} Nix base32"),
            nix_compat::nixbase32::encode(&hash.as_bytes()).into_bytes(),
        ),
    ]
}

fn assert_native_closure_surfaces_do_not_contain_canaries(
    closure_name: &str,
    closure: &NativeDrvClosure,
    canaries: &[(String, Vec<u8>)],
) {
    assert_surface_canaries_absent(
        closure_name,
        "root .drv path",
        closure.root().as_os_str().as_bytes(),
        canaries,
    );
    for (path, bytes) in closure.drvs() {
        let path_name = format!(".drv path {}", path.display());
        assert_surface_canaries_absent(
            closure_name,
            &path_name,
            path.as_os_str().as_bytes(),
            canaries,
        );
        let bytes_name = format!("ATerm bytes {}", path.display());
        assert_surface_canaries_absent(closure_name, &bytes_name, bytes, canaries);
    }
}

fn assert_surface_canaries_absent(
    closure_name: &str,
    surface_name: &str,
    surface: &[u8],
    canaries: &[(String, Vec<u8>)],
) {
    for (canary_name, canary) in canaries {
        assert!(
            !contains_bytes(surface, canary),
            "{canary_name} leaked into {closure_name} {surface_name}: {surface:?}"
        );
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
