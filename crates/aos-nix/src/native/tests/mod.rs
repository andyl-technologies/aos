//! Unit and oracle-differential tests for the native evaluator shim.

use super::*;
use crate::eval::IfdRealizationError;
use std::fs;
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
