//! Unit and oracle-differential tests for the native evaluator shim.

use super::*;
use crate::cache::{DurableBlake3Hash, PersistCache};
use crate::eval::IfdRealizationError;
use crate::string::NixString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

mod attr_path;
mod expr_eval;
mod fallback;
mod ifd;
mod instantiate_expr;
mod semantic_edit;
mod source_errors;

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

fn instantiate_file_closure_with_stats(
    native: &NixNative,
    file: &Path,
    attr: &str,
) -> Result<(NativeDrvClosure, crate::eval::EvalStats)> {
    let attr_path = attr_path_drv_path_segments(attr)?;
    let mut options = native.instantiation_options();
    let file = native_source_file(file, &options)?;
    let source_name = path_bytes(&file)?;
    let source_name_text = String::from_utf8_lossy(&source_name);
    let source = fs::read(&file).map_err(|source| NativeEvalError::EvalError {
        message: format!(
            "failed to read native instantiation source {}: {source}",
            source_name_text
        ),
    })?;
    let diagnostic_source = std::str::from_utf8(&source)
        .ok()
        .map(|source| NativeDiagnosticSource::new(source_name_text.as_ref(), source, None));
    let base = file.parent().unwrap_or_else(|| Path::new("/"));
    options.set_path_literal_base(path_bytes(base)?)?;
    let ir = native.lower_native_source_bytes(
        &source,
        Some(source_name_text.to_string()),
        Some(file.as_path()),
        None,
        diagnostic_source,
    )?;
    if let Some((feature, span)) = native_instantiation_cli_fallback_feature(&ir, &native.options) {
        return Err(NativeEvalError::Unsupported {
            feature: feature.to_string(),
            span: Some(crate::error::SrcSpan {
                start: span.start,
                end: span.end,
            }),
        }
        .into());
    }
    let outcome = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        &ir,
        &attr_path,
        options,
        source_name.clone(),
        source.clone(),
        native.ifd_realizer.clone(),
        native.eval_cache.clone(),
    )
    .map_err(|error| match diagnostic_source {
        Some(diagnostic_source) => native_eval_error_with_source(error, diagnostic_source),
        None => native_eval_error(error, None),
    })?;
    let stats = *outcome.stats();
    native.observe_eval_cache(&outcome);
    let closure = native.native_drv_closure_from_outcome(outcome)?;
    Ok((closure, stats))
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

struct TempTreeCleanup(PathBuf);

impl TempTreeCleanup {
    fn new(path: PathBuf) -> Self {
        Self(path)
    }
}

impl Drop for TempTreeCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn context_free_nix_string_xxh3(bytes: &[u8]) -> u64 {
    let value = NixString::from_bytes(bytes.to_vec());
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn hot_xxh3_surface_canaries(label: &str, hash: u64) -> Vec<(String, Vec<u8>)> {
    vec![
        (format!("{label} decimal"), hash.to_string().into_bytes()),
        (format!("{label} hex"), format!("{hash:016x}").into_bytes()),
        (
            format!("{label} little-endian bytes"),
            hash.to_le_bytes().to_vec(),
        ),
        (
            format!("{label} big-endian bytes"),
            hash.to_be_bytes().to_vec(),
        ),
    ]
}

fn persistent_force_cache_surface_canaries(persist_root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut canaries = Vec::new();
    if !persist_root.exists() {
        return Ok(canaries);
    }

    let persist = PersistCache::open(persist_root)?;
    let trace_entries = persist.node_trace_log().latest_entries()?;
    for entry in persist.node_metadata_index().latest_entries()? {
        let Some(value_hash) = entry.value().materialized_value_hash() else {
            continue;
        };
        if !matches!(
            persist.load_cached_expression_node_value_indexed(entry.key()),
            Ok(Some(_))
        ) {
            continue;
        }
        canaries.extend(durable_hash_surface_canaries(
            "forced expression node metadata BLAKE3",
            entry.key().hash(),
        ));
        canaries.extend(durable_hash_surface_canaries(
            "forced expression materialized value BLAKE3",
            value_hash.as_durable_hash(),
        ));
        let matching_traces = trace_entries.iter().filter(|trace_entry| {
            trace_entry.key() == entry.key()
                && trace_entry.value_hash() == value_hash
                && !trace_entry.payload().is_tombstone()
        });
        for trace_entry in matching_traces {
            canaries.extend(durable_hash_surface_canaries(
                "forced expression trace value BLAKE3",
                trace_entry.value_hash().as_durable_hash(),
            ));
            for input in trace_entry.payload().inputs() {
                canaries.extend(durable_hash_surface_canaries(
                    "forced expression trace identity BLAKE3",
                    input.identity().hash(),
                ));
                canaries.extend(durable_hash_surface_canaries(
                    "forced expression trace observation BLAKE3",
                    input.observation_hash(),
                ));
            }
        }
    }
    Ok(canaries)
}

fn assert_persistent_force_cache_payload_entries(
    persist_root: &Path,
) -> Result<Vec<(String, Vec<u8>)>> {
    let canaries = persistent_force_cache_surface_canaries(persist_root)?;
    assert!(
        canaries
            .iter()
            .any(|(label, _)| label.starts_with("forced expression node metadata BLAKE3")),
        "native force-cache run should write persistent forced-expression node metadata canaries"
    );
    assert!(
        canaries
            .iter()
            .any(|(label, _)| { label.starts_with("forced expression materialized value BLAKE3") }),
        "native force-cache run should materialize a persistent forced-expression value canary"
    );
    Ok(canaries)
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
