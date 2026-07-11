//! Unit and oracle-differential tests for the native evaluator shim.

use super::*;
use crate::cache::{
    DurableBlake3Hash, ParseCache, ParseFileKey, PersistCache, PersistFileArtifactKey,
    PersistNodeMetadataKey,
};
use crate::eval::IfdRealizationError;
use crate::eval::eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache;
use crate::string::NixString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

mod attr_path;
mod cache_parity;
mod expr_eval;
mod fallback;
mod fv6_payloads;
mod ifd;
mod instantiate_expr;
mod memo_tiers;
mod root_cutoff_tests;
mod semantic_edit;
mod source_errors;
mod warm_import;

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

fn assert_ir_has_non_conservative_facts(ir: &Ir) {
    assert!(
        ir.facts
            .as_slice()
            .iter()
            .any(|facts| *facts != crate::compile::ExprFacts::conservative()),
        "native-lowered IR should carry non-conservative analysis facts"
    );
}

fn assert_parse_cache_has_non_conservative_facts(cache_root: &Path, source: &[u8]) -> Result<()> {
    let cached = ParseCache::new(cache_root)
        .load_cached_bytes(source)?
        .expect("parse-cache entry should exist");
    assert_ir_has_non_conservative_facts(&cached.ir);
    Ok(())
}

fn instantiate_file_closure_with_stats(
    native: &NixNative,
    file: &Path,
    attr: &str,
) -> Result<(NativeDrvClosure, crate::eval::EvalStats)> {
    let (closure, stats, _persistent_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(native, file, attr)?;
    Ok((closure, stats))
}

fn instantiate_file_closure_with_stats_and_hits(
    native: &NixNative,
    file: &Path,
    attr: &str,
) -> Result<(
    NativeDrvClosure,
    crate::eval::EvalStats,
    Vec<PersistNodeMetadataKey>,
)> {
    let attr_path = attr_path_drv_path_segments(attr)?;
    let mut options = native.file_instantiation_options();
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
        Some(diagnostic_source) => {
            native_eval_error_with_source_trace(error, diagnostic_source, EvalTraceStyle::Summary)
        }
        None => native_eval_error_with_trace(error, None, EvalTraceStyle::Summary),
    })?;
    let stats = *outcome.stats();
    let persistent_hit_keys = outcome.persist_force_cache_hit_keys().to_vec();
    native.observe_eval_cache(&outcome);
    let closure = native.native_drv_closure_from_outcome(outcome)?;
    Ok((closure, stats, persistent_hit_keys))
}

fn assert_no_incremental_cache_activity(stats: &crate::eval::EvalStats, label: &str) {
    assert_eq!(
        stats.force_cache_hits(),
        0,
        "{label} reported force-cache hits"
    );
    assert_eq!(
        stats.force_cache_misses(),
        0,
        "{label} reported force-cache misses"
    );
    assert_eq!(
        stats.cache_hits(),
        0,
        "{label} reported aggregate evaluator cache hits"
    );
    assert_eq!(
        stats.cache_misses(),
        0,
        "{label} reported aggregate evaluator cache misses"
    );
    assert_eq!(
        stats.force_cache_memoization_admits(),
        0,
        "{label} reported force-cache memoization admit decisions"
    );
    assert_eq!(
        stats.force_cache_memoization_bypasses(),
        0,
        "{label} reported force-cache memoization bypass decisions"
    );
    assert_eq!(
        stats.force_cache_memoization_demands(),
        0,
        "{label} reported force-cache memoization demand decisions"
    );
    assert_eq!(
        stats.force_cache_materialization_materializes(),
        0,
        "{label} reported durable materialization decisions"
    );
    assert_eq!(
        stats.force_cache_materialization_keeps_in_memory(),
        0,
        "{label} reported keep-in-memory decisions"
    );
    assert_eq!(
        stats.force_cache_materialization_decisions(),
        0,
        "{label} reported materialization decisions"
    );
    assert_eq!(stats.early_cutoffs(), 0, "{label} reported early cutoffs");
    assert_eq!(
        stats.derivation_aterm_path_reuses(),
        0,
        "{label} reported derivation ATerm path reuse"
    );
    assert_eq!(
        stats.static_derivation_output_path_reuses(),
        0,
        "{label} reported static-output path reuse"
    );
}

fn assert_no_force_cache_or_side_record_activity(stats: &crate::eval::EvalStats, label: &str) {
    assert_eq!(
        stats.force_cache_hits(),
        0,
        "{label} reported force-cache hits"
    );
    assert_eq!(
        stats.force_cache_misses(),
        0,
        "{label} reported force-cache misses"
    );
    assert_eq!(
        stats.force_cache_memoization_admits(),
        0,
        "{label} reported force-cache memoization admit decisions"
    );
    assert_eq!(
        stats.force_cache_memoization_bypasses(),
        0,
        "{label} reported force-cache memoization bypass decisions"
    );
    assert_eq!(
        stats.force_cache_memoization_demands(),
        0,
        "{label} reported force-cache memoization demand decisions"
    );
    assert_eq!(
        stats.force_cache_materialization_materializes(),
        0,
        "{label} reported durable materialization decisions"
    );
    assert_eq!(
        stats.force_cache_materialization_keeps_in_memory(),
        0,
        "{label} reported keep-in-memory decisions"
    );
    assert_eq!(
        stats.force_cache_materialization_decisions(),
        0,
        "{label} reported materialization decisions"
    );
    assert_eq!(stats.early_cutoffs(), 0, "{label} reported early cutoffs");
    assert_eq!(
        stats.derivation_aterm_path_reuses(),
        0,
        "{label} reported derivation ATerm path reuse"
    );
    assert_eq!(
        stats.static_derivation_output_path_reuses(),
        0,
        "{label} reported static-output path reuse"
    );
}

#[derive(Debug)]
struct NativeFileClosureCacheParity {
    uncached: NativeDrvClosure,
    cache_miss: NativeDrvClosure,
    cache_second: NativeDrvClosure,
    persistent_hit: NativeDrvClosure,
    disabled_with_persist_root: NativeDrvClosure,
    uncached_stats: crate::eval::EvalStats,
    cache_miss_stats: crate::eval::EvalStats,
    cache_second_stats: crate::eval::EvalStats,
    persistent_hit_stats: crate::eval::EvalStats,
    disabled_stats: crate::eval::EvalStats,
    persistent_hit_keys: Vec<PersistNodeMetadataKey>,
}

impl NativeFileClosureCacheParity {
    fn assert_byte_identical(&self) {
        assert_eq!(self.cache_miss, self.uncached);
        assert_eq!(self.cache_second, self.uncached);
        assert_eq!(self.persistent_hit, self.uncached);
        assert_eq!(self.disabled_with_persist_root, self.uncached);
    }

    fn assert_cache_off_observed_no_incremental_cache_activity(&self) {
        for (label, stats) in [
            ("uncached", &self.uncached_stats),
            ("disabled eval-cache", &self.disabled_stats),
        ] {
            assert_no_incremental_cache_activity(
                stats,
                &format!("{label} native file-closure run"),
            );
        }
    }

    fn assert_cache_off_observed_no_force_cache_or_side_record_activity(&self) {
        for (label, stats) in [
            ("uncached", &self.uncached_stats),
            ("disabled eval-cache", &self.disabled_stats),
        ] {
            assert_no_force_cache_or_side_record_activity(
                stats,
                &format!("{label} native file-closure run"),
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CacheOffStatsContract {
    Strict,
    AllowAggregateCacheStats,
}

fn native_file_closure_cache_parity<F>(
    root: &Path,
    store: &Path,
    persist_root: &Path,
    file: &Path,
    attr: &str,
    configure_options: F,
) -> Result<NativeFileClosureCacheParity>
where
    F: Fn(&mut TreeWalkOptions) -> Result<()>,
{
    native_file_closure_cache_parity_with_cache_off_contract(
        root,
        store,
        persist_root,
        file,
        attr,
        configure_options,
        CacheOffStatsContract::Strict,
    )
}

fn native_file_closure_cache_parity_allowing_aggregate_cache_activity<F>(
    root: &Path,
    store: &Path,
    persist_root: &Path,
    file: &Path,
    attr: &str,
    configure_options: F,
) -> Result<NativeFileClosureCacheParity>
where
    F: Fn(&mut TreeWalkOptions) -> Result<()>,
{
    native_file_closure_cache_parity_with_cache_off_contract(
        root,
        store,
        persist_root,
        file,
        attr,
        configure_options,
        CacheOffStatsContract::AllowAggregateCacheStats,
    )
}

fn native_file_closure_cache_parity_with_cache_off_contract<F>(
    root: &Path,
    store: &Path,
    persist_root: &Path,
    file: &Path,
    attr: &str,
    configure_options: F,
    cache_off_contract: CacheOffStatsContract,
) -> Result<NativeFileClosureCacheParity>
where
    F: Fn(&mut TreeWalkOptions) -> Result<()>,
{
    let store_bytes = store.as_os_str().as_bytes().to_vec();
    let source = fs::read(file)?;
    let realpath = fs::canonicalize(file)?;
    let file_key = ParseFileKey::for_source(&realpath, &source);
    let cache_miss_parse_root = root.join("cache-miss-parse");
    let cache_second_parse_root = root.join("cache-second-parse");
    let persistent_hit_parse_root = root.join("persistent-hit-parse");
    let options_for =
        |parse_root: Option<&Path>, persist: bool, eval_cache_enabled: bool| -> Result<_> {
            let mut options = TreeWalkOptions::with_store_dir(store_bytes.clone())?;
            configure_options(&mut options)?;
            if let Some(parse_root) = parse_root {
                options.set_parse_cache_root(parse_root);
            } else {
                options.clear_parse_cache_root();
            }
            if persist {
                options.set_persist_cache_root(persist_root);
            } else {
                options.clear_persist_cache_root();
            }
            options.set_eval_cache_enabled(eval_cache_enabled);
            Ok(options)
        };

    let (uncached, uncached_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(None, false, false)?)?,
        file,
        attr,
    )?;
    assert_eq!(uncached_stats.force_cache_hits(), 0);
    assert_eq!(uncached_stats.force_cache_misses(), 0);

    let (cache_miss, cache_miss_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(Some(&cache_miss_parse_root), true, true)?)?,
        file,
        attr,
    )?;
    assert_eq!(cache_miss, uncached);
    let cache_miss_parse_cache = ParseCache::new(&cache_miss_parse_root);
    let parse_key = cache_miss_parse_cache.key_for_source(&source);
    assert!(
        cache_miss_parse_cache
            .entry_for_key(parse_key)
            .is_complete(),
        "cache-on miss should populate the local parse cache"
    );
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    assert!(
        PersistCache::open(persist_root)?
            .lookup_file_artifact(file_artifact_key)?
            .is_some(),
        "cache-on miss should write a durable file-backed parse artifact"
    );

    let (cache_second, cache_second_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(Some(&cache_second_parse_root), true, true)?)?,
        file,
        attr,
    )?;
    assert_eq!(cache_second, uncached);
    assert!(
        ParseCache::new(&cache_second_parse_root)
            .entry_for_key(parse_key)
            .is_complete(),
        "second cache-on pass should populate its local parse cache"
    );

    let observed_hits = Arc::new(Mutex::new(Vec::new()));
    let observed_hits_for_hook = Arc::clone(&observed_hits);
    let mut persistent_hit_native = NixNative::with_options(
        0,
        options_for(Some(&persistent_hit_parse_root), true, true)?,
    )?;
    persistent_hit_native.set_persistent_parse_hit_hook(move |hit| {
        observed_hits_for_hook
            .lock()
            .expect("persistent parse hit observations lock")
            .push(hit);
    });
    let (persistent_hit, persistent_hit_stats, persistent_hit_keys) =
        instantiate_file_closure_with_stats_and_hits(&persistent_hit_native, file, attr)?;
    assert_eq!(persistent_hit, uncached);
    assert_eq!(
        observed_hits
            .lock()
            .expect("persistent parse hit observations lock")
            .clone(),
        vec![NativePersistentParseHit::Source],
        "fresh file-root parse cache should hydrate from the durable source artifact"
    );
    assert!(
        ParseCache::new(&persistent_hit_parse_root)
            .entry_for_key(parse_key)
            .is_complete(),
        "persistent file-backed parse hit should hydrate the fresh parse-cache entry"
    );

    let persist = PersistCache::open(persist_root)?;
    let force_sidecar_snapshot =
        snapshot_regular_file_paths(persist_root, &persistent_force_sidecar_paths(&persist))?;
    let full_persist_snapshot = snapshot_regular_file_tree(persist_root)?;

    let (disabled_with_persist_root, disabled_stats) = instantiate_file_closure_with_stats(
        &NixNative::with_options(0, options_for(None, true, false)?)?,
        file,
        attr,
    )?;
    assert_eq!(disabled_with_persist_root, uncached);
    assert_eq!(
        snapshot_regular_file_paths(persist_root, &persistent_force_sidecar_paths(&persist))?,
        force_sidecar_snapshot,
        "disabled eval-cache must not mutate persistent force sidecars"
    );
    assert_eq!(
        snapshot_regular_file_tree(persist_root)?,
        full_persist_snapshot,
        "disabled eval-cache must not mutate persistent cache file contents"
    );

    let report = NativeFileClosureCacheParity {
        uncached,
        cache_miss,
        cache_second,
        persistent_hit,
        disabled_with_persist_root,
        uncached_stats,
        cache_miss_stats,
        cache_second_stats,
        persistent_hit_stats,
        disabled_stats,
        persistent_hit_keys,
    };
    report.assert_byte_identical();
    match cache_off_contract {
        CacheOffStatsContract::Strict => {
            report.assert_cache_off_observed_no_incremental_cache_activity();
        }
        CacheOffStatsContract::AllowAggregateCacheStats => {
            report.assert_cache_off_observed_no_force_cache_or_side_record_activity();
        }
    }

    let canaries = persistent_force_cache_surface_canaries(persist_root)?;
    if !canaries.is_empty() {
        assert_native_closure_surfaces_do_not_contain_canaries(
            "uncached native cache-parity closure",
            &report.uncached,
            &canaries,
        );
        assert_native_closure_surfaces_do_not_contain_canaries(
            "cache-miss native cache-parity closure",
            &report.cache_miss,
            &canaries,
        );
        assert_native_closure_surfaces_do_not_contain_canaries(
            "second cache-on native cache-parity closure",
            &report.cache_second,
            &canaries,
        );
        assert_native_closure_surfaces_do_not_contain_canaries(
            "persistent-hit native cache-parity closure",
            &report.persistent_hit,
            &canaries,
        );
        assert_native_closure_surfaces_do_not_contain_canaries(
            "disabled native cache-parity closure",
            &report.disabled_with_persist_root,
            &canaries,
        );
    }

    Ok(report)
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
                    input.identity().hash().as_durable_hash(),
                ));
                canaries.extend(durable_hash_surface_canaries(
                    "forced expression trace observation BLAKE3",
                    input.observation_hash().as_durable_hash(),
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

fn persistent_force_sidecar_paths(persist: &PersistCache) -> Vec<PathBuf> {
    let layout = persist.layout();
    vec![
        layout.node_metadata_index_path(),
        layout.node_trace_log_path(),
        layout.value_packfile_path(),
        layout.value_index_path(),
    ]
}

fn snapshot_regular_file_paths(
    root: &Path,
    paths: &[PathBuf],
) -> Result<std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>> {
    let mut snapshot = std::collections::BTreeMap::new();
    for path in paths {
        let relative = path.strip_prefix(root)?.as_os_str().as_bytes().to_vec();
        let contents = if path.exists() {
            Some(fs::read(path)?)
        } else {
            None
        };
        assert!(
            snapshot.insert(relative, contents).is_none(),
            "persistent cache snapshot should not see duplicate paths"
        );
    }
    Ok(snapshot)
}

fn snapshot_regular_file_tree(root: &Path) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut snapshot = std::collections::BTreeMap::new();
    if root.exists() {
        snapshot_regular_file_tree_at(root, root, &mut snapshot)?;
    }
    Ok(snapshot)
}

fn snapshot_regular_file_tree_at(
    root: &Path,
    current: &Path,
    snapshot: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let mut entries = fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            snapshot_regular_file_tree_at(root, &path, snapshot)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root)?.as_os_str().as_bytes().to_vec();
            assert!(
                snapshot.insert(relative, fs::read(path)?).is_none(),
                "persistent cache snapshot should not see duplicate paths"
            );
        }
    }
    Ok(())
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
