//! Tree-walk evaluator tests for derivation force-cache surfaces.

use super::derivation_2_support::{
    derivation_aterm_cache_subject, derivation_surfaces, eval_single_derivation_with_cache,
    static_derivation_outputs_cache_subject,
};
use super::*;
mod part_1;
use crate::cache::{
    CacheExprIdentity, DemandCacheKey, NodeFreshness, PersistCache, PersistNodeMetadataKey,
    ValueHash,
};

#[derive(Debug)]
struct EffectfulDerivationSurface {
    path: String,
    aterm: Vec<u8>,
    trace: Vec<ImpureInputFingerprint>,
    thunks_forced: u64,
    cache_hits: u64,
    force_cache_hits: u64,
    force_cache_misses: u64,
    path_reuses: u64,
    output_path_reuses: u64,
    hash_calculations: u64,
    text_path_calculations: u64,
    persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
}

#[derive(Debug)]
struct NestedCurrentTimeDerivations {
    surfaces: Vec<(String, Vec<u8>)>,
    trace: Vec<ImpureInputFingerprint>,
    path_reuses: u64,
    output_path_reuses: u64,
    hash_calculations: u64,
    text_path_calculations: u64,
}

fn evaluate_nested_current_time_derivations(
    ir: &Ir,
    options: TreeWalkOptions,
    context: &str,
) -> NestedCurrentTimeDerivations {
    let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
        ir,
        options,
        None,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    )
    .unwrap_or_else(|error| panic!("{context} should evaluate: {error:?}"));
    assert_eq!(
        outcome.derivations().len(),
        2,
        "{context} should record inner and outer derivations"
    );
    NestedCurrentTimeDerivations {
        surfaces: derivation_surfaces(&outcome),
        trace: outcome.impure_input_trace().to_vec(),
        path_reuses: outcome.stats().derivation_aterm_path_reuses(),
        output_path_reuses: outcome.stats().static_derivation_output_path_reuses(),
        hash_calculations: outcome.stats().derivation_hash_calculations(),
        text_path_calculations: outcome.stats().derivation_text_path_calculations(),
    }
}

fn assert_persistent_force_cache_trace_log_contains(
    persist_root: &std::path::Path,
    expected_trace: &[ImpureInputFingerprint],
    context: &str,
) -> (PersistNodeMetadataKey, ValueHash) {
    let expected = expected_trace
        .iter()
        .map(|input| {
            input
                .as_cacheable()
                .unwrap_or_else(|| panic!("{context} expected trace should be cacheable"))
                .clone()
        })
        .collect::<Vec<_>>();
    let persist = PersistCache::open(persist_root).expect("persistent cache opens");
    let metadata_entries = persist
        .node_metadata_index()
        .latest_entries()
        .expect("persistent node metadata entries load");
    let trace_entries = persist
        .node_trace_log()
        .latest_entries()
        .expect("persistent node trace entries load");
    let live_matches = trace_entries
        .iter()
        .filter_map(|entry| {
            if entry.payload().is_tombstone() || entry.payload().inputs() != expected.as_slice() {
                return None;
            }
            let metadata_links_trace = metadata_entries.iter().any(|metadata| {
                metadata.key() == entry.key()
                    && metadata.value().materialized_value_hash() == Some(entry.value_hash())
            });
            metadata_links_trace.then_some((entry.key(), entry.value_hash()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        live_matches.len(),
        1,
        "{context} should persist exactly one live force-cache verifying trace for the expected inputs"
    );
    live_matches[0]
}

fn assert_no_live_persistent_side_record(
    persist_root: &std::path::Path,
    identity: CacheExprIdentity,
    free_var_value_hashes: &[ValueHash],
    context: &str,
) {
    if !persist_root.exists() {
        return;
    }
    let persist = PersistCache::open(persist_root).expect("persistent cache opens");
    let key =
        PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
    assert_eq!(
        persist
            .lookup_node_materialized_value_hash(key)
            .expect("persistent side-record metadata lookup succeeds"),
        None,
        "{context} should not link a live persistent side payload"
    );
}

fn evaluate_effectful_derivation_surface(
    ir: &Ir,
    source: &str,
    options: TreeWalkOptions,
    eval_cache: EvalCacheRuntime,
) -> EffectfulDerivationSurface {
    evaluate_effectful_derivation_surface_with_cache(
        ir,
        source,
        options,
        Arc::new(Mutex::new(eval_cache)),
    )
}

fn evaluate_effectful_derivation_surface_with_cache(
    ir: &Ir,
    source: &str,
    options: TreeWalkOptions,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
) -> EffectfulDerivationSurface {
    let attr_path = vec![b"pkg".to_vec()];
    let outcome = eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
        ir,
        &attr_path,
        options,
        "force-cache-effectful-drv-surface.nix",
        source,
        None,
        eval_cache,
    )
    .expect("derivation attr-path eval succeeds");
    let [derivation] = outcome.derivations() else {
        panic!(
            "expected one recorded derivation, got {:?}",
            outcome.derivations()
        );
    };
    EffectfulDerivationSurface {
        path: derivation.absolute_path().to_owned(),
        aterm: derivation
            .aterm_bytes()
            .expect("static derivation has ATerm bytes")
            .to_vec(),
        trace: outcome.impure_input_trace().to_vec(),
        thunks_forced: outcome.stats().thunks_forced(),
        cache_hits: outcome.stats().cache_hits(),
        force_cache_hits: outcome.stats().force_cache_hits(),
        force_cache_misses: outcome.stats().force_cache_misses(),
        path_reuses: outcome.stats().derivation_aterm_path_reuses(),
        output_path_reuses: outcome.stats().static_derivation_output_path_reuses(),
        hash_calculations: outcome.stats().derivation_hash_calculations(),
        text_path_calculations: outcome.stats().derivation_text_path_calculations(),
        persist_force_cache_hit_keys: outcome.persist_force_cache_hit_keys().to_vec(),
    }
}

