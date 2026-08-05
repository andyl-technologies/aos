//! Shared helpers for derivation cache-path evaluator tests.

use super::*;
use crate::cache::{CacheExprIdentity, ValueHash};

#[derive(Debug)]
pub(super) struct DerivationCacheRun {
    pub(super) path: String,
    pub(super) aterm: Vec<u8>,
    pub(super) early_cutoffs: u64,
    pub(super) cache_hits: u64,
    pub(super) cache_misses: u64,
    pub(super) force_hits: u64,
    pub(super) force_misses: u64,
    pub(super) path_reuses: u64,
    pub(super) output_path_reuses: u64,
    pub(super) hash_calculations: u64,
    pub(super) text_path_calculations: u64,
}

pub(super) fn eval_single_derivation_with_cache(
    ir: &Ir,
    options: TreeWalkOptions,
    cache: Arc<Mutex<EvalCacheRuntime>>,
) -> DerivationCacheRun {
    let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(ir, options, None, cache)
        .expect("derivation evaluates");
    let [derivation] = outcome.derivations() else {
        panic!(
            "expected one recorded derivation, got {:?}",
            outcome.derivations()
        );
    };
    DerivationCacheRun {
        path: derivation.absolute_path().to_owned(),
        aterm: derivation
            .aterm_bytes()
            .expect("derivation has ATerm bytes")
            .to_vec(),
        early_cutoffs: outcome.stats().early_cutoffs(),
        cache_hits: outcome.stats().cache_hits(),
        cache_misses: outcome.stats().cache_misses(),
        force_hits: outcome.stats().force_cache_hits(),
        force_misses: outcome.stats().force_cache_misses(),
        path_reuses: outcome.stats().derivation_aterm_path_reuses(),
        output_path_reuses: outcome.stats().static_derivation_output_path_reuses(),
        hash_calculations: outcome.stats().derivation_hash_calculations(),
        text_path_calculations: outcome.stats().derivation_text_path_calculations(),
    }
}

pub(super) fn derivation_aterm_cache_subject(
    ir: &Ir,
    options: TreeWalkOptions,
    cache: Arc<Mutex<EvalCacheRuntime>>,
) -> (CacheExprIdentity, Vec<ValueHash>) {
    TreeWalk::with_options_and_eval_cache(ir, options, cache)
        .derivation_aterm_cache_subject_for_current_node(ir.root)
        .expect("root derivation ATerm subject builds")
}

pub(super) fn static_derivation_outputs_cache_subject(
    ir: &Ir,
    options: TreeWalkOptions,
    cache: Arc<Mutex<EvalCacheRuntime>>,
) -> (CacheExprIdentity, Vec<ValueHash>) {
    TreeWalk::with_options_and_eval_cache(ir, options, cache)
        .static_derivation_outputs_cache_subject_for_current_node(ir.root)
        .expect("root static derivation output subject builds")
}

pub(super) fn static_derivation_pre_output_aterm() -> Vec<u8> {
    static_derivation_pre_output_aterm_with_env(None)
}

pub(super) fn static_derivation_pre_output_aterm_with_env(env: Option<&str>) -> Vec<u8> {
    let ir = lower("null");
    let eval = TreeWalk::new(&ir);
    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation
        .outputs
        .insert("out".to_owned(), nix_compat::derivation::Output::default());
    derivation.builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder".to_owned();
    derivation.system = "x86_64-linux".to_owned();
    derivation
        .environment
        .insert("builder".to_owned(), derivation.builder.clone().into());
    derivation.environment.insert("name".to_owned(), "x".into());
    if let Some(env) = env {
        derivation.environment.insert("env".to_owned(), env.into());
    }
    derivation
        .environment
        .insert("out".to_owned(), Vec::new().into());
    derivation
        .environment
        .insert("system".to_owned(), derivation.system.clone().into());
    eval.derivation_aterm_bytes(&derivation)
}

pub(super) fn enabled_eval_cache_options() -> TreeWalkOptions {
    TreeWalkOptions::with_eval_cache_enabled(true)
}

pub(super) fn enabled_eval_cache_options_with_store_dir(store_dir: Vec<u8>) -> TreeWalkOptions {
    let mut options = enabled_eval_cache_options();
    options
        .set_store_dir(store_dir)
        .expect("store directory configures");
    options
}

pub(super) fn derivation_surfaces(outcome: &EvalOutcome) -> Vec<(String, Vec<u8>)> {
    let mut surfaces = outcome
        .derivations()
        .iter()
        .map(|derivation| {
            (
                derivation.absolute_path().to_owned(),
                derivation
                    .aterm_bytes()
                    .expect("derivation has ATerm bytes")
                    .to_vec(),
            )
        })
        .collect::<Vec<_>>();
    surfaces.sort_by(|left, right| left.0.cmp(&right.0));
    surfaces
}
