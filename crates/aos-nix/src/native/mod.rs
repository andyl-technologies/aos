//! `aos-core` facing native evaluator shim.
//!
//! [`NixNative`] is the stable integration handle that will own the parser
//! cache, symbol interner, hash-consing tables, and evaluator arena as Phase 1
//! fills in. The current implementation is deliberately conservative: native
//! instantiation and JSON expression evaluation stay limited to the implemented
//! Phase-1 subset.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::ops::Range;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::Result;

#[cfg(test)]
use crate::cache::EvalCache;
use crate::cache::{
    CacheableInputFingerprint, CachedParse, EvalCacheRuntime, MaterializationDecision, ParseCache,
    ParseCacheError, ParseFileKey, PersistCache, PersistRootRecordKey,
};
#[cfg(test)]
use crate::compile::{EffectClass, IrFacts};
use crate::compile::{Ir, IrAttrPathId, IrAttrPathSegment, IrData, IrId, IrKind, annotate_capture_plans, resolve};
use crate::diagnostic::EvalTraceStyle;
use crate::drv_materialize::materialize_drv;
use crate::error::NativeEvalError;
use crate::eval::tree_walk::{canonicalize_policy_path, normalize_absolute_path_bytes};
use crate::eval::{
    EvalErrorLabel, EvalMode, EvalOutcome, EvalStats, IfdRealizer, MemoTierEvents, Tier1Engine,
    TreeWalkError, TreeWalkErrorKind, TreeWalkOptions,
    eval_instantiation_attr_path_owned_with_options_source_realizer_eval_cache_and_engine,
    eval_whnf_owned_with_options_realizer_eval_cache_and_engine, revalidate_cacheable_input_trace,
};
use crate::jit::NixJitTier1Engine;
use crate::runtime::builtins::{
    Builtin, BuiltinAvailability, BuiltinExecution, NativeCliFallbackFeature, StrictUnaryPrimOp,
    is_unshadowable_global_name, lookup_builtin,
};
use crate::syntax::{Span, parse_bytes};
use crate::value::{Value, ValueTag};
use aos_nix_dialect::nix_lower;

/// In-process RFC-0007 evaluator handle.
#[derive(Debug, Clone)]
pub struct NixNative {
    verbose: u8,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    #[cfg(test)]
    persist_cache_hook: Option<PersistCacheTestHook>,
    #[cfg(test)]
    persistent_parse_hit_hook: Option<PersistentParseHitTestHook>,
}

#[cfg(test)]
#[derive(Clone)]
struct PersistCacheTestHook(Arc<dyn Fn(&PersistCache) + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for PersistCacheTestHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PersistCacheTestHook")
    }
}

#[cfg(test)]
#[derive(Clone)]
struct PersistentParseHitTestHook(Arc<dyn Fn(NativePersistentParseHit) + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for PersistentParseHitTestHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PersistentParseHitTestHook")
    }
}

/// Identifies which persistent parse-index path supplied a native cache hit.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativePersistentParseHit {
    /// A raw source-bytes artifact was hydrated from the persistent parse index.
    Bytes,
    /// A file-backed source artifact was hydrated from the persistent file index.
    Source,
}

/// An evaluated derivation closure that has not been registered in the store.
///
/// The root path and each key in [`Self::drvs`] are absolute `.drv` paths. The
/// byte values are the ATerm bytes the native evaluator produced in memory.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NativeDrvClosure {
    root: PathBuf,
    drvs: BTreeMap<PathBuf, Vec<u8>>,
}

impl NativeDrvClosure {
    /// Returns the top-level `.drv` path selected by the instantiation request.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns in-memory `.drv` ATerm bytes by absolute `.drv` path.
    pub fn drvs(&self) -> &BTreeMap<PathBuf, Vec<u8>> {
        &self.drvs
    }

    /// Consumes the closure into its root path and `.drv` byte map.
    pub fn into_parts(self) -> (PathBuf, BTreeMap<PathBuf, Vec<u8>>) {
        (self.root, self.drvs)
    }
}

impl NixNative {
    /// Creates a native evaluator handle.
    ///
    /// # Errors
    ///
    /// The Phase-1 shim has no fallible initialization. Future implementations
    /// may return errors when opening the persistent cache or validating store
    /// paths.
    pub fn new(verbose: u8) -> Result<Self> {
        Self::with_options(verbose, TreeWalkOptions::new())
    }

    /// Creates a native evaluator handle with explicit tree-walk settings.
    ///
    /// # Errors
    ///
    /// The Phase-1 shim has no fallible initialization. Future implementations
    /// may return errors when opening the persistent cache or validating store
    /// paths.
    pub fn with_options(verbose: u8, options: TreeWalkOptions) -> Result<Self> {
        Ok(Self {
            verbose,
            eval_cache: Arc::new(Mutex::new(EvalCacheRuntime::from_enabled(
                options.eval_cache_enabled(),
            ))),
            options,
            ifd_realizer: None,
            #[cfg(test)]
            persist_cache_hook: None,
            #[cfg(test)]
            persistent_parse_hit_hook: None,
        })
    }

    /// Returns the configured verbosity level.
    pub fn verbose(&self) -> u8 {
        self.verbose
    }

    /// Installs a callback used to realize derivation outputs for IFD.
    pub fn set_ifd_realizer(&mut self, realizer: IfdRealizer) {
        self.ifd_realizer = Some(realizer);
    }

    #[cfg(test)]
    pub(crate) fn set_persist_cache_hook(
        &mut self,
        hook: impl Fn(&PersistCache) + Send + Sync + 'static,
    ) {
        self.persist_cache_hook = Some(PersistCacheTestHook(Arc::new(hook)));
    }

    /// Installs a callback used by tests to observe persistent parse-cache hits.
    #[cfg(test)]
    pub(crate) fn set_persistent_parse_hit_hook(
        &mut self,
        hook: impl Fn(NativePersistentParseHit) + Send + Sync + 'static,
    ) {
        self.persistent_parse_hit_hook = Some(PersistentParseHitTestHook(Arc::new(hook)));
    }

    /// Returns this evaluator with a callback used to realize derivation outputs for IFD.
    pub fn with_ifd_realizer(mut self, realizer: IfdRealizer) -> Self {
        self.set_ifd_realizer(realizer);
        self
    }

    /// Clears any configured IFD realizer.
    pub fn clear_ifd_realizer(&mut self) {
        self.ifd_realizer = None;
    }

    /// Evaluates `attr` from `file` to a derivation path.
    ///
    /// This path-level native instantiation is intentionally conservative: the
    /// tree-walk oracle must evaluate the selected value, expose a `drvPath`
    /// string, and materialize every in-memory `.drv` in the configured store.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the selected expression
    /// reaches an evaluator feature that is still outside the native tree-walk
    /// subset. Returns [`NativeEvalError::EvalError`] when the selected value
    /// does not expose a string `drvPath`.
    pub fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let closure = self.eval_file_attr_derivation_closure(file, attr)?;
        materialize_drv_closure(&closure)?;
        Ok(closure.root().to_path_buf())
    }

    /// Evaluates `attr` from `file` to an in-memory derivation closure.
    ///
    /// The returned `.drv` bytes are not written to or registered in the Nix
    /// store. This is intended for differential comparison against the C++ Nix
    /// oracle until native store registration is implemented.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the selected expression
    /// reaches an evaluator feature that is still outside the native tree-walk
    /// subset. Returns [`NativeEvalError::EvalError`] when the selected value
    /// does not expose a string `drvPath`.
    pub fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<NativeDrvClosure> {
        self.eval_file_attr_derivation_closure(file, attr)
    }

    /// Evaluates `attr` from `file` to an in-memory closure and evaluator counters.
    ///
    /// The returned stats describe the tree-walk evaluator work performed for
    /// this instantiation and use the same schema as the native evaluator
    /// tracing counters.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the selected expression
    /// reaches an evaluator feature that is still outside the native tree-walk
    /// subset. Returns [`NativeEvalError::EvalError`] when the selected value
    /// does not expose a string `drvPath`.
    pub fn instantiate_closure_with_stats(
        &self,
        file: &Path,
        attr: &str,
    ) -> Result<(NativeDrvClosure, EvalStats)> {
        self.eval_file_attr_derivation_closure_with_stats(file, attr)
    }

    /// Writes an in-memory derivation closure to the configured Nix store.
    ///
    /// Existing `.drv` files are accepted only when their bytes are identical to
    /// the closure bytes. Differing existing files are treated as internal
    /// native-evaluator failures rather than overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Internal`] when a `.drv` file cannot be
    /// safely installed into the store.
    pub fn materialize_closure(&self, closure: &NativeDrvClosure) -> Result<()> {
        materialize_drv_closure(closure)
    }

    /// Evaluates a raw expression to a derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression does not
    /// evaluate to a derivation-like attribute set with a string `drvPath`.
    pub fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let source = derivation_path_wrapper_source(expr);
        let source_map = WrappedSourceMap {
            prefix_len: DRV_PATH_WRAPPER_PREFIX.len(),
            expr_len: expr.len(),
        };
        let diagnostic_source = NativeDiagnosticSource::new("expr.nix", expr, Some(source_map));
        self.eval_derivation_materialized_source(&source, Some(source_map), Some(diagnostic_source))
    }

    /// Evaluates a raw expression to a derivation path with caller-selected diagnostics.
    ///
    /// `diagnostic_range` identifies the byte slice of `expr` that must match
    /// `diagnostic_source` and should be shown when parser, lowering, or
    /// evaluator spans land inside that slice. This lets integration layers
    /// evaluate an expanded expression while still reporting user-authored
    /// subexpressions.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Internal`] if `diagnostic_range` is not a valid
    /// byte range within `expr` or its bytes do not match `diagnostic_source`.
    /// Otherwise errors match [`Self::instantiate_expr`].
    pub fn instantiate_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<PathBuf> {
        let source = derivation_path_wrapper_source(expr);
        let (source_map, diagnostic_source) = diagnostic_source_for_range(
            expr,
            diagnostic_name,
            diagnostic_source,
            DRV_PATH_WRAPPER_PREFIX.len(),
            diagnostic_range,
        )?;
        self.eval_derivation_materialized_source(&source, Some(source_map), Some(diagnostic_source))
    }

    /// Evaluates a raw expression to an in-memory derivation closure.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression does not
    /// evaluate to a derivation-like attribute set with a string `drvPath`.
    pub fn instantiate_expr_closure(&self, expr: &str) -> Result<NativeDrvClosure> {
        Ok(self.instantiate_expr_closure_with_stats(expr)?.0)
    }

    /// Evaluates a raw expression to an in-memory derivation closure and counters.
    ///
    /// The returned stats describe the tree-walk evaluator work performed for
    /// this instantiation and use the same schema as the native evaluator
    /// tracing counters.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression does not
    /// evaluate to a derivation-like attribute set with a string `drvPath`.
    pub fn instantiate_expr_closure_with_stats(
        &self,
        expr: &str,
    ) -> Result<(NativeDrvClosure, EvalStats)> {
        let source = derivation_path_wrapper_source(expr);
        let source_map = WrappedSourceMap {
            prefix_len: DRV_PATH_WRAPPER_PREFIX.len(),
            expr_len: expr.len(),
        };
        let diagnostic_source = NativeDiagnosticSource::new("expr.nix", expr, Some(source_map));
        self.eval_derivation_closure_source_with_stats(
            &source,
            Some(source_map),
            Some(diagnostic_source),
        )
    }

    /// Evaluates a raw expression to an in-memory derivation closure with caller-selected diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Internal`] if `diagnostic_range` is not a valid
    /// byte range within `expr` or its bytes do not match `diagnostic_source`.
    /// Otherwise errors match
    /// [`Self::instantiate_expr_closure`].
    pub fn instantiate_expr_closure_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<NativeDrvClosure> {
        let source = derivation_path_wrapper_source(expr);
        let (source_map, diagnostic_source) = diagnostic_source_for_range(
            expr,
            diagnostic_name,
            diagnostic_source,
            DRV_PATH_WRAPPER_PREFIX.len(),
            diagnostic_range,
        )?;
        self.eval_derivation_closure_source(&source, Some(source_map), Some(diagnostic_source))
    }

    /// Evaluates a raw expression and renders it as strict JSON text.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression fails with
    /// normal Nix evaluation semantics or cannot be represented as JSON.
    pub fn eval_expr(&self, expr: &str) -> Result<String> {
        Ok(self.eval_expr_with_stats(expr)?.0)
    }

    /// Evaluates a raw expression as strict JSON and returns evaluator counters.
    ///
    /// The returned stats describe the tree-walk evaluator work performed for
    /// this expression evaluation and use the same schema as the native
    /// evaluator tracing counters.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression fails with
    /// normal Nix evaluation semantics or cannot be represented as JSON.
    pub fn eval_expr_with_stats(&self, expr: &str) -> Result<(String, EvalStats)> {
        let source = json_wrapper_source(expr);
        let source_map = WrappedSourceMap {
            prefix_len: JSON_WRAPPER_PREFIX.len(),
            expr_len: expr.len(),
        };
        let diagnostic_source = NativeDiagnosticSource::new("expr.nix", expr, Some(source_map));
        let ir = self.lower_native_source(&source, Some(source_map), Some(diagnostic_source))?;
        ensure_native_json_subset(&ir, expr.len(), &self.options)?;
        let outcome = self.eval_ir(&ir).map_err(|error| {
            native_eval_error_with_source_trace(error, diagnostic_source, self.eval_trace_style())
        })?;
        let stats = *outcome.stats();
        self.maybe_dump_eval_stats(&stats);
        Ok((json_string_from_outcome(&outcome)?, stats))
    }

    /// Evaluates a raw expression with caller-selected diagnostic source text.
    ///
    /// `diagnostic_range` identifies the byte slice of `expr` that must match
    /// `diagnostic_source` and should be shown when parser, lowering, or
    /// evaluator spans land inside that slice. This is intended for user-facing
    /// wrappers such as the native REPL, where the evaluator must see an
    /// expanded expression but diagnostics should point into the input the user
    /// typed.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Internal`] if `diagnostic_range` is not a valid
    /// byte range within `expr` or its bytes do not match `diagnostic_source`.
    /// Otherwise errors match [`Self::eval_expr`].
    pub fn eval_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<String> {
        let source = json_wrapper_source(expr);
        let (source_map, diagnostic_source) = diagnostic_source_for_range(
            expr,
            diagnostic_name,
            diagnostic_source,
            JSON_WRAPPER_PREFIX.len(),
            diagnostic_range,
        )?;
        let ir = self.lower_native_source(&source, Some(source_map), Some(diagnostic_source))?;
        ensure_native_json_subset(&ir, expr.len(), &self.options)?;
        let outcome = self.eval_ir(&ir).map_err(|error| {
            native_eval_error_with_source_trace(error, diagnostic_source, self.eval_trace_style())
        })?;
        json_string_from_outcome(&outcome)
    }

    /// Returns a stable implementation name for diagnostics.
    pub fn name(&self) -> &'static str {
        "aos-nix"
    }

    #[cfg(test)]
    pub(crate) fn eval_cache_snapshot(&self) -> Option<EvalCache> {
        self.eval_cache
            .lock()
            .expect("eval cache lock")
            .cache()
            .cloned()
    }

    #[cfg(test)]
    fn eval_derivation_path_source(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
    ) -> Result<PathBuf> {
        let ir = self.lower_native_source(source, source_map, None)?;
        let outcome = self.eval_instantiation_ir(&ir).map_err(|error| {
            native_eval_error_with_trace(error, source_map, self.eval_trace_style())
        })?;
        derivation_path_from_value(outcome.value(), outcome.heap())
    }

    fn eval_derivation_materialized_source(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<PathBuf> {
        let closure = self.eval_derivation_closure_source(source, source_map, diagnostic_source)?;
        materialize_drv_closure(&closure)?;
        Ok(closure.root().to_path_buf())
    }

    fn eval_derivation_closure_source(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<NativeDrvClosure> {
        Ok(self
            .eval_derivation_closure_source_with_stats(source, source_map, diagnostic_source)?
            .0)
    }

    fn eval_derivation_closure_source_with_stats(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<(NativeDrvClosure, EvalStats)> {
        let ir = self.lower_native_source(source, source_map, diagnostic_source)?;
        if let Some((feature, span)) = native_instantiation_cli_fallback_feature(&ir, &self.options)
        {
            return Err(NativeEvalError::Unsupported {
                feature: feature.to_string(),
                span: source_map.and_then(|source_map| source_span_from_wrapped(span, source_map)),
            }
            .into());
        }
        let outcome = self
            .eval_instantiation_ir(&ir)
            .map_err(|error| match diagnostic_source {
                Some(diagnostic_source) => native_eval_error_with_source_trace(
                    error,
                    diagnostic_source,
                    self.eval_trace_style(),
                ),
                None => native_eval_error_with_trace(error, source_map, self.eval_trace_style()),
            })?;
        let stats = *outcome.stats();
        self.maybe_dump_eval_stats(&stats);
        Ok((self.native_drv_closure_from_outcome(outcome)?, stats))
    }

    fn eval_file_attr_derivation_closure(
        &self,
        file: &Path,
        attr: &str,
    ) -> Result<NativeDrvClosure> {
        Ok(self
            .eval_file_attr_derivation_closure_with_stats(file, attr)?
            .0)
    }

    fn eval_file_attr_derivation_closure_with_stats(
        &self,
        file: &Path,
        attr: &str,
    ) -> Result<(NativeDrvClosure, EvalStats)> {
        let mut options = self.file_instantiation_options();
        let file = native_source_file(file, &options)?;
        let source_name = path_bytes(&file)?;
        let source_name_text = String::from_utf8_lossy(&source_name);
        let source = fs::read(&file).map_err(|source| NativeEvalError::EvalError {
            message: format!(
                "failed to read native instantiation source {}: {source}",
                source_name_text
            ),
        })?;
        let base = file.parent().unwrap_or_else(|| Path::new("/"));
        options.set_path_literal_base(path_bytes(base)?)?;

        // A root cutoff key is derived only when the durable cutoff is enabled
        // and a persistent-cache root is configured; the same key drives both a
        // warm hit and cold-path record writeback.
        let cutoff_key = (options.root_cutoff_enabled() && options.persist_cache_root().is_some())
            .then(|| root_cutoff::root_record_key(&file, &source, attr, &options));

        let mut memo_events = MemoTierEvents::default();
        if let Some(key) = cutoff_key {
            if let Some((closure, hit_source)) =
                self.load_root_cutoff_closure(&options, key, &mut memo_events)
            {
                self.verify_root_cutoff_closure(
                    &file,
                    attr,
                    &options,
                    hit_source,
                    &closure,
                    &source,
                )?;
                let mut stats = EvalStats::for_root_cutoff();
                stats.merge_memo_tier_events(&memo_events);
                self.maybe_dump_eval_stats(&stats);
                return Ok((closure, stats));
            }
        }

        let (closure, mut stats, cacheable_inputs) =
            self.eval_file_attr_closure_full(&file, attr, &options, &source)?;
        stats.merge_memo_tier_events(&memo_events);
        if let (Some(key), Some(inputs)) = (cutoff_key, cacheable_inputs) {
            self.store_root_cutoff(&options, key, &closure, &inputs);
        }
        self.maybe_dump_eval_stats(&stats);
        Ok((closure, stats))
    }

    fn native_drv_closure_from_outcome(&self, outcome: EvalOutcome) -> Result<NativeDrvClosure> {
        let root = derivation_path_from_value(outcome.value(), outcome.heap())?;
        let mut drvs = BTreeMap::new();
        for derivation in outcome.derivations() {
            let path = PathBuf::from(derivation.absolute_path());
            let bytes = derivation
                .aterm_bytes()
                .ok_or_else(|| NativeEvalError::Unsupported {
                    feature: format!(
                        "native drv byte materialization for deferred derivation {}",
                        derivation.absolute_path()
                    ),
                    span: None,
                })?;
            drvs.insert(path, bytes.to_vec());
        }
        if !drvs.contains_key(&root) {
            return Err(NativeEvalError::EvalError {
                message: format!(
                    "native instantiation selected a drvPath that was not produced by derivationStrict: {}",
                    root.display()
                ),
            }
            .into());
        }
        Ok(NativeDrvClosure { root, drvs })
    }

    fn lower_native_source(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<Ir> {
        self.lower_native_source_bytes(source.as_bytes(), None, None, source_map, diagnostic_source)
    }

    fn lower_native_source_bytes(
        &self,
        source: &[u8],
        source_hint: Option<String>,
        source_path: Option<&Path>,
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<Ir> {
        if let Some(root) = self.options.parse_cache_root() {
            let cache = ParseCache::new(root);
            let persist_cache = self
                .options
                .persist_cache_root()
                .and_then(|root| PersistCache::open(root).ok())
                .map(|persist_cache| {
                    self.run_persist_cache_hook(&persist_cache);
                    persist_cache
                });
            if let Some(persist_cache) = &persist_cache {
                let cached =
                    self.load_native_parse_artifact_any(&cache, persist_cache, source_path, source);
                if let Some((mut cached, from_secondary)) = cached {
                    #[cfg(test)]
                    self.observe_persistent_parse_hit(if source_path.is_some() {
                        NativePersistentParseHit::Source
                    } else {
                        NativePersistentParseHit::Bytes
                    });
                    if from_secondary {
                        self.promote_native_parse_artifact(
                            persist_cache,
                            source,
                            source_path,
                            &cached,
                        );
                    }
                    self.refresh_and_materialize_native_cached_parse(
                        persist_cache,
                        source,
                        source_path,
                        &mut cached,
                    );
                    return Ok(cached.ir);
                }
            }
            match cache.load_or_parse_bytes(source, source_hint) {
                Ok(mut cached) => {
                    if let Some(persist_cache) = &persist_cache {
                        self.refresh_and_materialize_native_cached_parse(
                            persist_cache,
                            source,
                            source_path,
                            &mut cached,
                        );
                    } else {
                        // Warm loads with a version-current facts sidecar
                        // skip re-analysis entirely.
                        let _ = cached.ensure_facts_current_and_stored();
                    }
                    return Ok(cached.ir);
                }
                Err(error) => {
                    if let Some(error) =
                        parse_cache_frontend_error(error, source_map, diagnostic_source)
                    {
                        return Err(error.into());
                    }
                }
            }
        }

        Self::lower_native_source_uncached(source, source_map, diagnostic_source)
    }

    fn refresh_and_materialize_native_cached_parse(
        &self,
        persist_cache: &PersistCache,
        source: &[u8],
        source_path: Option<&Path>,
        cached: &mut CachedParse,
    ) {
        // Warm path: a version-current facts sidecar skips re-analysis.
        let _ = cached.ensure_facts_current_and_stored();
        if !cached.stored {
            return;
        }
        if let Some(source_path) = source_path {
            let file_key = ParseFileKey::for_source(source_path, source);
            let _ = persist_cache.materialize_parse_artifact_entry_indexed(
                &file_key,
                cached.key,
                &cached.entry,
                MaterializationDecision::Materialize,
            );
        } else {
            let _ = persist_cache.materialize_parse_cache_entry_indexed(
                cached.key,
                &cached.entry,
                MaterializationDecision::Materialize,
            );
        }
    }

    fn lower_native_source_uncached(
        source: &[u8],
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<Ir> {
        let parsed = parse_bytes(source)
            .map_err(|source| unsupported_parse_error(source, source_map, diagnostic_source))?;
        let resolved = resolve(parsed)
            .map_err(|source| unsupported_scope_error(source, source_map, diagnostic_source))?;
        let mut ir = nix_lower(resolved)
            .map_err(|source| unsupported_ir_error(source, source_map, diagnostic_source))?;
        // Fresh uncached IR needs FV-5 capture facts; durable-cache runs the full pipeline.
        let _ = annotate_capture_plans(&mut ir);
        Ok(ir)
    }

    fn eval_ir(&self, ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
        let options = self.options.clone();
        let engine = self.tier1_engine_for(&options);
        let outcome = eval_whnf_owned_with_options_realizer_eval_cache_and_engine(
            ir,
            options,
            self.ifd_realizer.clone(),
            self.eval_cache.clone(),
            engine,
        )?;
        self.observe_eval_cache(&outcome);
        Ok(outcome)
    }

    fn eval_instantiation_ir(&self, ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
        let options = self.instantiation_options();
        let engine = self.tier1_engine_for(&options);
        let outcome = eval_whnf_owned_with_options_realizer_eval_cache_and_engine(
            ir,
            options,
            self.ifd_realizer.clone(),
            self.eval_cache.clone(),
            engine,
        )?;
        self.observe_eval_cache(&outcome);
        Ok(outcome)
    }

    /// Builds a tier-1 JIT engine when the options enable tier-1 publishing.
    ///
    /// Returns `None` when the flag is off (the plain tree-walk path), when
    /// parallel evaluation mode is configured (the engine is worker-affine, so
    /// `AOS_NIX_JIT` is ignored under `AOS_NIX_PARALLEL`), or when the
    /// runtime-symbol candidate preflight cannot be built, in which case
    /// evaluation transparently falls back to the tree walk.
    fn tier1_engine_for(&self, options: &TreeWalkOptions) -> Option<Rc<dyn Tier1Engine>> {
        // RFC-0007 Candidate-C cutover: the tier-1 JIT emits the active two-word
        // value ABI and two-word stack maps. Under the `candidate_c_value`
        // variant the runtime value is one word, so the JIT is unreachable by
        // construction until S4b reworks its ABI + stack-map geometry; the
        // engine is never created here. See design-notes/candidate-c-cutover-plan.md
        // §6.1 (S4b re-enables JIT after S3's one-word stack maps land).
        #[cfg(feature = "candidate_c_value")]
        {
            let _ = options;
            return None;
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            if options.parallel_workers().is_some() {
                return None;
            }
            if !options.jit_tier1_publish_enabled() {
                return None;
            }
            NixJitTier1Engine::new().ok().map(|engine| {
                Rc::new(engine.with_compiled_body_cache_options(options))
                    as Rc<dyn Tier1Engine>
            })
        }
    }

    fn instantiation_options(&self) -> TreeWalkOptions {
        let mut options = self.options.clone();
        options.set_reject_ambient_search_path(true);
        options.set_reject_unconfigured_impure_builtin_constants(true);
        options
    }

    fn file_instantiation_options(&self) -> TreeWalkOptions {
        let mut options = self.instantiation_options();
        options.set_reject_ambient_search_path(options.nix_path().is_empty());
        options
    }

    fn eval_trace_style(&self) -> EvalTraceStyle {
        if self.verbose() > 0 {
            EvalTraceStyle::Full
        } else {
            EvalTraceStyle::Summary
        }
    }

    #[cfg(test)]
    fn run_persist_cache_hook(&self, persist_cache: &PersistCache) {
        if let Some(hook) = &self.persist_cache_hook {
            (hook.0)(persist_cache);
        }
    }

    #[cfg(not(test))]
    fn run_persist_cache_hook(&self, _persist_cache: &PersistCache) {}

    #[cfg(test)]
    fn observe_persistent_parse_hit(&self, hit: NativePersistentParseHit) {
        if let Some(hook) = &self.persistent_parse_hit_hook {
            (hook.0)(hit);
        }
    }

    fn observe_eval_cache(&self, outcome: &EvalOutcome) {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "native evaluator cache lock was poisoned; skipping trace observation"
            );
            return;
        };
        if let Err(error) = cache.observe_impure_inputs(outcome) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "native evaluator cache trace observation failed"
            );
        }
    }
}

fn json_string_from_outcome(outcome: &EvalOutcome) -> Result<String> {
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .map_err(|source| NativeEvalError::Internal {
            message: format!("JSON renderer returned a non-string value: {source}"),
        })?;
    String::from_utf8(string.bytes().to_vec()).map_err(|source| {
        NativeEvalError::Internal {
            message: format!("JSON renderer returned non-UTF-8 bytes: {source}"),
        }
        .into()
    })
}

fn native_source_file(file: &Path, options: &TreeWalkOptions) -> Result<PathBuf> {
    let requested = PathBuf::from(std::ffi::OsString::from_vec(path_bytes(file)?));
    check_native_filesystem_path_access(options, requested.as_os_str().as_bytes())?;
    let metadata = fs::metadata(&requested).map_err(|source| NativeEvalError::EvalError {
        message: format!(
            "failed to stat native instantiation source {}: {source}",
            requested.display()
        ),
    })?;
    let target = if metadata.is_dir() {
        let target = requested.join("default.nix");
        check_native_filesystem_path_access(options, target.as_os_str().as_bytes())?;
        target
    } else {
        requested
    };
    fs::canonicalize(&target).map_err(|source| {
        NativeEvalError::EvalError {
            message: format!(
                "failed to resolve native instantiation source {}: {source}",
                target.display()
            ),
        }
        .into()
    })
}

fn check_native_filesystem_path_access(options: &TreeWalkOptions, path: &[u8]) -> Result<()> {
    if options.eval_mode() == EvalMode::Impure {
        return Ok(());
    }
    if !Path::new(OsStr::from_bytes(path)).is_absolute() {
        return Err(NativeEvalError::EvalError {
            message: format!(
                "{:?} evaluation requires an absolute native instantiation source path: {}",
                options.eval_mode(),
                String::from_utf8_lossy(path)
            ),
        }
        .into());
    }

    let normalized = normalize_absolute_path_bytes(path);
    if options.path_is_allowed(&normalized) {
        if let Some(resolved) = canonicalize_policy_path(path) {
            if !options.resolved_path_is_allowed(&resolved) {
                return Err(native_filesystem_access_denied(options.eval_mode(), &resolved).into());
            }
        }
        return Ok(());
    }

    Err(native_filesystem_access_denied(options.eval_mode(), &normalized).into())
}

fn native_filesystem_access_denied(mode: EvalMode, path: &[u8]) -> NativeEvalError {
    NativeEvalError::EvalError {
        message: format!(
            "{mode:?} evaluation forbids filesystem access to native instantiation source {}",
            String::from_utf8_lossy(path)
        ),
    }
}

mod error;
mod eval_stats_dump;
mod fallback;
pub(crate) mod memo_net;
mod parse_locations;
mod root_cutoff;
mod source;

#[cfg(test)]
pub(crate) mod tests;

use error::*;
use fallback::*;
use source::*;

const JSON_WRAPPER_PREFIX: &str = "builtins.toJSON (\n";
const JSON_WRAPPER_SUFFIX: &str = "\n)";
const DRV_PATH_WRAPPER_PREFIX: &str = "(\n";
const DRV_PATH_WRAPPER_SUFFIX: &str = "\n).drvPath";

fn diagnostic_source_for_range<'a>(
    expr: &str,
    diagnostic_name: &'a str,
    diagnostic_source: &'a str,
    wrapper_prefix_len: usize,
    diagnostic_range: Range<usize>,
) -> Result<(WrappedSourceMap, NativeDiagnosticSource<'a>)> {
    if diagnostic_range.start > diagnostic_range.end || diagnostic_range.end > expr.len() {
        return Err(NativeEvalError::Internal {
            message: format!(
                "invalid diagnostic range {}..{} for expression length {}",
                diagnostic_range.start,
                diagnostic_range.end,
                expr.len()
            ),
        }
        .into());
    }
    if &expr.as_bytes()[diagnostic_range.clone()] != diagnostic_source.as_bytes() {
        return Err(NativeEvalError::Internal {
            message: "diagnostic source does not match selected expression range".to_string(),
        }
        .into());
    }
    let prefix_len = wrapper_prefix_len
        .checked_add(diagnostic_range.start)
        .ok_or_else(|| NativeEvalError::Internal {
            message: "diagnostic range offset overflowed".to_string(),
        })?;
    let expr_len = diagnostic_range.end - diagnostic_range.start;
    let source_map = WrappedSourceMap {
        prefix_len,
        expr_len,
    };
    Ok((
        source_map,
        NativeDiagnosticSource::new(diagnostic_name, diagnostic_source, Some(source_map)),
    ))
}

#[derive(Clone, Copy)]
struct WrappedSourceMap {
    prefix_len: usize,
    expr_len: usize,
}
