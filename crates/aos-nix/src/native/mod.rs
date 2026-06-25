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
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;

#[cfg(test)]
use crate::cache::EvalCache;
use crate::cache::{EvalCacheRuntime, ParseCache, ParseCacheError};
#[cfg(test)]
use crate::compile::EffectClass;
use crate::compile::{Ir, IrAttrPathId, IrAttrPathSegment, IrData, IrId, IrKind, resolve};
use crate::drv_materialize::materialize_drv;
use crate::error::NativeEvalError;
use crate::eval::tree_walk::{canonicalize_policy_path, normalize_absolute_path_bytes};
use crate::eval::{
    EvalErrorLabel, EvalMode, EvalOutcome, IfdRealizer, TreeWalkError, TreeWalkErrorKind,
    TreeWalkOptions,
    eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache,
    eval_whnf_owned_with_options_realizer_and_eval_cache,
};
use crate::runtime::builtins::{
    Builtin, BuiltinAvailability, NativeCliFallbackFeature, is_unshadowable_global_name,
    lookup_builtin,
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

    /// Evaluates a raw expression to an in-memory derivation closure.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] when the expression reaches an
    /// evaluator feature that is still outside the native tree-walk subset.
    /// Returns [`NativeEvalError::EvalError`] when the expression does not
    /// evaluate to a derivation-like attribute set with a string `drvPath`.
    pub fn instantiate_expr_closure(&self, expr: &str) -> Result<NativeDrvClosure> {
        let source = derivation_path_wrapper_source(expr);
        let source_map = WrappedSourceMap {
            prefix_len: DRV_PATH_WRAPPER_PREFIX.len(),
            expr_len: expr.len(),
        };
        let diagnostic_source = NativeDiagnosticSource::new("expr.nix", expr, Some(source_map));
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
        let source = json_wrapper_source(expr);
        let source_map = WrappedSourceMap {
            prefix_len: JSON_WRAPPER_PREFIX.len(),
            expr_len: expr.len(),
        };
        let diagnostic_source = NativeDiagnosticSource::new("expr.nix", expr, Some(source_map));
        let ir = self.lower_native_source(&source, Some(source_map), Some(diagnostic_source))?;
        ensure_native_json_subset(&ir, expr.len(), &self.options)?;
        let outcome = self
            .eval_ir(&ir)
            .map_err(|error| native_eval_error_with_source(error, diagnostic_source))?;
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
        let outcome = self
            .eval_instantiation_ir(&ir)
            .map_err(|error| native_eval_error(error, source_map))?;
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
                Some(diagnostic_source) => native_eval_error_with_source(error, diagnostic_source),
                None => native_eval_error(error, source_map),
            })?;
        self.native_drv_closure_from_outcome(outcome)
    }

    fn eval_file_attr_derivation_closure(
        &self,
        file: &Path,
        attr: &str,
    ) -> Result<NativeDrvClosure> {
        let attr_path = attr_path_drv_path_segments(attr)?;
        let mut options = self.instantiation_options();
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
        let ir = self.lower_native_source_bytes(
            &source,
            Some(source_name_text.to_string()),
            None,
            diagnostic_source,
        )?;
        if let Some((feature, span)) = native_instantiation_cli_fallback_feature(&ir, &self.options)
        {
            return Err(NativeEvalError::Unsupported {
                feature: feature.to_string(),
                span: Some(crate::error::SrcSpan {
                    start: span.start,
                    end: span.end,
                }),
            }
            .into());
        }
        let outcome =
            eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache(
                &ir,
                &attr_path,
                options,
                source_name.clone(),
                source.clone(),
                self.ifd_realizer.clone(),
                self.eval_cache.clone(),
            )
            .map_err(|error| match diagnostic_source {
                Some(diagnostic_source) => native_eval_error_with_source(error, diagnostic_source),
                None => native_eval_error(error, None),
            })?;
        self.observe_eval_cache(&outcome);
        self.native_drv_closure_from_outcome(outcome)
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
        self.lower_native_source_bytes(source.as_bytes(), None, source_map, diagnostic_source)
    }

    fn lower_native_source_bytes(
        &self,
        source: &[u8],
        source_hint: Option<String>,
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<Ir> {
        if let Some(root) = self.options.parse_cache_root() {
            let cache = ParseCache::new(root);
            match cache.load_or_parse_bytes(source, source_hint) {
                Ok(cached) => {
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

    fn lower_native_source_uncached(
        source: &[u8],
        source_map: Option<WrappedSourceMap>,
        diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    ) -> Result<Ir> {
        let parsed = parse_bytes(source)
            .map_err(|source| unsupported_parse_error(source, source_map, diagnostic_source))?;
        let resolved = resolve(parsed)
            .map_err(|source| unsupported_scope_error(source, source_map, diagnostic_source))?;
        nix_lower(resolved)
            .map_err(|source| unsupported_ir_error(source, source_map, diagnostic_source).into())
    }

    fn eval_ir(&self, ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
        let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
            ir,
            self.options.clone(),
            self.ifd_realizer.clone(),
            self.eval_cache.clone(),
        )?;
        self.observe_eval_cache(&outcome);
        Ok(outcome)
    }

    fn eval_instantiation_ir(&self, ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
        let outcome = eval_whnf_owned_with_options_realizer_and_eval_cache(
            ir,
            self.instantiation_options(),
            self.ifd_realizer.clone(),
            self.eval_cache.clone(),
        )?;
        self.observe_eval_cache(&outcome);
        Ok(outcome)
    }

    fn instantiation_options(&self) -> TreeWalkOptions {
        let mut options = self.options.clone();
        options.set_reject_ambient_search_path(true);
        options.set_reject_unconfigured_impure_builtin_constants(true);
        options
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
mod fallback;
mod source;

#[cfg(test)]
mod tests;

use error::*;
use fallback::*;
use source::*;

const JSON_WRAPPER_PREFIX: &str = "builtins.toJSON (\n";
const JSON_WRAPPER_SUFFIX: &str = "\n)";
const DRV_PATH_WRAPPER_PREFIX: &str = "(\n";
const DRV_PATH_WRAPPER_SUFFIX: &str = "\n).drvPath";

#[derive(Clone, Copy)]
struct WrappedSourceMap {
    prefix_len: usize,
    expr_len: usize,
}
