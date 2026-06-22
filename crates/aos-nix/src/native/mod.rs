//! `aos-core` facing native evaluator shim.
//!
//! [`NixNative`] is the stable integration handle that will own the parser
//! cache, symbol interner, hash-consing tables, and evaluator arena as Phase 1
//! fills in. The current implementation is deliberately conservative: native
//! instantiation and JSON expression evaluation stay limited to the implemented
//! Phase-1 subset.

use std::collections::BTreeMap;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::cache::{ParseCache, ParseCacheError};
use crate::compile::{
    EffectClass, Ir, IrAttrPathId, IrAttrPathSegment, IrData, IrId, IrKind, lower, resolve,
};
use crate::drv_materialize::materialize_drv;
use crate::error::{NativeEvalError, SrcSpan};
use crate::eval::{
    EvalMode, EvalOutcome, IfdRealizer, TreeWalkError, TreeWalkErrorKind, TreeWalkOptions,
    eval_instantiation_attr_path_owned_with_options_and_realizer,
    eval_whnf_owned_with_options_and_realizer,
};
use crate::runtime::builtins::{
    Builtin, BuiltinAvailability, NativeCliFallbackFeature, is_unshadowable_global_name,
    lookup_builtin,
};
use crate::syntax::{Span, parse_str};
use crate::value::{Value, ValueTag};

/// In-process RFC-0007 evaluator handle.
#[derive(Debug, Clone)]
pub struct NixNative {
    verbose: u8,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
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
        self.eval_derivation_materialized_source(
            &source,
            Some(source_map),
            Some(NativeDiagnosticSource::new(
                "expr.nix",
                expr,
                Some(source_map),
            )),
        )
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
        self.eval_derivation_closure_source(
            &source,
            Some(source_map),
            Some(NativeDiagnosticSource::new(
                "expr.nix",
                expr,
                Some(source_map),
            )),
        )
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
        let ir = self.lower_native_source(&source, Some(source_map))?;
        ensure_native_json_subset(&ir, expr.len(), &self.options)?;
        let outcome = self.eval_ir(&ir).map_err(|error| {
            native_eval_error_with_source(
                error,
                NativeDiagnosticSource::new("expr.nix", expr, Some(source_map)),
            )
        })?;
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
    fn eval_derivation_path_source(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
    ) -> Result<PathBuf> {
        let ir = self.lower_native_source(source, source_map)?;
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
        let ir = self.lower_native_source(source, source_map)?;
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
        let source = file_import_source(file)?;
        let ir = self.lower_native_source(&source, None)?;
        if let Some((feature, span)) = native_instantiation_cli_fallback_feature(&ir, &self.options)
        {
            return Err(NativeEvalError::Unsupported {
                feature: feature.to_string(),
                span: Some(SrcSpan {
                    start: span.start,
                    end: span.end,
                }),
            }
            .into());
        }
        let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
            &ir,
            &attr_path,
            self.instantiation_options(),
            self.ifd_realizer.clone(),
        )
        .map_err(|error| native_eval_error(error, None))?;
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
    ) -> Result<Ir> {
        if let Some(root) = self.options.parse_cache_root() {
            let cache = ParseCache::new(root);
            match cache.load_or_parse_bytes(source.as_bytes(), None) {
                Ok(cached) => {
                    return Ok(cached.ir);
                }
                Err(error) => {
                    if let Some(error) = parse_cache_frontend_error(error, source_map) {
                        return Err(error.into());
                    }
                }
            }
        }

        Self::lower_native_source_uncached(source, source_map)
    }

    fn lower_native_source_uncached(
        source: &str,
        source_map: Option<WrappedSourceMap>,
    ) -> Result<Ir> {
        let parsed = parse_str(source).map_err(|source| {
            unsupported_frontend_error("parse", source.to_string(), source.span(), source_map)
        })?;
        let resolved = resolve(parsed).map_err(|source| {
            unsupported_frontend_error("resolve", source.to_string(), source.span(), source_map)
        })?;
        lower(resolved).map_err(|source| {
            unsupported_frontend_error("lower", source.to_string(), source.span(), source_map)
                .into()
        })
    }

    fn eval_ir(&self, ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
        eval_whnf_owned_with_options_and_realizer(
            ir,
            self.options.clone(),
            self.ifd_realizer.clone(),
        )
    }

    fn eval_instantiation_ir(&self, ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
        eval_whnf_owned_with_options_and_realizer(
            ir,
            self.instantiation_options(),
            self.ifd_realizer.clone(),
        )
    }

    fn instantiation_options(&self) -> TreeWalkOptions {
        let mut options = self.options.clone();
        options.set_reject_ambient_search_path(true);
        options.set_reject_unconfigured_impure_builtin_constants(true);
        options
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
