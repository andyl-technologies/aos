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
use crate::error::NativeEvalError;
use crate::eval::{
    EvalMode, EvalOutcome, IfdRealizer, TreeWalkError, TreeWalkErrorKind, TreeWalkOptions,
    eval_whnf_owned_with_options_and_realizer,
};
use crate::runtime::builtins::lookup_builtin;
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
        let attr_path = attr_path_selector(attr)?;
        let file = nix_string_literal(&path_bytes(file)?)?;
        let source = format!("(import {file}){attr_path}.drvPath");
        self.eval_derivation_materialized_source(&source, None)
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
        let attr_path = attr_path_selector(attr)?;
        let file = nix_string_literal(&path_bytes(file)?)?;
        let source = format!("(import {file}){attr_path}.drvPath");
        self.eval_derivation_closure_source(&source, None)
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
        self.eval_derivation_materialized_source(
            &source,
            Some(WrappedSourceMap {
                prefix_len: DRV_PATH_WRAPPER_PREFIX.len(),
                expr_len: expr.len(),
            }),
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
        self.eval_derivation_closure_source(
            &source,
            Some(WrappedSourceMap {
                prefix_len: DRV_PATH_WRAPPER_PREFIX.len(),
                expr_len: expr.len(),
            }),
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
        let outcome = self
            .eval_ir(&ir)
            .map_err(|error| native_eval_error(error, Some(source_map)))?;
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
    ) -> Result<PathBuf> {
        let closure = self.eval_derivation_closure_source(source, source_map)?;
        materialize_drv_closure(&closure)?;
        Ok(closure.root().to_path_buf())
    }

    fn eval_derivation_closure_source(
        &self,
        source: &str,
        source_map: Option<WrappedSourceMap>,
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
            .map_err(|error| native_eval_error(error, source_map))?;
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
                    return lower(cached.resolved).map_err(|source| {
                        unsupported_frontend_error(
                            "lower",
                            source.to_string(),
                            source.span(),
                            source_map,
                        )
                        .into()
                    });
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
        let mut options = self.options.clone();
        options.set_reject_ambient_search_path(true);
        options.set_reject_unconfigured_impure_builtin_constants(true);
        eval_whnf_owned_with_options_and_realizer(ir, options, self.ifd_realizer.clone())
    }
}

fn parse_cache_frontend_error(
    error: ParseCacheError,
    source_map: Option<WrappedSourceMap>,
) -> Option<NativeEvalError> {
    match error {
        ParseCacheError::Parse { source } => Some(unsupported_frontend_error(
            "parse",
            source.to_string(),
            source.span(),
            source_map,
        )),
        ParseCacheError::Scope { source } => Some(unsupported_frontend_error(
            "resolve",
            source.to_string(),
            source.span(),
            source_map,
        )),
        ParseCacheError::LowerIr { source } => Some(unsupported_frontend_error(
            "lower",
            source.to_string(),
            source.span(),
            source_map,
        )),
        ParseCacheError::CanonicalizeSource { .. }
        | ParseCacheError::ReadSource { .. }
        | ParseCacheError::CreateDir { .. }
        | ParseCacheError::WriteMeta { .. }
        | ParseCacheError::WriteArtifact { .. }
        | ParseCacheError::ReadArtifact { .. }
        | ParseCacheError::DecodeArtifact { .. }
        | ParseCacheError::EncodeArtifact(_) => None,
    }
}

fn materialize_drv_closure(closure: &NativeDrvClosure) -> Result<()> {
    for (path, bytes) in closure.drvs() {
        materialize_drv(path, bytes).map_err(|source| NativeEvalError::Internal {
            message: source.to_string(),
        })?;
    }
    Ok(())
}

const JSON_WRAPPER_PREFIX: &str = "builtins.toJSON (\n";
const JSON_WRAPPER_SUFFIX: &str = "\n)";
const DRV_PATH_WRAPPER_PREFIX: &str = "(\n";
const DRV_PATH_WRAPPER_SUFFIX: &str = "\n).drvPath";

fn json_wrapper_source(expr: &str) -> String {
    format!("{JSON_WRAPPER_PREFIX}{expr}{JSON_WRAPPER_SUFFIX}")
}

fn derivation_path_wrapper_source(expr: &str) -> String {
    format!("{DRV_PATH_WRAPPER_PREFIX}{expr}{DRV_PATH_WRAPPER_SUFFIX}")
}

#[derive(Clone, Copy)]
struct WrappedSourceMap {
    prefix_len: usize,
    expr_len: usize,
}

fn unsupported_frontend_error(
    stage: &'static str,
    message: String,
    span: Span,
    source_map: Option<WrappedSourceMap>,
) -> NativeEvalError {
    NativeEvalError::Unsupported {
        feature: format!("native expression {stage} failure: {message}"),
        span: source_map.and_then(|source_map| source_span_from_wrapped(span, source_map)),
    }
}

fn native_eval_error(
    error: TreeWalkError,
    source_map: Option<WrappedSourceMap>,
) -> NativeEvalError {
    let kind = error.kind();
    if let Some(feature) = tree_walk_unsupported_feature(&kind) {
        return NativeEvalError::Unsupported {
            feature,
            span: source_map
                .and_then(|source_map| source_span_from_wrapped(error.span(), source_map)),
        };
    }

    NativeEvalError::EvalError {
        message: error.to_string(),
    }
}

fn tree_walk_unsupported_feature(kind: &TreeWalkErrorKind) -> Option<String> {
    match kind {
        TreeWalkErrorKind::UnsupportedLambdaPattern { .. }
        | TreeWalkErrorKind::UnsupportedLetBindingKey { .. }
        | TreeWalkErrorKind::UnsupportedSourcePathType { .. }
        | TreeWalkErrorKind::UnsupportedPrimOp { .. }
        | TreeWalkErrorKind::UnsupportedBuiltinAttr { .. }
        | TreeWalkErrorKind::UnsupportedImportFromDerivation { .. }
        | TreeWalkErrorKind::UnsupportedDerivationStrictFeature { .. }
        | TreeWalkErrorKind::UnsupportedEqualityType { .. }
        | TreeWalkErrorKind::UnsupportedAttrPath { .. }
        | TreeWalkErrorKind::UnsupportedNode { .. }
        | TreeWalkErrorKind::ImportFromDerivation { .. } => Some(kind.to_string()),
        TreeWalkErrorKind::UnsupportedAmbientSearchPath { feature, .. } => {
            Some((*feature).to_string())
        }
        TreeWalkErrorKind::UnsupportedAmbientBuiltinConstant { feature, .. } => {
            Some((*feature).to_string())
        }
        TreeWalkErrorKind::SearchPathNotFound { ambient: true, .. } => {
            Some("configured Nix search path lookup".to_string())
        }
        TreeWalkErrorKind::Type {
            expected,
            actual: ValueTag::Attrs,
            ..
        } if matches!(*expected, "lambda" | "function") => Some(kind.to_string()),
        TreeWalkErrorKind::Type {
            expected: "attrs",
            actual: ValueTag::Lambda | ValueTag::Primop,
            ..
        } => Some(kind.to_string()),
        _ => None,
    }
}

fn ensure_native_json_subset(
    ir: &Ir,
    expr_len: usize,
    options: &TreeWalkOptions,
) -> Result<(), NativeEvalError> {
    for (index, node) in ir.arena.nodes().iter().enumerate() {
        if node.effect == EffectClass::Effectful {
            return Err(unsupported_native_node(
                "effectful expression evaluation",
                node.span,
                expr_len,
            ));
        }

        if node.kind == IrKind::BuiltinAttr
            && let IrData::Symbol(symbol) = node.data
            && let Some(name) = ir.symbols.resolve(symbol)
            && let Some(feature) = builtin_attr_native_json_fallback_feature(name, options)
        {
            return Err(unsupported_native_node(feature, node.span, expr_len));
        }

        if node.kind == IrKind::GlobalVar
            && let IrData::Symbol(symbol) = node.data
        {
            let Some(name) = ir.symbols.resolve(symbol) else {
                continue;
            };
            if name == b"builtins" {
                if let Some(feature) =
                    builtins_global_native_json_fallback_feature(ir, index, options)
                {
                    return Err(unsupported_native_node(feature, node.span, expr_len));
                }
                continue;
            }
            if let Some(feature) = builtin_native_cli_fallback_feature(name) {
                return Err(unsupported_native_node(feature, node.span, expr_len));
            }
        }

        if node.kind == IrKind::PrimOp
            && let IrData::PrimOp { symbol, .. } = node.data
            && let Some(name) = ir.symbols.resolve(symbol)
            && let Some(feature) = builtin_native_cli_fallback_feature(name)
        {
            return Err(unsupported_native_node(feature, node.span, expr_len));
        }

        if node.kind == IrKind::SearchPath {
            return Err(unsupported_native_node(
                "configured Nix search path lookup",
                node.span,
                expr_len,
            ));
        }
    }

    Ok(())
}

fn derivation_path_from_value(value: Value, heap: &crate::eval::EvalHeap) -> Result<PathBuf> {
    let string = heap
        .get_string(value)
        .map_err(|source| NativeEvalError::EvalError {
            message: format!("native instantiation did not produce a string drvPath: {source}"),
        })?;
    let path =
        std::str::from_utf8(string.bytes()).map_err(|source| NativeEvalError::EvalError {
            message: format!("native instantiation produced a non-UTF-8 drvPath: {source}"),
        })?;
    if !path.ends_with(".drv") {
        return Err(NativeEvalError::EvalError {
            message: format!("native instantiation produced a non-derivation path: {path}"),
        }
        .into());
    }
    Ok(PathBuf::from(path))
}

fn attr_path_selector(attr: &str) -> Result<String> {
    let mut selector = String::new();
    for segment in parse_attr_path_segments(attr)? {
        selector.push('.');
        selector.push_str(&nix_string_literal(&segment)?);
    }
    Ok(selector)
}

fn parse_attr_path_segments(attr: &str) -> Result<Vec<Vec<u8>>> {
    if attr.is_empty() {
        return Err(NativeEvalError::EvalError {
            message: "native instantiation attribute path must not be empty".to_string(),
        }
        .into());
    }

    let bytes = attr.as_bytes();
    let mut segments = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        let (segment, next_cursor) = if bytes[cursor] == b'"' {
            parse_quoted_attr_segment(attr, cursor)?
        } else {
            parse_bare_attr_segment(attr, cursor)?
        };
        segments.push(segment);
        cursor = next_cursor;

        if cursor == bytes.len() {
            break;
        }
        if bytes[cursor] != b'.' {
            return Err(NativeEvalError::EvalError {
                message: format!("native instantiation attribute path has invalid syntax: {attr}"),
            }
            .into());
        }
        cursor += 1;
        if cursor == bytes.len() {
            return Err(NativeEvalError::EvalError {
                message: format!(
                    "native instantiation attribute path has an empty segment: {attr}"
                ),
            }
            .into());
        }
    }

    Ok(segments)
}

fn parse_bare_attr_segment(attr: &str, start: usize) -> Result<(Vec<u8>, usize)> {
    let bytes = attr.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() && bytes[cursor] != b'.' {
        if bytes[cursor] == b'"' || bytes[cursor].is_ascii_whitespace() {
            return Err(NativeEvalError::EvalError {
                message: format!("native instantiation attribute path has invalid syntax: {attr}"),
            }
            .into());
        }
        cursor += 1;
    }
    if cursor == start {
        return Err(NativeEvalError::EvalError {
            message: format!("native instantiation attribute path has an empty segment: {attr}"),
        }
        .into());
    }
    if !is_valid_bare_attr_segment(&bytes[start..cursor]) {
        return Err(NativeEvalError::EvalError {
            message: format!(
                "native instantiation attribute path has an invalid bare segment: {attr}"
            ),
        }
        .into());
    }
    Ok((bytes[start..cursor].to_vec(), cursor))
}

fn is_valid_bare_attr_segment(segment: &[u8]) -> bool {
    let Some((first, rest)) = segment.split_first() else {
        return false;
    };
    if !is_nix_ident_start(*first) {
        return false;
    }
    if !rest.iter().copied().all(is_nix_ident_continue) {
        return false;
    }
    segment == b"or" || !is_reserved_nix_keyword(segment)
}

fn is_nix_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_nix_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'\'' | b'-')
}

fn is_reserved_nix_keyword(segment: &[u8]) -> bool {
    matches!(
        segment,
        b"let" | b"in" | b"if" | b"then" | b"else" | b"with" | b"rec" | b"inherit" | b"assert"
    )
}

fn parse_quoted_attr_segment(attr: &str, start: usize) -> Result<(Vec<u8>, usize)> {
    let bytes = attr.as_bytes();
    let mut out = Vec::new();
    let mut cursor = start + 1;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => return Ok((out, cursor + 1)),
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                return Err(NativeEvalError::Unsupported {
                    feature: "dynamic interpolation in native instantiation attribute path"
                        .to_string(),
                    span: None,
                }
                .into());
            }
            b'\\' => {
                cursor += 1;
                let Some(escaped) = bytes.get(cursor).copied() else {
                    return Err(NativeEvalError::EvalError {
                        message: format!(
                            "native instantiation attribute path has an unterminated escape: {attr}"
                        ),
                    }
                    .into());
                };
                match escaped {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'\\' | b'"' => out.push(escaped),
                    b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                        out.extend_from_slice(b"${");
                        cursor += 1;
                    }
                    _ => {
                        return Err(NativeEvalError::Unsupported {
                            feature: "unsupported escape in native instantiation attribute path"
                                .to_string(),
                            span: None,
                        }
                        .into());
                    }
                }
            }
            byte => out.push(byte),
        }
        cursor += 1;
    }

    Err(NativeEvalError::EvalError {
        message: format!("native instantiation attribute path has an unterminated string: {attr}"),
    }
    .into())
}

fn path_bytes(path: &Path) -> Result<Vec<u8>> {
    let bytes = path.as_os_str().as_bytes();
    if path.is_absolute() {
        Ok(bytes.to_vec())
    } else {
        let mut out = std::env::current_dir()
            .map_err(|source| NativeEvalError::EvalError {
                message: format!(
                    "failed to resolve current directory for native instantiation: {source}"
                ),
            })?
            .into_os_string()
            .into_vec();
        out.push(b'/');
        out.extend_from_slice(bytes);
        Ok(out)
    }
}

fn nix_string_literal(bytes: &[u8]) -> Result<String> {
    let mut out = String::new();
    out.push('"');
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => out.push_str(r"\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str(r"\n"),
            b'\r' => out.push_str(r"\r"),
            b'\t' => out.push_str(r"\t"),
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                out.push_str(r"\${");
                cursor += 1;
            }
            0x20..=0x7e => out.push(char::from(bytes[cursor])),
            _ => {
                return Err(NativeEvalError::Unsupported {
                    feature: "non-ASCII path or attribute segment in native instantiation"
                        .to_string(),
                    span: None,
                }
                .into());
            }
        }
        cursor += 1;
    }
    out.push('"');
    Ok(out)
}

fn builtins_global_native_json_fallback_feature(
    ir: &Ir,
    receiver_index: usize,
    options: &TreeWalkOptions,
) -> Option<&'static str> {
    let mut selected_known_native_builtin = false;

    for node in ir.arena.nodes() {
        let (receiver, path) = match node.data {
            IrData::Select { receiver, path, .. } | IrData::HasAttr { receiver, path, .. } => {
                (receiver, path)
            }
            _ => continue,
        };
        if !select_receiver_references_global(ir, receiver, receiver_index) {
            continue;
        }

        let Some(name) = static_single_attr_path(ir, path) else {
            return Some("CLI-sensitive builtin evaluation");
        };
        if name == b"currentSystem"
            && options.eval_mode() != EvalMode::Pure
            && options.current_system().is_some()
        {
            selected_known_native_builtin = true;
            continue;
        }
        if name == b"builtins" {
            return Some("CLI-sensitive builtin evaluation");
        }
        let Some(builtin) = lookup_builtin(name) else {
            return Some("CLI-sensitive builtin evaluation");
        };
        if let Some(feature) = builtin.native_cli_fallback_feature() {
            return Some(feature);
        }

        selected_known_native_builtin = true;
    }

    if selected_known_native_builtin {
        None
    } else {
        Some("CLI-sensitive builtin evaluation")
    }
}

fn builtin_attr_native_json_fallback_feature(
    name: &[u8],
    options: &TreeWalkOptions,
) -> Option<&'static str> {
    if name == b"currentSystem"
        && options.eval_mode() != EvalMode::Pure
        && options.current_system().is_some()
    {
        return None;
    }
    if name == b"builtins" {
        return Some("CLI-sensitive builtin evaluation");
    }
    builtin_native_cli_fallback_feature(name)
}

fn builtin_native_cli_fallback_feature(name: &[u8]) -> Option<&'static str> {
    lookup_builtin(name).and_then(|builtin| builtin.native_cli_fallback_feature())
}

fn native_instantiation_cli_fallback_feature(
    ir: &Ir,
    options: &TreeWalkOptions,
) -> Option<(&'static str, Span)> {
    for node in ir.arena.nodes() {
        if node.kind == IrKind::BuiltinAttr
            && let IrData::Symbol(symbol) = node.data
            && let Some(name) = ir.symbols.resolve(symbol)
            && builtin_instantiation_attr_is_cli_sensitive(name, options)
        {
            return Some(("CLI-sensitive builtin evaluation", node.span));
        }
    }

    for (index, node) in ir.arena.nodes().iter().enumerate() {
        let (IrKind::GlobalVar, IrData::Symbol(symbol)) = (node.kind, node.data) else {
            continue;
        };
        let Some(name) = ir.symbols.resolve(symbol) else {
            continue;
        };
        if name != b"builtins" {
            continue;
        };
        if let Some(feature) =
            builtins_global_native_instantiation_fallback_feature(ir, index, options)
        {
            return Some(feature);
        }
    }
    None
}

fn builtin_instantiation_attr_is_cli_sensitive(name: &[u8], options: &TreeWalkOptions) -> bool {
    match name {
        b"currentSystem" => {
            options.eval_mode() != EvalMode::Pure && options.current_system().is_none()
        }
        b"currentTime" => options.eval_mode() != EvalMode::Pure && options.current_time().is_none(),
        _ => false,
    }
}

fn builtins_global_native_instantiation_fallback_feature(
    ir: &Ir,
    receiver_index: usize,
    options: &TreeWalkOptions,
) -> Option<(&'static str, Span)> {
    for node in ir.arena.nodes() {
        let (receiver, path) = match node.data {
            IrData::Select { receiver, path, .. } | IrData::HasAttr { receiver, path, .. } => {
                (receiver, path)
            }
            _ => continue,
        };
        if !select_receiver_references_global(ir, receiver, receiver_index) {
            continue;
        }

        if builtins_instantiation_attr_path_is_cli_sensitive(ir, path, options) {
            return Some(("CLI-sensitive builtin evaluation", node.span));
        }
    }
    None
}

fn builtins_instantiation_attr_path_is_cli_sensitive(
    ir: &Ir,
    path: IrAttrPathId,
    options: &TreeWalkOptions,
) -> bool {
    let Some(segments) = ir.attr_paths.get(path.index()) else {
        return true;
    };
    let Some(first) = segments.first() else {
        return false;
    };
    let IrAttrPathSegment::Static(symbol) = first else {
        return true;
    };
    ir.symbols
        .resolve(*symbol)
        .is_some_and(|name| builtin_instantiation_attr_is_cli_sensitive(name, options))
}

fn select_receiver_references_global(ir: &Ir, mut receiver: IrId, global_index: usize) -> bool {
    loop {
        if receiver.index() == global_index {
            return true;
        }

        let Some(node) = ir.arena.node(receiver) else {
            return false;
        };
        let (IrKind::ThunkAlloc, IrData::Node(inner)) = (node.kind, node.data) else {
            return false;
        };
        if inner.index() == receiver.index() {
            return false;
        }
        receiver = inner;
    }
}

fn static_single_attr_path<'a>(ir: &'a Ir, path: IrAttrPathId) -> Option<&'a [u8]> {
    let Some(segments) = ir.attr_paths.get(path.index()) else {
        return None;
    };
    let [IrAttrPathSegment::Static(symbol)] = segments.as_ref() else {
        return None;
    };
    ir.symbols.resolve(*symbol)
}

fn unsupported_native_node(feature: &'static str, span: Span, expr_len: usize) -> NativeEvalError {
    let source_map = WrappedSourceMap {
        prefix_len: JSON_WRAPPER_PREFIX.len(),
        expr_len,
    };
    NativeEvalError::Unsupported {
        feature: feature.to_string(),
        span: source_span_from_wrapped(span, source_map),
    }
}

fn source_span_from_wrapped(
    span: Span,
    source_map: WrappedSourceMap,
) -> Option<crate::error::SrcSpan> {
    let prefix_len = u32::try_from(source_map.prefix_len).ok()?;
    let expr_len = u32::try_from(source_map.expr_len).ok()?;
    let expr_end = prefix_len.checked_add(expr_len)?;
    if span.start < prefix_len || span.end > expr_end {
        return None;
    }
    Some(src_span(Span::new(
        span.start - prefix_len,
        span.end - prefix_len,
    )))
}

const fn src_span(span: Span) -> crate::error::SrcSpan {
    crate::error::SrcSpan {
        start: span.start,
        end: span.end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::IfdRealizationError;
    use std::fs;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn native_expression_eval_renders_strict_json() -> Result<()> {
        let native = NixNative::new(0)?;

        assert_eq!(native.eval_expr("1 + 1")?, "2");
        assert_eq!(native.eval_expr("1 # trailing comment")?, "1");
        assert_eq!(native.eval_expr(r#""x""#)?, r#""x""#);
        assert_eq!(
            native.eval_expr(r#"{ b = 1; a = [ true null "x" ]; }"#)?,
            r#"{"a":[true,null,"x"],"b":1}"#
        );

        Ok(())
    }

    #[test]
    fn native_expression_eval_uses_configured_parse_cache() -> Result<()> {
        let root = unique_temp_dir("native-expression-parse-cache");
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let cache_root = root.join("parse");
        let mut options = TreeWalkOptions::new();
        options.set_parse_cache_root(&cache_root);
        let native = NixNative::with_options(0, options)?;
        let expr = "1 + 1";

        assert_eq!(native.eval_expr(expr)?, "2");

        let cache = ParseCache::new(&cache_root);
        let entry = cache.entry_for_source(json_wrapper_source(expr).as_bytes());
        assert!(
            entry.is_complete(),
            "native expression evaluation should populate the parse-cache entry"
        );

        assert_eq!(native.eval_expr(expr)?, "2");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_expression_parse_cache_preserves_frontend_error_spans() -> Result<()> {
        let root = unique_temp_dir("native-expression-parse-cache-error");
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let mut options = TreeWalkOptions::new();
        options.set_parse_cache_root(root.join("parse"));
        let native = NixNative::with_options(0, options)?;

        let err = native
            .eval_expr("let { body = 1; }")
            .expect_err("frontend gaps should fall back through the cached path");

        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported {
                    feature,
                    span: Some(_),
                }) if feature.contains("native expression parse failure")
            ),
            "{err:?}"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_expr_returns_drv_path() -> Result<()> {
        let (native, root, store) = native_with_temp_store("native-instantiation-expr")?;

        let path = native.instantiate_expr(
            r#"derivationStrict {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
        )?;

        assert!(path.starts_with(&store), "{}", path.display());
        assert!(path.to_string_lossy().ends_with("-base.drv"));
        let bytes = assert_materialized_drv(&path)?;
        assert!(bytes.starts_with(b"Derive("));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_expr_uses_configured_parse_cache() -> Result<()> {
        let root = unique_temp_dir("native-instantiation-parse-cache");
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let store = root.join("store");
        let cache_root = root.join("parse");
        let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
        options.set_parse_cache_root(&cache_root);
        let native = NixNative::with_options(0, options)?;
        let expr = r#"derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#;

        let path = native.instantiate_expr(expr)?;

        assert!(path.starts_with(&store), "{}", path.display());
        let cache = ParseCache::new(&cache_root);
        let entry = cache.entry_for_source(derivation_path_wrapper_source(expr).as_bytes());
        assert!(
            entry.is_complete(),
            "native instantiation should populate the parse-cache entry"
        );

        let cached_path = native.instantiate_expr(expr)?;
        assert_eq!(cached_path, path);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_reified_builtins_do_not_force_nix_path() -> Result<()> {
        let (native, root, store) = native_with_temp_store("native-reified-builtins")?;

        for source in [
            r#"let b = builtins; in b.derivationStrict {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
            r#"let b = builtins; in b.${"derivationStrict"} {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
            r#"with builtins; derivationStrict {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
        ] {
            let closure = native.instantiate_expr_closure(source)?;
            assert!(
                closure.root().starts_with(&store),
                "{}",
                closure.root().display()
            );
            assert!(closure.root().to_string_lossy().ends_with("-base.drv"));
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_uses_configured_ifd_realizer() -> Result<()> {
        let root = unique_temp_dir("native-ifd");
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let store = root.join("store");
        fs::create_dir(&store)?;
        let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
        let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
        let import_path = output_path.join("imported.nix");
        let builder = store.join("cccccccccccccccccccccccccccccccc-builder");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_realizer = Arc::clone(&requests);
        let drv_path_for_realizer = drv_path.as_os_str().as_bytes().to_vec();
        let import_path_for_realizer = import_path.clone();
        let output_path_for_realizer = output_path.clone();
        let realizer = IfdRealizer::new(move |request| {
            requests_for_realizer
                .lock()
                .expect("request log lock")
                .push((
                    request.path().to_vec(),
                    request.drv_path().to_vec(),
                    request.output_name().map(<[u8]>::to_vec),
                    request.context_kind(),
                    request.op(),
                ));
            if request.drv_path() != drv_path_for_realizer.as_slice() {
                return Err(IfdRealizationError::new("unexpected derivation path"));
            }
            fs::create_dir_all(&output_path_for_realizer)
                .map_err(|source| IfdRealizationError::new(source.to_string()))?;
            fs::write(&import_path_for_realizer, br#""from-ifd""#)
                .map_err(|source| IfdRealizationError::new(source.to_string()))?;
            Ok(())
        });
        let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
        let native = NixNative::with_options(0, options)?.with_ifd_realizer(realizer);
        let source = format!(
            r#"let
                 imported = builtins.appendContext {imported} {{
                   {drv} = {{ outputs = [ "out" ]; }};
                 }};
                 d = builtins.derivationStrict {{
                   name = "native-ifd";
                   system = "x86_64-linux";
                   builder = {builder};
                   args = [ (import imported) ];
                 }};
               in d.drvPath"#,
            imported = nix_string_literal(&path_bytes(&import_path)?)?,
            drv = nix_string_literal(&path_bytes(&drv_path)?)?,
            builder = nix_string_literal(&path_bytes(&builder)?)?,
        );

        let path = native.eval_derivation_path_source(&source, None)?;
        assert!(path.to_string_lossy().ends_with("-native-ifd.drv"));
        let requests = requests.lock().expect("request log lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, import_path.as_os_str().as_bytes());
        assert_eq!(requests[0].1, drv_path.as_os_str().as_bytes());
        assert_eq!(requests[0].2.as_deref(), Some(b"out".as_slice()));
        assert_eq!(requests[0].3, crate::string::ContextKind::SingleOutput);
        assert_eq!(requests[0].4, "import");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_ifd_materializes_known_drv_before_realizer() -> Result<()> {
        use std::ffi::OsStr;

        let root = unique_temp_dir("native-ifd-known-drv");
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let store = root.join("store");
        fs::create_dir(&store)?;
        let builder = store.join("cccccccccccccccccccccccccccccccc-builder");
        let store_for_realizer = store.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_realizer = Arc::clone(&requests);
        let realizer = IfdRealizer::new(move |request| {
            let drv_path = PathBuf::from(OsStr::from_bytes(request.drv_path()));
            let drv_bytes = fs::read(&drv_path)
                .map_err(|source| IfdRealizationError::new(source.to_string()))?;
            if !drv_bytes.starts_with(b"Derive(") {
                return Err(IfdRealizationError::new(
                    "materialized IFD derivation is not an ATerm derivation",
                ));
            }
            let materialized_drvs = fs::read_dir(&store_for_realizer)
                .map_err(|source| IfdRealizationError::new(source.to_string()))?
                .map(|entry| {
                    entry
                        .map_err(|source| IfdRealizationError::new(source.to_string()))
                        .map(|entry| entry.path())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let materialized_drv_count = materialized_drvs
                .iter()
                .filter(|path| path.extension() == Some(OsStr::new("drv")))
                .count();
            if materialized_drv_count < 2 {
                return Err(IfdRealizationError::new(
                    "native IFD did not materialize the input derivation closure",
                ));
            }
            requests_for_realizer
                .lock()
                .expect("request log lock")
                .push((
                    request.path().to_vec(),
                    request.drv_path().to_vec(),
                    request.output_name().map(<[u8]>::to_vec),
                    request.context_kind(),
                    request.op(),
                ));
            let import_path = PathBuf::from(OsStr::from_bytes(request.path()));
            let Some(output_dir) = import_path.parent() else {
                return Err(IfdRealizationError::new("IFD import path has no parent"));
            };
            fs::create_dir_all(output_dir)
                .map_err(|source| IfdRealizationError::new(source.to_string()))?;
            fs::write(&import_path, br#""from-native-ifd""#)
                .map_err(|source| IfdRealizationError::new(source.to_string()))?;
            Ok(())
        });
        let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
        let native = NixNative::with_options(0, options)?.with_ifd_realizer(realizer);
        let source = format!(
            r#"let
                 base = builtins.derivationStrict {{
                   name = "base";
                   system = "x86_64-linux";
                   builder = {builder};
                 }};
                 producer = builtins.derivationStrict {{
                   name = "producer";
                   system = "x86_64-linux";
                   builder = {builder};
                   input = base.out;
                 }};
                 consumer = builtins.derivationStrict {{
                   name = "consumer";
                   system = "x86_64-linux";
                   builder = {builder};
                   args = [ (import "${{producer.out}}/imported.nix") ];
                 }};
               in consumer.drvPath"#,
            builder = nix_string_literal(&path_bytes(&builder)?)?,
        );

        let path = native.eval_derivation_path_source(&source, None)?;

        assert!(path.to_string_lossy().ends_with("-consumer.drv"));
        let requests = requests.lock().expect("request log lock");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.ends_with(b"/imported.nix"));
        assert!(requests[0].1.starts_with(store.as_os_str().as_bytes()));
        assert_eq!(requests[0].2.as_deref(), Some(b"out".as_slice()));
        assert_eq!(requests[0].3, crate::string::ContextKind::SingleOutput);
        assert_eq!(requests[0].4, "import");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_ifd_realizer_failures_remain_fallback_eligible() -> Result<()> {
        let root = unique_temp_dir("native-ifd-failure");
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        let store = root.join("store");
        fs::create_dir(&store)?;
        let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
        let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
        let import_path = output_path.join("imported.nix");
        let builder = store.join("cccccccccccccccccccccccccccccccc-builder");
        let realizer = IfdRealizer::new(|_| Err(IfdRealizationError::new("missing native drv")));
        let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
        let native = NixNative::with_options(0, options)?.with_ifd_realizer(realizer);
        let source = format!(
            r#"let
                 imported = builtins.appendContext {imported} {{
                   {drv} = {{ outputs = [ "out" ]; }};
                 }};
                 d = builtins.derivationStrict {{
                   name = "native-ifd";
                   system = "x86_64-linux";
                   builder = {builder};
                   args = [ (import imported) ];
                 }};
               in d.drvPath"#,
            imported = nix_string_literal(&path_bytes(&import_path)?)?,
            drv = nix_string_literal(&path_bytes(&drv_path)?)?,
            builder = nix_string_literal(&path_bytes(&builder)?)?,
        );

        let error = native
            .eval_derivation_path_source(&source, None)
            .expect_err("realizer failure remains fallback eligible");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, .. })
                    if feature.contains("IFD realization failed")
                        && feature.contains("missing native drv")
            ),
            "{error:?}"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_expr_returns_drv_closure_bytes() -> Result<()> {
        let native = NixNative::new(0)?;

        let closure = native.instantiate_expr_closure(
            r#"derivationStrict {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
        )?;

        assert_eq!(
            closure.root(),
            Path::new("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv")
        );
        let root_bytes = closure
            .drvs()
            .get(closure.root())
            .expect("root derivation bytes are recorded");
        assert!(root_bytes.starts_with(b"Derive("));
        assert!(nix_compat::derivation::Derivation::from_aterm_bytes(root_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn native_instantiation_expr_closure_includes_input_derivation_bytes() -> Result<()> {
        let native = NixNative::new(0)?;

        let closure = native.instantiate_expr_closure(
            r#"let
                 base = derivationStrict {
                   name = "base";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in derivationStrict {
                 name = "consumer";
                 system = "x86_64-linux";
                 builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
                 input = "${base.out}";
               }"#,
        )?;

        let base = Path::new("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
        assert!(closure.drvs().contains_key(base));
        assert_eq!(closure.drvs().len(), 2);
        let root_bytes = closure
            .drvs()
            .get(closure.root())
            .expect("root derivation bytes are recorded");
        let root_text = std::str::from_utf8(root_bytes)?;
        assert!(root_text.contains("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv"));
        Ok(())
    }

    #[test]
    fn native_instantiation_expr_materializes_input_drv_closure() -> Result<()> {
        let (native, root, store) = native_with_temp_store("native-materialized-closure")?;
        let expr = r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in derivationStrict {
             name = "consumer";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${base.out}";
           }"#;

        let expected = native.instantiate_expr_closure(expr)?;
        assert_eq!(expected.drvs().len(), 2);
        assert!(expected.drvs().keys().all(|path| !path.exists()));

        let path = native.instantiate_expr(expr)?;

        assert_eq!(path, expected.root());
        assert!(path.starts_with(&store), "{}", path.display());
        for (path, expected_bytes) in expected.drvs() {
            let actual = assert_materialized_drv(path)?;
            assert_eq!(&actual, expected_bytes, "{}", path.display());
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_refuses_conflicting_existing_drv() -> Result<()> {
        let (native, root, _store) = native_with_temp_store("native-conflicting-drv")?;
        let expr = r#"derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#;
        let closure = native.instantiate_expr_closure(expr)?;
        let parent = closure
            .root()
            .parent()
            .ok_or_else(|| anyhow::anyhow!("root derivation path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(closure.root(), b"not a derivation")?;

        let error = native
            .instantiate_expr(expr)
            .expect_err("conflicting derivation file must not be overwritten");

        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Internal { message })
                    if message.contains("refusing to overwrite existing derivation")
            ),
            "{error:?}"
        );
        assert_eq!(fs::read(closure.root())?, b"not a derivation");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_expr_closure_supports_floating_ca_bytes() -> Result<()> {
        let (native, root, store) = native_with_temp_store("native-floating-ca")?;
        let expr = r#"derivationStrict {
             name = "ca";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             __contentAddressed = true;
             outputHashAlgo = "sha256";
             outputHashMode = "recursive";
           }"#;

        let path = native.instantiate_expr(expr)?;
        assert!(path.starts_with(&store), "{}", path.display());
        assert!(path.to_string_lossy().ends_with("-ca.drv"));
        let materialized = assert_materialized_drv(&path)?;

        let closure = native.instantiate_expr_closure(expr)?;
        assert_eq!(closure.root(), path);
        let bytes = closure
            .drvs()
            .get(closure.root())
            .expect("floating CA root derivation bytes are recorded");
        let text = std::str::from_utf8(bytes)?;
        assert!(text.contains(r#""r:sha256""#));
        assert!(text.contains(r#"("out","","r:sha256","")"#));
        assert_eq!(&materialized, bytes);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_path_instantiation_materializes_downstream_deferred_drv_bytes() -> Result<()> {
        let (native, root, store) = native_with_temp_store("native-deferred-drv")?;
        let expr = r#"let
             base = derivationStrict {
               name = "ca";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in derivationStrict {
             name = "consumer";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${base.out}";
           }"#;

        let path = native.instantiate_expr(expr)?;
        assert!(path.starts_with(&store), "{}", path.display());
        assert!(path.to_string_lossy().ends_with("-consumer.drv"));

        let closure = native.instantiate_expr_closure(expr)?;
        assert_eq!(closure.root(), path);
        assert_eq!(closure.drvs().len(), 2);
        for (path, expected_bytes) in closure.drvs() {
            let actual = assert_materialized_drv(path)?;
            assert_eq!(&actual, expected_bytes, "{}", path.display());
        }

        let root_bytes = closure
            .drvs()
            .get(closure.root())
            .expect("deferred consumer root derivation bytes are recorded");
        let root_text = std::str::from_utf8(root_bytes)?;
        assert!(root_text.contains(r#"("out","/"#));
        assert!(!root_text.contains(r#"("out","","","")"#));
        assert!(!root_text.contains(r#"("out","")"#));
        assert_eq!(root_text.matches(r#"("out","/"#).count(), 2);
        let ca_drv = closure
            .drvs()
            .keys()
            .find(|path| path.to_string_lossy().ends_with("-ca.drv"))
            .expect("CA input derivation is recorded");
        assert!(root_text.contains(&ca_drv.display().to_string()));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn configured_cpp_nix_native_drv_closure_bytes_match_cli() -> Result<()> {
        let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
            eprintln!("AOS_NIX_ORACLE not set; skipping native drv byte oracle check");
            return Ok(());
        };
        let native = NixNative::new(0)?;

        for expr in [
            r#"derivationStrict {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
            r#"let
                 base = derivationStrict {
                   name = "base";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in derivationStrict {
                 name = "consumer";
                 system = "x86_64-linux";
                 builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
                 input = "${base.out}";
               }"#,
            r#"derivationStrict {
                 name = "ca";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __contentAddressed = true;
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
            r#"let
                 base = derivationStrict {
                   name = "ca";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   __contentAddressed = true;
                   outputHashAlgo = "sha256";
                   outputHashMode = "recursive";
                 };
               in derivationStrict {
                 name = "consumer";
                 system = "x86_64-linux";
                 builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
                 input = "${base.out}";
               }"#,
        ] {
            let closure = native.instantiate_expr_closure(expr)?;
            let output = Command::new(&oracle).args(["--expr", expr]).output()?;
            if !output.status.success()
                && String::from_utf8_lossy(&output.stderr).contains("experimental Nix feature")
            {
                eprintln!("configured C++ Nix oracle skipped experimental expression {expr:?}");
                continue;
            }
            assert!(
                output.status.success(),
                "C++ Nix oracle unexpectedly rejected {expr:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let root = String::from_utf8(output.stdout)?.trim().to_string();
            assert_eq!(closure.root(), Path::new(&root), "{expr}");

            for (path, bytes) in closure.drvs() {
                let expected = fs::read(path)?;
                assert_eq!(bytes, &expected, "{}", path.display());
            }
        }

        Ok(())
    }

    #[test]
    fn native_instantiation_imports_file_attr_path() -> Result<()> {
        let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate")?;
        let dir = root.join("src");
        fs::create_dir_all(&dir)?;
        let file = dir.join("default.nix");
        fs::write(
            &file,
            r#"{
              pkgs.hello = derivationStrict {
                name = "base";
                system = "x86_64-linux";
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }"#,
        )?;

        let path = native.instantiate(&file, "pkgs.hello")?;

        assert!(path.starts_with(&store), "{}", path.display());
        assert!(path.to_string_lossy().ends_with("-base.drv"));
        let _ = assert_materialized_drv(&path)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_accepts_quoted_attr_path_segments() -> Result<()> {
        let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-quoted")?;
        let dir = root.join("src");
        fs::create_dir_all(&dir)?;
        let file = dir.join("default.nix");
        fs::write(
            &file,
            r#"{
              "pkgs.with.dot".hello = derivationStrict {
                name = "base";
                system = "x86_64-linux";
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }"#,
        )?;

        let path = native.instantiate(&file, r#""pkgs.with.dot".hello"#)?;

        assert!(path.starts_with(&store), "{}", path.display());
        assert!(path.to_string_lossy().ends_with("-base.drv"));
        let _ = assert_materialized_drv(&path)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_instantiation_function_file_stays_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;
        let dir = unique_temp_dir("aos-nix-native-instantiate-function");
        fs::create_dir_all(&dir)?;
        let file = dir.join("default.nix");
        fs::write(
            &file,
            r#"{ system ? "x86_64-linux" }: {
              pkgs.hello = derivationStrict {
                name = "base";
                inherit system;
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }"#,
        )?;

        let error = native
            .instantiate(&file, "pkgs.hello")
            .expect_err("function-valued files should fall back to C++ Nix for now");
        let _ = fs::remove_dir_all(&dir);

        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { .. })
        ));
        Ok(())
    }

    #[test]
    fn native_instantiation_search_path_stays_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;

        for (source, expected) in [
            ("<nixpkgs>", "configured Nix search path lookup"),
            ("builtins.nixPath", "builtins.nixPath"),
            ("let b = builtins; in b.nixPath", "builtins.nixPath"),
            (r#"builtins.${"nixPath"}"#, "builtins.nixPath"),
            ("with builtins; nixPath", "builtins.nixPath"),
        ] {
            let error = native
                .instantiate_expr(source)
                .expect_err("search-path-sensitive instantiation should fall back");
            assert!(
                matches!(
                    error.downcast_ref::<NativeEvalError>(),
                    Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                        if feature.contains(expected)
                ),
                "unexpected error for {source:?}: {error:?}"
            );
        }

        let dir = unique_temp_dir("aos-nix-native-instantiate-search-path");
        fs::create_dir_all(&dir)?;
        let file = dir.join("default.nix");
        fs::write(&file, r#"{ pkgs.hello = <nixpkgs>; }"#)?;

        let error = native
            .instantiate(&file, "pkgs.hello")
            .expect_err("file-backed search-path instantiation should fall back");
        let _ = fs::remove_dir_all(&dir);

        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, .. })
                    if feature.contains("configured Nix search path lookup")
            ),
            "unexpected error: {error:?}"
        );

        let error = native
            .instantiate_expr(
                r#"builtins.findFile [ { path = "/definitely-missing-aos-nix"; } ] "missing""#,
            )
            .expect_err("explicit findFile misses are semantic eval errors");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { .. })
            ),
            "unexpected explicit findFile error: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn native_instantiation_impure_builtin_constants_stay_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;

        for source in [
            "builtins.currentTime",
            "builtins.currentTime or 42",
            "builtins.currentSystem",
            "builtins ? currentTime",
            "builtins ? currentSystem",
            r#"builtins.${"currentTime"}"#,
        ] {
            let error = native
                .instantiate_expr(source)
                .expect_err("CLI-sensitive impure constants should fall back");
            assert!(
                matches!(
                    error.downcast_ref::<NativeEvalError>(),
                    Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                        if feature.contains("CLI-sensitive builtin evaluation")
                ),
                "unexpected error for {source:?}: {error:?}"
            );
        }

        let configured_system = NixNative::with_options(
            0,
            TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?,
        )?;
        let error = configured_system
            .instantiate_expr("builtins.currentSystem")
            .expect_err("configured currentSystem is evaluated natively, then rejected as non-drv");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { .. })
            ),
            "unexpected configured currentSystem error: {error:?}"
        );

        let mut pure_options = TreeWalkOptions::new();
        pure_options.set_eval_mode(EvalMode::Pure);
        let pure = NixNative::with_options(0, pure_options)?;
        let error = pure
            .instantiate_expr("builtins.currentTime or 42")
            .expect_err("pure currentTime remains a native semantic result");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { .. })
            ),
            "unexpected pure currentTime error: {error:?}"
        );

        let error = native
            .instantiate_expr("builtins.length.foo or 42")
            .expect_err("unrelated static builtins paths should stay semantic");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { .. })
            ),
            "unexpected unrelated static builtins path error: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn native_instantiation_imported_impure_constants_stay_fallback_eligible() -> Result<()> {
        let dir = unique_temp_dir("native-instantiation-impure-import");
        fs::create_dir_all(&dir)?;
        let file = dir.join("default.nix");
        fs::write(
            &file,
            r#"{
              pkgs.hello = derivationStrict {
                name = "base";
                system = builtins.currentSystem;
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
              pkgs.alias = let b = builtins; in derivationStrict {
                name = "alias";
                system = b.currentSystem;
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
              pkgs.dynamic = let name = "currentSystem"; in derivationStrict {
                name = "dynamic";
                system = builtins.${name};
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }"#,
        )?;
        let native = NixNative::new(0)?;

        for attr in ["pkgs.hello", "pkgs.alias", "pkgs.dynamic"] {
            let error = native
                .instantiate(&file, attr)
                .expect_err("file-backed impure constants should fall back");
            assert!(
                matches!(
                    error.downcast_ref::<NativeEvalError>(),
                    Some(NativeEvalError::Unsupported { feature, .. })
                        if feature.contains("CLI-sensitive builtin evaluation")
                ),
                "unexpected file-backed error for {attr}: {error:?}"
            );
        }

        let file_literal = nix_string_literal(file.as_os_str().as_bytes())?;
        let error = native
            .instantiate_expr(&format!("(import {file_literal}).pkgs.hello"))
            .expect_err("expression import impure constants should fall back");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature.contains("CLI-sensitive builtin evaluation")
            ),
            "unexpected expression import error: {error:?}"
        );

        let error = native
            .instantiate_expr(&format!(
                "(builtins.scopedImport {{ }} {file_literal}).pkgs.hello"
            ))
            .expect_err("scoped import impure constants should fall back");
        let _ = fs::remove_dir_all(&dir);

        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature.contains("CLI-sensitive builtin evaluation")
            ),
            "unexpected scoped import error: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn native_instantiation_attr_path_selector_rejects_invalid_bare_segments() -> Result<()> {
        for attr in ["pkgs;hello", "1pkg.hello", "let.hello", "pkgs."] {
            let error = attr_path_selector(attr).expect_err("invalid attr path should fail");
            assert!(matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { .. })
            ));
        }

        assert_eq!(
            attr_path_selector("or.foo-bar.x'")?,
            r#"."or"."foo-bar"."x'""#
        );
        assert_eq!(
            attr_path_selector(r#""pkgs.with.dot".hello"#)?,
            r#"."pkgs.with.dot"."hello""#
        );
        Ok(())
    }

    #[test]
    fn native_instantiation_string_literals_escape_interpolation_openers() -> Result<()> {
        assert_eq!(nix_string_literal(b"/tmp/${name}")?, r#""/tmp/\${name}""#);
        assert_eq!(
            attr_path_selector(r#""a\${b}".hello"#)?,
            r#"."a\${b}"."hello""#
        );

        let error = attr_path_selector(r#""a${b}""#)
            .expect_err("dynamic attr-path interpolation should stay unsupported");
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { .. })
        ));
        Ok(())
    }

    #[test]
    fn native_instantiation_rejects_non_derivations() -> Result<()> {
        let native = NixNative::new(0)?;

        let error = native
            .instantiate_expr("1")
            .expect_err("non-derivations should not instantiate");

        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ));
        Ok(())
    }

    #[test]
    fn native_instantiation_rejects_fabricated_drv_path_attrsets() -> Result<()> {
        let native = NixNative::new(0)?;

        let error = native
            .instantiate_expr(
                r#"{ drvPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fake.drv"; }"#,
            )
            .expect_err("fabricated drvPath attrsets do not have native drv bytes");

        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::EvalError { message })
                    if message.contains("not produced by derivationStrict")
            ),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn configured_cpp_nix_native_expression_eval_matches_cli_json() -> Result<()> {
        let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
            eprintln!("AOS_NIX_ORACLE not set; skipping configured native eval_expr check");
            return Ok(());
        };
        let native = NixNative::new(0)?;

        for source in [
            "1 + 1",
            "1 # trailing comment",
            r#""x""#,
            r#"{ b = 1; a = [ true null "x" ]; }"#,
            r#"builtins.toJSON { a = "x"; }"#,
        ] {
            let output = Command::new(&oracle)
                .args(["--eval", "--strict", "--json", "--expr", source])
                .output()?;
            assert!(
                output.status.success(),
                "C++ Nix oracle unexpectedly rejected {source:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let expected = String::from_utf8(output.stdout)?.trim().to_string();
            assert_eq!(native.eval_expr(source)?, expected, "{source}");
        }

        Ok(())
    }

    #[test]
    fn native_expression_eval_reports_semantic_errors() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("1 + true")
            .expect_err("type errors are native evaluation errors");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("type error")
        ));
        Ok(())
    }

    #[test]
    fn native_expression_eval_rejects_cli_sensitive_builtins() -> Result<()> {
        let native = NixNative::new(0)?;

        for source in [
            r#"builtins.getEnv "HOME""#,
            "builtins.nixPath",
            "builtins.builtins",
            "builtins ? currentSystem",
            "builtins.attrNames builtins",
            "builtins.fetchMercurial",
            "<nixpkgs>",
            r#"derivation { name = "x"; system = "x86_64-linux"; builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder"; }"#,
            r#"builtins.derivation { name = "x"; system = "x86_64-linux"; builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder"; }"#,
        ] {
            let err = native
                .eval_expr(source)
                .expect_err("CLI-sensitive expressions must fall back");
            assert!(
                matches!(
                    err.downcast_ref::<NativeEvalError>(),
                    Some(NativeEvalError::Unsupported { span: Some(_), .. })
                ),
                "{source}"
            );
        }

        Ok(())
    }

    #[test]
    fn native_expression_eval_reports_flakes_as_the_fallback_feature() -> Result<()> {
        let native = NixNative::new(0)?;

        for source in [
            r#"builtins.getFlake "github:NixOS/nixpkgs/0000000000000000000000000000000000000000""#,
            "builtins.getFlake or null",
        ] {
            let err = native
                .eval_expr(source)
                .expect_err("flake expressions must fall back");
            assert!(
                matches!(
                    err.downcast_ref::<NativeEvalError>(),
                    Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                        if feature == "flakes"
                ),
                "{source}: {err:?}"
            );
        }

        Ok(())
    }

    #[test]
    fn native_expression_eval_supports_pure_flake_ref_helpers() -> Result<()> {
        let native = NixNative::new(0)?;

        assert_eq!(
            native.eval_expr(r#"builtins.parseFlakeRef "github:NixOS/nixpkgs/23.05?dir=lib""#)?,
            r#"{"dir":"lib","owner":"NixOS","ref":"23.05","repo":"nixpkgs","type":"github"}"#
        );
        assert_eq!(
            native
                .eval_expr(r#"let parse = builtins.parseFlakeRef; in parse "nixpkgs/unstable""#)?,
            r#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#
        );
        assert_eq!(
            native.eval_expr(
                r#"let b = { inherit (builtins) parseFlakeRef; }; in b.parseFlakeRef "nixpkgs/unstable""#
            )?,
            r#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#
        );
        assert_eq!(
            native.eval_expr(
                r#"let render = builtins.flakeRefToString; in render {
                    dir = "lib";
                    owner = "NixOS";
                    ref = "23.05";
                    repo = "nixpkgs";
                    type = "github";
                }"#
            )?,
            r#""github:NixOS/nixpkgs/23.05?dir=lib""#
        );
        assert_eq!(
            native.eval_expr(
                r#"let b = { inherit (builtins) flakeRefToString; }; in b.flakeRefToString {
                    type = "indirect";
                    id = "nixpkgs";
                }"#
            )?,
            r#""flake:nixpkgs""#
        );

        Ok(())
    }

    #[test]
    fn native_expression_eval_uses_configured_current_system() -> Result<()> {
        let native = NixNative::with_options(
            0,
            TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())?,
        )?;

        assert_eq!(
            native.eval_expr("builtins.currentSystem")?,
            "\"aos-test-target\""
        );
        assert_eq!(
            native.eval_expr(r#"builtins.currentSystem or "fallback""#)?,
            "\"aos-test-target\""
        );
        Ok(())
    }

    #[test]
    fn configured_native_expression_eval_still_rejects_reified_builtins_inventory() -> Result<()> {
        let native = NixNative::with_options(
            0,
            TreeWalkOptions::with_current_system(b"aos-test-target".to_vec())?,
        )?;

        let err = native
            .eval_expr("builtins.attrNames builtins")
            .expect_err("reified builtins inventory should still fall back");
        assert!(
            matches!(
                err.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { span: Some(_), .. })
            ),
            "{err:?}"
        );
        Ok(())
    }

    #[test]
    fn native_expression_eval_keeps_frontend_gaps_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("let { body = 1; }")
            .expect_err("frontend gaps should fall back to the CLI");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, .. })
                if feature.contains("native expression parse failure")
        ));
        Ok(())
    }

    #[test]
    fn native_expression_eval_handles_functor_application() -> Result<()> {
        let native = NixNative::new(0)?;
        let json = native.eval_expr("({ __functor = self: x: x + 1; } 1)")?;

        assert_eq!(json, "2");
        Ok(())
    }

    #[test]
    fn native_expression_eval_keeps_non_functor_attrset_application_fallback_eligible() -> Result<()>
    {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("({} 1)")
            .expect_err("non-functor attrset application should fall back to the CLI");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("type error")
        ));
        Ok(())
    }

    #[test]
    fn native_expression_eval_keeps_missing_features_fallback_eligible() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr(r#"builtins.import "/tmp/aos-nix-native-missing-import.nix""#)
            .expect_err("unsupported features are still reported as unsupported");

        assert!(matches!(
            err.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("effectful expression evaluation")
                    || feature.contains("CLI-sensitive builtin evaluation")
                    || feature.contains("unsupported tree-walk primop")
        ));
        assert_eq!(native.name(), "aos-nix");
        Ok(())
    }

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
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
