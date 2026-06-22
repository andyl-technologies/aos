//! Frontend- and tree-walk-error translation into [`NativeEvalError`].
//!
//! These helpers map parser, scope-resolution, lowering, and tree-walk
//! failures into the conservative native-evaluator error surface, deciding
//! which gaps stay fallback-eligible ([`NativeEvalError::Unsupported`]) versus
//! which are reported as genuine semantic failures ([`NativeEvalError::EvalError`]).

use super::*;

use crate::compile::{IrError, ScopeError};
use crate::diagnostic::{
    EvalDiagnostic, IrDiagnostic, ParseDiagnostic, ScopeDiagnostic, render_fancy_report,
};
use crate::syntax::ParseError;

#[derive(Clone, Copy)]
pub(super) struct NativeDiagnosticSource<'a> {
    name: &'static str,
    source: &'a str,
    source_map: Option<WrappedSourceMap>,
}

impl<'a> NativeDiagnosticSource<'a> {
    pub(super) const fn new(
        name: &'static str,
        source: &'a str,
        source_map: Option<WrappedSourceMap>,
    ) -> Self {
        Self {
            name,
            source,
            source_map,
        }
    }
}

pub(super) fn parse_cache_frontend_error(
    error: ParseCacheError,
    source_map: Option<WrappedSourceMap>,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
) -> Option<NativeEvalError> {
    match error {
        ParseCacheError::Parse { source } => Some(unsupported_parse_error(
            source,
            source_map,
            diagnostic_source,
        )),
        ParseCacheError::Scope { source } => Some(unsupported_scope_error(
            source,
            source_map,
            diagnostic_source,
        )),
        ParseCacheError::LowerIr { source } => {
            Some(unsupported_ir_error(source, source_map, diagnostic_source))
        }
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

pub(super) fn unsupported_parse_error(
    error: ParseError,
    source_map: Option<WrappedSourceMap>,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
) -> NativeEvalError {
    let rendered = diagnostic_source.and_then(|source| rendered_parse_diagnostic(&error, source));
    unsupported_frontend_error(
        "parse",
        rendered.unwrap_or_else(|| error.to_string()),
        error.span(),
        source_map,
    )
}

pub(super) fn unsupported_scope_error(
    error: ScopeError,
    source_map: Option<WrappedSourceMap>,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
) -> NativeEvalError {
    let rendered = diagnostic_source.and_then(|source| rendered_scope_diagnostic(&error, source));
    unsupported_frontend_error(
        "resolve",
        rendered.unwrap_or_else(|| error.to_string()),
        error.span(),
        source_map,
    )
}

pub(super) fn unsupported_ir_error(
    error: IrError,
    source_map: Option<WrappedSourceMap>,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
) -> NativeEvalError {
    let rendered = diagnostic_source.and_then(|source| rendered_ir_diagnostic(&error, source));
    unsupported_frontend_error(
        "lower",
        rendered.unwrap_or_else(|| error.to_string()),
        error.span(),
        source_map,
    )
}

pub(super) fn unsupported_frontend_error(
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

fn rendered_parse_diagnostic(
    error: &ParseError,
    source: NativeDiagnosticSource<'_>,
) -> Option<String> {
    let span = match source.source_map {
        Some(source_map) => wrapped_source_span(error.span(), source_map)?,
        None => error.span(),
    };
    if !span_fits_source(span, source.source) {
        return None;
    }

    let diagnostic = ParseDiagnostic::new(
        source.name,
        source.source,
        ParseError::new(error.kind().clone(), span),
    );
    render_fancy_report(&diagnostic).ok()
}

fn rendered_scope_diagnostic(
    error: &ScopeError,
    source: NativeDiagnosticSource<'_>,
) -> Option<String> {
    let span = match source.source_map {
        Some(source_map) => wrapped_source_span(error.span(), source_map)?,
        None => error.span(),
    };
    if !span_fits_source(span, source.source) {
        return None;
    }

    let diagnostic = ScopeDiagnostic::new(
        source.name,
        source.source,
        ScopeError::new(error.kind().clone(), span),
    );
    render_fancy_report(&diagnostic).ok()
}

fn rendered_ir_diagnostic(error: &IrError, source: NativeDiagnosticSource<'_>) -> Option<String> {
    let span = match source.source_map {
        Some(source_map) => wrapped_source_span(error.span(), source_map)?,
        None => error.span(),
    };
    if !span_fits_source(span, source.source) {
        return None;
    }

    let diagnostic = IrDiagnostic::new(
        source.name,
        source.source,
        IrError::new(error.kind().clone(), span),
    );
    render_fancy_report(&diagnostic).ok()
}

pub(super) fn native_eval_error(
    error: TreeWalkError,
    source_map: Option<WrappedSourceMap>,
) -> NativeEvalError {
    native_eval_error_impl(error, source_map, None)
}

pub(super) fn native_eval_error_with_source(
    error: TreeWalkError,
    source: NativeDiagnosticSource<'_>,
) -> NativeEvalError {
    native_eval_error_impl(error, source.source_map, Some(source))
}

fn native_eval_error_impl(
    error: TreeWalkError,
    source_map: Option<WrappedSourceMap>,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
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
        message: native_eval_error_message(&error, diagnostic_source),
    }
}

fn native_eval_error_message(
    error: &TreeWalkError,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
) -> String {
    diagnostic_source
        .and_then(|source| rendered_eval_diagnostic(error, source))
        .unwrap_or_else(|| error.to_string())
}

fn rendered_eval_diagnostic(
    error: &TreeWalkError,
    source: NativeDiagnosticSource<'_>,
) -> Option<String> {
    let span = match source.source_map {
        Some(source_map) => wrapped_source_span(error.span(), source_map)?,
        None => error.span(),
    };
    if !span_fits_source(span, source.source) {
        return None;
    }

    let diagnostic = EvalDiagnostic::new(source.name, source.source, error.clone().with_span(span));
    render_fancy_report(&diagnostic).ok()
}

fn span_fits_source(span: Span, source: &str) -> bool {
    let start = span.start as usize;
    let end = span.end.max(span.start.saturating_add(1)) as usize;
    start < source.len() && end <= source.len()
}

fn tree_walk_unsupported_feature(kind: &TreeWalkErrorKind) -> Option<String> {
    match kind {
        TreeWalkErrorKind::UnsupportedLambdaPattern { .. }
        | TreeWalkErrorKind::UnsupportedLetBindingKey { .. }
        | TreeWalkErrorKind::UnsupportedSourcePathType { .. }
        | TreeWalkErrorKind::UnsupportedPrimOp { .. }
        | TreeWalkErrorKind::UnsupportedBuiltinAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchTreeFeature { .. }
        | TreeWalkErrorKind::UnsupportedImportFromDerivation { .. }
        | TreeWalkErrorKind::UnsupportedEqualityType { .. }
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

pub(super) fn unsupported_native_node(
    feature: &'static str,
    span: Span,
    expr_len: usize,
) -> NativeEvalError {
    let source_map = WrappedSourceMap {
        prefix_len: JSON_WRAPPER_PREFIX.len(),
        expr_len,
    };
    NativeEvalError::Unsupported {
        feature: feature.to_string(),
        span: source_span_from_wrapped(span, source_map),
    }
}

pub(super) fn source_span_from_wrapped(
    span: Span,
    source_map: WrappedSourceMap,
) -> Option<crate::error::SrcSpan> {
    wrapped_source_span(span, source_map).map(src_span)
}

fn wrapped_source_span(span: Span, source_map: WrappedSourceMap) -> Option<Span> {
    let prefix_len = u32::try_from(source_map.prefix_len).ok()?;
    let expr_len = u32::try_from(source_map.expr_len).ok()?;
    let expr_end = prefix_len.checked_add(expr_len)?;
    if span.start < prefix_len || span.end > expr_end {
        return None;
    }
    Some(Span::new(span.start - prefix_len, span.end - prefix_len))
}

const fn src_span(span: Span) -> crate::error::SrcSpan {
    crate::error::SrcSpan {
        start: span.start,
        end: span.end,
    }
}
