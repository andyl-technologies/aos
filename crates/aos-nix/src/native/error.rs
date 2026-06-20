//! Frontend- and tree-walk-error translation into [`NativeEvalError`].
//!
//! These helpers map parser, scope-resolution, lowering, and tree-walk
//! failures into the conservative native-evaluator error surface, deciding
//! which gaps stay fallback-eligible ([`NativeEvalError::Unsupported`]) versus
//! which are reported as genuine semantic failures ([`NativeEvalError::EvalError`]).

use super::*;

pub(super) fn parse_cache_frontend_error(
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

pub(super) fn native_eval_error(
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
