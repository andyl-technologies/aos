//! Frontend- and tree-walk-error translation into [`NativeEvalError`].
//!
//! These helpers map parser, scope-resolution, lowering, and tree-walk
//! failures into the conservative native-evaluator error surface, deciding
//! which gaps stay fallback-eligible ([`NativeEvalError::Unsupported`]) versus
//! which are reported as genuine semantic failures ([`NativeEvalError::EvalError`]).

use super::*;

use crate::compile::{IrError, ScopeError};
use crate::diagnostic::{
    EvalDiagnostic, EvalTraceStyle, IrDiagnostic, ParseDiagnostic, ScopeDiagnostic,
    append_eval_trace_report, render_fancy_report,
};
use crate::syntax::{ParseError, ParseErrorKind};

#[derive(Clone, Copy)]
pub(super) struct NativeDiagnosticSource<'a> {
    name: &'a str,
    source: &'a str,
    source_map: Option<WrappedSourceMap>,
}

impl<'a> NativeDiagnosticSource<'a> {
    pub(super) const fn new(
        name: &'a str,
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
        | ParseCacheError::InvalidFactSidecarUpdate { .. }
        | ParseCacheError::DecodeArtifactBundle { .. }
        | ParseCacheError::DecodeMeta { .. }
        | ParseCacheError::Simplify { .. }
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
    let kind = parse_error_kind_for_source(error.kind(), source.source_map)?;
    if !span_fits_source(span, source.source) {
        return None;
    }

    let diagnostic = ParseDiagnostic::new(source.name, source.source, ParseError::new(kind, span));
    render_fancy_report(&diagnostic).ok()
}

fn parse_error_kind_for_source(
    kind: &ParseErrorKind,
    source_map: Option<WrappedSourceMap>,
) -> Option<ParseErrorKind> {
    match (kind, source_map) {
        (ParseErrorKind::DuplicateAttribute { first, second }, Some(source_map)) => {
            Some(ParseErrorKind::DuplicateAttribute {
                first: wrapped_source_span(*first, source_map)?,
                second: wrapped_source_span(*second, source_map)?,
            })
        }
        _ => Some(kind.clone()),
    }
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

pub(super) fn native_eval_error_with_trace(
    error: TreeWalkError,
    source_map: Option<WrappedSourceMap>,
    trace_style: EvalTraceStyle,
) -> NativeEvalError {
    native_eval_error_impl(error, source_map, None, trace_style)
}

pub(super) fn native_eval_error_with_source_trace(
    error: TreeWalkError,
    source: NativeDiagnosticSource<'_>,
    trace_style: EvalTraceStyle,
) -> NativeEvalError {
    native_eval_error_impl(error, source.source_map, Some(source), trace_style)
}

fn native_eval_error_impl(
    error: TreeWalkError,
    source_map: Option<WrappedSourceMap>,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    trace_style: EvalTraceStyle,
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
        message: native_eval_error_message(&error, diagnostic_source, trace_style),
    }
}

fn native_eval_error_message(
    error: &TreeWalkError,
    diagnostic_source: Option<NativeDiagnosticSource<'_>>,
    trace_style: EvalTraceStyle,
) -> String {
    if error.source().is_some() {
        return rendered_embedded_eval_diagnostic(error, trace_style)
            .unwrap_or_else(|| append_eval_trace_report(error.to_string(), error, trace_style));
    }
    diagnostic_source
        .and_then(|source| rendered_eval_diagnostic(error, source, trace_style))
        .unwrap_or_else(|| append_eval_trace_report(error.to_string(), error, trace_style))
}

fn rendered_embedded_eval_diagnostic(
    error: &TreeWalkError,
    trace_style: EvalTraceStyle,
) -> Option<String> {
    let source = error.source()?;
    let source_text = std::str::from_utf8(source.bytes()).ok()?;
    if !span_fits_source(error.span(), source_text) {
        return None;
    }
    if !error
        .labels()
        .iter()
        .all(|label| span_fits_source(label.span(), source_text))
    {
        return None;
    }
    if !error
        .contexts()
        .iter()
        .filter(|context| context_matches_embedded_source(context, source))
        .all(|context| span_fits_source(context.span(), source_text))
    {
        return None;
    }

    let name = String::from_utf8_lossy(source.name());
    let diagnostic = EvalDiagnostic::new(name.as_ref(), source_text, error.clone());
    render_fancy_report(&diagnostic)
        .ok()
        .map(|report| append_eval_trace_report(report, error, trace_style))
}

fn context_matches_embedded_source(
    context: &crate::eval::tree_walk::EvalErrorContext,
    source: &crate::eval::EvalErrorSource,
) -> bool {
    match context.source() {
        Some(context_source) => context_source == source,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::IrId;
    use crate::eval::tree_walk::EvalErrorContext;
    use crate::eval::{EvalErrorSource, TreeWalkError, TreeWalkErrorKind};
    use crate::syntax::Span;
    use crate::value::ValueTag;

    #[test]
    fn embedded_eval_diagnostic_filters_context_labels_from_other_sources() {
        let child_source_text =
            "1 + true\n# child-context-line\n\n\n\n# root-span-sentinel should not be labelled\n";
        let child_source =
            EvalErrorSource::new(b"child.nix".to_vec(), child_source_text.as_bytes().to_vec());
        let root_source = EvalErrorSource::new(
            b"root.nix".to_vec(),
            br#"builtins.addErrorContext "root context" (import ./child.nix)"#.to_vec(),
        );
        let child_context_start = child_source_text
            .find("child-context-line")
            .expect("child context sentinel should be present");
        let root_context_start = child_source_text
            .find("root-span-sentinel")
            .expect("root context sentinel should be present");
        let error = TreeWalkError::new(
            TreeWalkErrorKind::Type {
                id: IrId::new(1),
                expected: "number",
                actual: ValueTag::Bool,
            },
            Span { start: 4, end: 8 },
        )
        .with_contexts(vec![
            EvalErrorContext::new(b"root context".to_vec())
                .with_span(Span {
                    start: root_context_start as u32,
                    end: (root_context_start + "root-span-sentinel".len()) as u32,
                })
                .with_source(root_source),
            EvalErrorContext::new(b"sourceless root context".to_vec()).with_span(Span {
                start: root_context_start as u32,
                end: (root_context_start + "root-span-sentinel".len()) as u32,
            }),
            EvalErrorContext::new(b"child context".to_vec())
                .with_span(Span {
                    start: child_context_start as u32,
                    end: (child_context_start + "child-context-line".len()) as u32,
                })
                .with_source(child_source.clone()),
        ])
        .with_source(child_source);

        let report = rendered_embedded_eval_diagnostic(&error, EvalTraceStyle::Full)
            .expect("embedded diagnostic should render with mixed-source contexts");

        assert!(
            report.contains("while evaluating: root context"),
            "{report}"
        );
        assert!(
            report.contains("while evaluating: child context"),
            "{report}"
        );
        assert!(report.contains("child-context-line"), "{report}");
        assert!(!report.contains("root-span-sentinel"), "{report}");
    }

    #[test]
    fn native_eval_error_summarizes_and_expands_logical_traces() {
        let source_text = "a\nb\nc\nd\n";
        let source = EvalErrorSource::new(b"expr.nix".to_vec(), source_text.as_bytes().to_vec());
        let error = TreeWalkError::new(
            TreeWalkErrorKind::Thrown {
                id: IrId::new(1),
                message: b"boom".to_vec(),
            },
            Span::new(0, 1),
        )
        .with_contexts(vec![
            EvalErrorContext::new(b"one".to_vec())
                .with_span(Span::new(0, 1))
                .with_source(source.clone()),
            EvalErrorContext::new(b"two".to_vec())
                .with_span(Span::new(2, 3))
                .with_source(source.clone()),
            EvalErrorContext::new(b"three".to_vec())
                .with_span(Span::new(4, 5))
                .with_source(source.clone()),
            EvalErrorContext::new(b"four".to_vec())
                .with_span(Span::new(6, 7))
                .with_source(source.clone()),
        ])
        .with_source(source);
        let diagnostic_source = NativeDiagnosticSource::new("expr.nix", source_text, None);

        let summary = native_eval_error_with_source_trace(
            error.clone(),
            diagnostic_source,
            EvalTraceStyle::Summary,
        );
        let NativeEvalError::EvalError { message: summary } = summary else {
            panic!("summary trace should be an eval error");
        };
        assert!(
            summary.contains("while evaluating: one at expr.nix:1:1"),
            "{summary}"
        );
        assert!(summary.contains("1 more frame hidden"), "{summary}");
        assert!(
            !summary.contains("while evaluating: four at expr.nix:4:1"),
            "{summary}"
        );

        let full =
            native_eval_error_with_source_trace(error, diagnostic_source, EvalTraceStyle::Full);
        let NativeEvalError::EvalError { message: full } = full else {
            panic!("full trace should be an eval error");
        };
        assert!(
            full.contains("while evaluating: four at expr.nix:4:1"),
            "{full}"
        );
        assert!(!full.contains("hidden"), "{full}");
    }
}

fn rendered_eval_diagnostic(
    error: &TreeWalkError,
    source: NativeDiagnosticSource<'_>,
    trace_style: EvalTraceStyle,
) -> Option<String> {
    let span = match source.source_map {
        Some(source_map) => wrapped_source_span(error.span(), source_map)?,
        None => error.span(),
    };
    if !span_fits_source(span, source.source) {
        return None;
    }

    let error = eval_error_for_source(error, span, source.source_map)?;
    if !error
        .labels()
        .iter()
        .all(|label| span_fits_source(label.span(), source.source))
    {
        return None;
    }
    if !error
        .contexts()
        .iter()
        .all(|context| span_fits_source(context.span(), source.source))
    {
        return None;
    }

    let trace_source = crate::eval::EvalErrorSource::new(
        source.name.as_bytes().to_vec(),
        source.source.as_bytes().to_vec(),
    );
    let contexts = error
        .contexts()
        .iter()
        .map(|context| match context.source() {
            Some(_) => context.clone(),
            None => context.clone().with_source(trace_source.clone()),
        })
        .collect();
    let error = error.with_contexts(contexts).with_source(trace_source);
    let diagnostic = EvalDiagnostic::new(source.name, source.source, error);
    render_fancy_report(&diagnostic)
        .ok()
        .map(|report| append_eval_trace_report(report, diagnostic.error(), trace_style))
}

fn eval_error_for_source(
    error: &TreeWalkError,
    span: Span,
    source_map: Option<WrappedSourceMap>,
) -> Option<TreeWalkError> {
    let error = error.clone().with_span(span);
    let Some(source_map) = source_map else {
        return Some(error);
    };
    let labels = error
        .labels()
        .iter()
        .map(|label| {
            Some(EvalErrorLabel {
                span: wrapped_source_span(label.span(), source_map)?,
                label: label.label(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let contexts = error
        .contexts()
        .iter()
        .map(|context| {
            Some(
                context
                    .clone()
                    .with_span(wrapped_source_span(context.span(), source_map)?),
            )
        })
        .collect::<Option<Vec<_>>>()?;
    Some(error.with_labels(labels).with_contexts(contexts))
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
        | TreeWalkErrorKind::ImportFromDerivation { .. }
        // §2.3 hard-fail -> fallback-eligible (readiness ruling, disposition table
        // in aos-nix-native-default-on-readiness.md). An unimplemented internal
        // dialect op is a native gap, never a real error; the per-argument
        // fetch/source/flake attr rejections name a valid Nix attr C++ accepts
        // (transparent C++ retry beats a hard stop; these are also preflight-shadowed
        // today, so this is defense-in-depth). Regex/JSON/TOML deliberately NOT here.
        | TreeWalkErrorKind::UnsupportedDialectOp { .. }
        | TreeWalkErrorKind::UnsupportedSourcePathAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchUrlAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchGitAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchMercurialAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchTarballAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchTreeAttr { .. }
        | TreeWalkErrorKind::UnsupportedFlakeRefAttr { .. } => Some(kind.to_string()),
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
