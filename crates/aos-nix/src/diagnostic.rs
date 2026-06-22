//! Source-backed diagnostic reports for parser and evaluator errors.
//!
//! This module is the miette presentation layer for RFC-0007 native-evaluator
//! errors. It preserves the existing typed error enums as the semantic
//! classification surface and adds source names, source bytes, labels, codes,
//! severity, and help text only when formatting a user-facing report.

use std::{error::Error, fmt, ops::Range};

use miette::{Diagnostic, GraphicalReportHandler, LabeledSpan, NamedSource, Severity, SourceCode};

use crate::{
    compile::{IrError, IrErrorKind, ScopeError, ScopeErrorKind},
    eval::{TreeWalkError, TreeWalkErrorKind},
    syntax::{LexError, LexErrorKind, ParseError, ParseErrorKind, Span},
};

const DIAGNOSTIC_URL: &str = "https://github.com/andyl-technologies/aos/blob/main/docs/rfcs/0007-nix-evaluator/24-observability-and-diagnostics.md";

/// A source-backed parser diagnostic.
pub type ParseDiagnostic = SourceDiagnostic<ParseError>;

/// A source-backed lexer diagnostic.
pub type LexDiagnostic = SourceDiagnostic<LexError>;

/// A source-backed tree-walk evaluator diagnostic.
pub type EvalDiagnostic = SourceDiagnostic<TreeWalkError>;

/// A source-backed scope-resolution diagnostic.
pub type ScopeDiagnostic = SourceDiagnostic<ScopeError>;

/// A source-backed IR-lowering diagnostic.
pub type IrDiagnostic = SourceDiagnostic<IrError>;

/// A typed native error paired with the source text that produced it.
#[derive(Clone, Debug)]
pub struct SourceDiagnostic<E> {
    error: E,
    source: NamedSource<String>,
}

impl<E> SourceDiagnostic<E> {
    /// Creates a diagnostic from a source name, source text, and typed error.
    pub fn new(name: impl AsRef<str>, source: impl Into<String>, error: E) -> Self {
        Self {
            error,
            source: NamedSource::new(name, source.into()),
        }
    }

    /// Returns the original typed error.
    pub const fn error(&self) -> &E {
        &self.error
    }
}

impl<E: fmt::Display> fmt::Display for SourceDiagnostic<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl<E> Error for SourceDiagnostic<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

impl Diagnostic for ParseDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(parse_error_code(self.error.kind())))
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        parse_error_help(self.error.kind()).map(|help| Box::new(help) as Box<dyn fmt::Display>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(DIAGNOSTIC_URL))
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.source)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(parse_error_labels(self.error.kind(), self.error.span()))
    }
}

impl Diagnostic for LexDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(lex_error_code(self.error.kind())))
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        lex_error_help(self.error.kind()).map(|help| Box::new(help) as Box<dyn fmt::Display>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(DIAGNOSTIC_URL))
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.source)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(label_for_span(
            self.error.span(),
            "lexer error",
        ))))
    }
}

impl Diagnostic for EvalDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(eval_error_code(&self.error.kind())))
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        eval_error_help(&self.error.kind()).map(|help| Box::new(help) as Box<dyn fmt::Display>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(DIAGNOSTIC_URL))
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.source)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(label_for_span(
            self.error.span(),
            "evaluation error",
        ))))
    }
}

impl Diagnostic for ScopeDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(scope_error_code(self.error.kind())))
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        scope_error_help(self.error.kind()).map(|help| Box::new(help) as Box<dyn fmt::Display>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(DIAGNOSTIC_URL))
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.source)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(label_for_span(
            self.error.span(),
            "scope-resolution error",
        ))))
    }
}

impl Diagnostic for IrDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(ir_error_code(self.error.kind())))
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        ir_error_help(self.error.kind()).map(|help| Box::new(help) as Box<dyn fmt::Display>)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(DIAGNOSTIC_URL))
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.source)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(label_for_span(
            self.error.span(),
            "IR-lowering error",
        ))))
    }
}

/// Renders any miette diagnostic through the built-in fancy renderer.
///
/// Callers should use this function as the report-printing seam instead of
/// depending on a concrete renderer. A future ariadne-backed renderer can then
/// replace this implementation without changing the typed error surface.
///
/// # Errors
///
/// Returns [`fmt::Error`] if writing the formatted diagnostic into the output
/// string fails.
pub fn render_fancy_report(diagnostic: &dyn Diagnostic) -> Result<String, fmt::Error> {
    let mut out = String::new();
    GraphicalReportHandler::new().render_report(&mut out, diagnostic)?;
    Ok(out)
}

fn label_for_span(span: Span, label: &'static str) -> LabeledSpan {
    let range = span_range(span);
    LabeledSpan::new_with_span(Some(label.to_owned()), range)
}

fn parse_error_labels(
    kind: &ParseErrorKind,
    primary_span: Span,
) -> Box<dyn Iterator<Item = LabeledSpan>> {
    match kind {
        ParseErrorKind::DuplicateAttribute { first, second } => Box::new(
            [
                label_for_span(*first, "first definition"),
                label_for_span(*second, "duplicate definition"),
            ]
            .into_iter(),
        ),
        _ => Box::new(std::iter::once(label_for_span(primary_span, "parse error"))),
    }
}

fn span_range(span: Span) -> Range<usize> {
    let start = span.start as usize;
    let end = span.end.max(span.start.saturating_add(1)) as usize;
    start..end
}

fn lex_error_code(kind: &LexErrorKind) -> &'static str {
    match kind {
        LexErrorKind::UnexpectedByte(_) => "aos_nix::lex::unexpected_byte",
        LexErrorKind::UnterminatedBlockComment => "aos_nix::lex::unterminated_block_comment",
        LexErrorKind::UnterminatedString => "aos_nix::lex::unterminated_string",
        LexErrorKind::UnterminatedInterpolation => "aos_nix::lex::unterminated_interpolation",
        LexErrorKind::UnterminatedSearchPath => "aos_nix::lex::unterminated_search_path",
        LexErrorKind::OffsetOverflow => "aos_nix::lex::offset_overflow",
    }
}

fn lex_error_help(kind: &LexErrorKind) -> Option<&'static str> {
    match kind {
        LexErrorKind::UnexpectedByte(_) => Some("Remove or quote the unexpected byte."),
        LexErrorKind::UnterminatedBlockComment => Some("Close the block comment with `*/`."),
        LexErrorKind::UnterminatedString => Some("Close the string literal."),
        LexErrorKind::UnterminatedInterpolation => {
            Some("Close the interpolation with a matching `}`.")
        }
        LexErrorKind::UnterminatedSearchPath => Some("Close the search path literal with `>`."),
        LexErrorKind::OffsetOverflow => None,
    }
}

fn parse_error_code(kind: &ParseErrorKind) -> &'static str {
    match kind {
        ParseErrorKind::Lex(kind) => lex_error_code(kind),
        ParseErrorKind::Ast(_) => "aos_nix::parse::ast",
        ParseErrorKind::UnexpectedToken { .. } => "aos_nix::parse::unexpected_token",
        ParseErrorKind::InvalidLiteral { .. } => "aos_nix::parse::invalid_literal",
        ParseErrorKind::InvalidUtf8Literal => "aos_nix::parse::invalid_utf8_literal",
        ParseErrorKind::InvalidSpan { .. } => "aos_nix::parse::invalid_span",
        ParseErrorKind::InvalidNodeId(_) => "aos_nix::parse::invalid_node_id",
        ParseErrorKind::NonAssociativeOperator { .. } => "aos_nix::parse::non_associative_operator",
        ParseErrorKind::InvalidBindingPath => "aos_nix::parse::invalid_binding_path",
        ParseErrorKind::PathTrailingSlash => "aos_nix::parse::path_trailing_slash",
        ParseErrorKind::DuplicateAttribute { .. } => "aos_nix::parse::duplicate_attribute",
        ParseErrorKind::InvalidFormalPattern { .. } => "aos_nix::parse::invalid_formal_pattern",
    }
}

fn parse_error_help(kind: &ParseErrorKind) -> Option<&'static str> {
    match kind {
        ParseErrorKind::Lex(kind) => lex_error_help(kind),
        ParseErrorKind::UnexpectedToken { .. } => Some("Check the surrounding Nix syntax."),
        ParseErrorKind::InvalidLiteral { .. } => Some("Use a literal spelling accepted by Nix."),
        ParseErrorKind::NonAssociativeOperator { .. } => {
            Some("Add parentheses to make the intended grouping explicit.")
        }
        ParseErrorKind::PathTrailingSlash => Some("Remove the trailing slash or quote the path."),
        ParseErrorKind::DuplicateAttribute { .. } => {
            Some("Keep one binding or make the path mergeable.")
        }
        ParseErrorKind::InvalidFormalPattern { .. } => Some("Use a valid Nix function pattern."),
        ParseErrorKind::Ast(_)
        | ParseErrorKind::InvalidUtf8Literal
        | ParseErrorKind::InvalidSpan { .. }
        | ParseErrorKind::InvalidNodeId(_)
        | ParseErrorKind::InvalidBindingPath => None,
    }
}

fn scope_error_code(kind: &ScopeErrorKind) -> &'static str {
    match kind {
        ScopeErrorKind::Ast(_) => "aos_nix::resolve::ast",
        ScopeErrorKind::InvalidNodeId(_) => "aos_nix::resolve::invalid_node_id",
        ScopeErrorKind::InvalidNodeShape { .. } => "aos_nix::resolve::invalid_node_shape",
        ScopeErrorKind::TooManyFrames => "aos_nix::resolve::too_many_frames",
        ScopeErrorKind::TooManyWithChains => "aos_nix::resolve::too_many_with_chains",
        ScopeErrorKind::TooManyInheritGroups => "aos_nix::resolve::too_many_inherit_groups",
        ScopeErrorKind::TooManySlots => "aos_nix::resolve::too_many_slots",
        ScopeErrorKind::TooManyUpvalues => "aos_nix::resolve::too_many_upvalues",
        ScopeErrorKind::UndefinedSymbol(_) => "aos_nix::resolve::undefined_symbol",
        ScopeErrorKind::DynamicLetBinding => "aos_nix::resolve::dynamic_let_binding",
        ScopeErrorKind::DynamicInheritTarget => "aos_nix::resolve::dynamic_inherit_target",
    }
}

fn scope_error_help(kind: &ScopeErrorKind) -> Option<&'static str> {
    match kind {
        ScopeErrorKind::UndefinedSymbol(_) => {
            Some("Define the name in scope or use a supported builtin.")
        }
        ScopeErrorKind::DynamicLetBinding => Some("Use a static attribute name for let bindings."),
        ScopeErrorKind::DynamicInheritTarget => {
            Some("Use a static attribute name for inherit targets.")
        }
        ScopeErrorKind::Ast(_)
        | ScopeErrorKind::InvalidNodeId(_)
        | ScopeErrorKind::InvalidNodeShape { .. }
        | ScopeErrorKind::TooManyFrames
        | ScopeErrorKind::TooManyWithChains
        | ScopeErrorKind::TooManyInheritGroups
        | ScopeErrorKind::TooManySlots
        | ScopeErrorKind::TooManyUpvalues => None,
    }
}

fn ir_error_code(kind: &IrErrorKind) -> &'static str {
    match kind {
        IrErrorKind::InvalidNodeId(_) => "aos_nix::lower::invalid_node_id",
        IrErrorKind::InvalidChildSlice => "aos_nix::lower::invalid_child_slice",
        IrErrorKind::InvalidWithChain { .. } => "aos_nix::lower::invalid_with_chain",
        IrErrorKind::UnloweredWithScope { .. } => "aos_nix::lower::unlowered_with_scope",
        IrErrorKind::InvalidNodeShape { .. } => "aos_nix::lower::invalid_node_shape",
        IrErrorKind::TooManyNodes => "aos_nix::lower::too_many_nodes",
        IrErrorKind::TooManyChildren => "aos_nix::lower::too_many_children",
        IrErrorKind::TooManySideTableEntries => "aos_nix::lower::too_many_side_table_entries",
        IrErrorKind::TooManyInlineCacheSites => "aos_nix::lower::too_many_inline_cache_sites",
        IrErrorKind::InvalidBindingKey => "aos_nix::lower::invalid_binding_key",
        IrErrorKind::InvalidInheritSource => "aos_nix::lower::invalid_inherit_source",
        IrErrorKind::Ast(_) => "aos_nix::lower::ast",
    }
}

fn ir_error_help(kind: &IrErrorKind) -> Option<&'static str> {
    match kind {
        IrErrorKind::InvalidBindingKey => Some("Use a static single-segment binding key."),
        IrErrorKind::InvalidInheritSource => Some("Use a valid inherit source expression."),
        IrErrorKind::InvalidNodeId(_)
        | IrErrorKind::InvalidChildSlice
        | IrErrorKind::InvalidWithChain { .. }
        | IrErrorKind::UnloweredWithScope { .. }
        | IrErrorKind::InvalidNodeShape { .. }
        | IrErrorKind::TooManyNodes
        | IrErrorKind::TooManyChildren
        | IrErrorKind::TooManySideTableEntries
        | IrErrorKind::TooManyInlineCacheSites
        | IrErrorKind::Ast(_) => None,
    }
}

fn eval_error_code(kind: &TreeWalkErrorKind) -> &'static str {
    match kind {
        TreeWalkErrorKind::Type { .. } => "aos_nix::eval::type",
        TreeWalkErrorKind::Thrown { .. } => "aos_nix::eval::throw",
        TreeWalkErrorKind::AssertionFailed { .. } => "aos_nix::eval::assertion_failed",
        TreeWalkErrorKind::DivisionByZero { .. } => "aos_nix::eval::division_by_zero",
        TreeWalkErrorKind::PathAccessDenied { .. } => "aos_nix::eval::path_access_denied",
        TreeWalkErrorKind::FetchUrlAccessDenied { .. } => "aos_nix::eval::fetchurl_access_denied",
        TreeWalkErrorKind::FetchGitAccessDenied { .. } => "aos_nix::eval::fetchgit_access_denied",
        TreeWalkErrorKind::FetchTarballAccessDenied { .. } => {
            "aos_nix::eval::fetchtarball_access_denied"
        }
        TreeWalkErrorKind::FetchTreeAccessDenied { .. } => "aos_nix::eval::fetchtree_access_denied",
        TreeWalkErrorKind::StorePathPureEval { .. } => "aos_nix::eval::store_path_pure_eval",
        TreeWalkErrorKind::FetchUrlHashRequired { .. } => "aos_nix::eval::fetchurl_hash_required",
        TreeWalkErrorKind::FetchGitRevRequired { .. } => "aos_nix::eval::fetchgit_rev_required",
        TreeWalkErrorKind::FetchMercurialRevRequired { .. } => {
            "aos_nix::eval::fetchmercurial_rev_required"
        }
        TreeWalkErrorKind::FetchTarballHashRequired { .. } => {
            "aos_nix::eval::fetchtarball_hash_required"
        }
        TreeWalkErrorKind::FetchTreeLockedInputRequired { .. } => {
            "aos_nix::eval::fetchtree_locked_input_required"
        }
        TreeWalkErrorKind::ImportFromDerivation { .. }
        | TreeWalkErrorKind::UnsupportedImportFromDerivation { .. } => {
            "aos_nix::eval::import_from_derivation"
        }
        TreeWalkErrorKind::UnsupportedPrimOp { .. }
        | TreeWalkErrorKind::UnsupportedBuiltinAttr { .. }
        | TreeWalkErrorKind::UnsupportedFetchTreeFeature { .. }
        | TreeWalkErrorKind::UnsupportedEqualityType { .. }
        | TreeWalkErrorKind::UnsupportedLambdaPattern { .. }
        | TreeWalkErrorKind::UnsupportedLetBindingKey { .. }
        | TreeWalkErrorKind::UnsupportedSourcePathType { .. } => "aos_nix::eval::unsupported",
        _ => "aos_nix::eval::internal",
    }
}

fn eval_error_help(kind: &TreeWalkErrorKind) -> Option<&'static str> {
    match kind {
        TreeWalkErrorKind::Type { .. } => Some("Use a value with the type expected here."),
        TreeWalkErrorKind::DivisionByZero { .. } => Some("Avoid dividing by zero."),
        TreeWalkErrorKind::PathAccessDenied { .. }
        | TreeWalkErrorKind::FetchUrlAccessDenied { .. }
        | TreeWalkErrorKind::FetchGitAccessDenied { .. }
        | TreeWalkErrorKind::FetchTarballAccessDenied { .. }
        | TreeWalkErrorKind::FetchTreeAccessDenied { .. } => Some(
            "Add the path or URI to the evaluator allow list, or disable restricted evaluation.",
        ),
        TreeWalkErrorKind::StorePathPureEval { .. } => {
            Some("Do not call `builtins.storePath` in pure evaluation mode.")
        }
        TreeWalkErrorKind::FetchUrlHashRequired { .. }
        | TreeWalkErrorKind::FetchTarballHashRequired { .. } => {
            Some("Add a fixed-output hash to make this fetch pure.")
        }
        TreeWalkErrorKind::FetchGitRevRequired { .. }
        | TreeWalkErrorKind::FetchMercurialRevRequired { .. } => {
            Some("Pin the fetch to an immutable revision.")
        }
        TreeWalkErrorKind::FetchTreeLockedInputRequired { .. } => {
            Some("Provide a locked fetchTree input with content hash metadata.")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compile::{IrError, IrErrorKind, lower, resolve},
        eval::eval_whnf_owned,
        syntax::{Lexer, parse_str},
    };

    #[test]
    fn parse_diagnostic_reports_code_label_and_source() {
        let source = "let = 1";
        let error = parse_str(source).expect_err("invalid syntax should fail");
        let diagnostic = ParseDiagnostic::new("expr.nix", source, error);

        assert!(diagnostic.source_code().is_some());
        assert_eq!(diagnostic.severity(), Some(Severity::Error));
        assert_eq!(
            diagnostic.code().map(|code| code.to_string()),
            Some("aos_nix::parse::unexpected_token".to_string())
        );
        assert!(diagnostic.url().is_some());

        let labels = diagnostic
            .labels()
            .expect("parse diagnostic has a label")
            .collect::<Vec<_>>();
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn duplicate_attr_parse_diagnostic_reports_both_spans() {
        assert_duplicate_attr_labels("{ a = 1; a = 2; }", "a = 1;", "a = 2;");
        assert_duplicate_attr_labels("{ a.b = 1; a.b = 2; }", "a.b = 1;", "a.b = 2;");
    }

    fn assert_duplicate_attr_labels(source: &str, first: &str, second: &str) {
        let error = parse_str(source).expect_err("duplicate attr path should fail");
        let diagnostic = ParseDiagnostic::new("expr.nix", source, error);

        assert_eq!(
            diagnostic.code().map(|code| code.to_string()),
            Some("aos_nix::parse::duplicate_attribute".to_string())
        );
        let labels = diagnostic
            .labels()
            .expect("duplicate attribute diagnostic has labels")
            .collect::<Vec<_>>();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].label(), Some("first definition"));
        assert_eq!(labels[0].offset(), source.find(first).unwrap());
        assert_eq!(labels[0].len(), first.len());
        assert_eq!(labels[1].label(), Some("duplicate definition"));
        assert_eq!(labels[1].offset(), source.find(second).unwrap());
        assert_eq!(labels[1].len(), second.len());
    }

    #[test]
    fn lexer_diagnostic_reports_specific_code() {
        let source = "~";
        let error = Lexer::new(source.as_bytes())
            .next_token()
            .expect_err("unexpected byte should fail lexing");
        let diagnostic = LexDiagnostic::new("expr.nix", source, error);

        assert_eq!(
            diagnostic.code().map(|code| code.to_string()),
            Some("aos_nix::lex::unexpected_byte".to_string())
        );
        assert!(diagnostic.help().is_some());
        assert!(diagnostic.url().is_some());
        assert!(diagnostic.source_code().is_some());
    }

    #[test]
    fn eval_diagnostic_keeps_error_class_in_code() {
        let source = "1 + \"x\"";
        let ir = lower(resolve(parse_str(source).unwrap()).unwrap()).unwrap();
        let error = eval_whnf_owned(&ir).expect_err("type mismatch should fail");
        assert!(matches!(error.kind(), TreeWalkErrorKind::Type { .. }));
        let typed_message = error.to_string();
        let diagnostic = EvalDiagnostic::new("expr.nix", source, error);

        assert!(matches!(
            diagnostic.error().kind(),
            TreeWalkErrorKind::Type { .. }
        ));
        assert_eq!(diagnostic.to_string(), typed_message);
        assert!(!diagnostic.to_string().contains("aos_nix::eval::type"));
        assert_eq!(
            diagnostic.code().map(|code| code.to_string()),
            Some("aos_nix::eval::type".to_string())
        );
        assert!(diagnostic.help().is_some());
        assert!(diagnostic.url().is_some());
        assert!(diagnostic.source_code().is_some());

        let report = render_fancy_report(&diagnostic).expect("diagnostic renders");
        assert!(report.contains("aos_nix::eval::type"), "{report}");
        assert!(
            report.contains("Use a value with the type expected here."),
            "{report}"
        );
    }

    #[test]
    fn scope_diagnostic_reports_resolver_code_and_source() {
        let source = "missing";
        let error = resolve(parse_str(source).unwrap()).expect_err("missing name should fail");
        let diagnostic = ScopeDiagnostic::new("expr.nix", source, error);

        assert_eq!(
            diagnostic.code().map(|code| code.to_string()),
            Some("aos_nix::resolve::undefined_symbol".to_string())
        );
        assert!(diagnostic.help().is_some());
        assert!(diagnostic.url().is_some());
        assert!(diagnostic.source_code().is_some());
    }

    #[test]
    fn ir_diagnostic_reports_lowering_code_and_source() {
        let source = "{ ${\"x\"} = 1; }";
        let error = IrError::new(IrErrorKind::InvalidBindingKey, Span::new(2, 8));
        let diagnostic = IrDiagnostic::new("expr.nix", source, error);

        assert_eq!(
            diagnostic.code().map(|code| code.to_string()),
            Some("aos_nix::lower::invalid_binding_key".to_string())
        );
        assert!(diagnostic.help().is_some());
        assert!(diagnostic.url().is_some());
        assert!(diagnostic.source_code().is_some());
    }

    #[test]
    fn fancy_renderer_uses_miette_report_handler() {
        let source = "let = 1";
        let error = parse_str(source).expect_err("invalid syntax should fail");
        let diagnostic = ParseDiagnostic::new("expr.nix", source, error);
        let report = render_fancy_report(&diagnostic).expect("diagnostic renders");

        assert!(report.contains("expr.nix"), "{report}");
        assert!(
            report.contains("aos_nix::parse::unexpected_token"),
            "{report}"
        );
    }
}
