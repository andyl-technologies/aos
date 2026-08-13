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
    eval::{EvalErrorSource, TreeWalkError, TreeWalkErrorKind},
    syntax::{LexError, LexErrorKind, ParseError, ParseErrorKind, Span},
};

const DIAGNOSTIC_URL: &str = "https://github.com/andyl-technologies/aos/blob/main/docs/rfcs/0007-nix-evaluator/24-observability-and-diagnostics.md";
const SUMMARY_TRACE_FRAME_LIMIT: usize = 3;

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

/// Selects how much logical evaluation trace to render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalTraceStyle {
    /// Renders the default short trace.
    Summary,
    /// Renders every frame currently retained on the logical eval-context stack.
    Full,
}

/// One frame in an evaluation trace reconstructed from logical evaluator state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalTraceFrame {
    message: String,
    source_name: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    span: Span,
}

impl EvalTraceFrame {
    /// Returns the frame message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the source name associated with the frame, if known.
    pub fn source_name(&self) -> Option<&str> {
        self.source_name.as_deref()
    }

    /// Returns the one-based source line associated with the frame, if known.
    pub const fn line(&self) -> Option<usize> {
        self.line
    }

    /// Returns the one-based source column associated with the frame, if known.
    pub const fn column(&self) -> Option<usize> {
        self.column
    }

    /// Returns the byte span associated with the frame.
    pub const fn span(&self) -> Span {
        self.span
    }
}

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
        Some(eval_error_labels(&self.error))
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

/// Returns logical evaluation trace frames from outermost to innermost.
pub fn eval_trace_frames(error: &TreeWalkError) -> Vec<EvalTraceFrame> {
    error
        .contexts()
        .iter()
        .map(|context| {
            let (source_name, line, column) = context
                .source()
                .map(|source| {
                    let (line, column) = source_position(source, context.span().start);
                    (
                        Some(String::from_utf8_lossy(source.name()).into_owned()),
                        line,
                        column,
                    )
                })
                .unwrap_or((None, None, None));
            EvalTraceFrame {
                message: String::from_utf8_lossy(context.message()).into_owned(),
                source_name,
                line,
                column,
                span: context.span(),
            }
        })
        .collect()
}

/// Renders logical evaluation trace frames for a tree-walk error.
pub fn render_eval_trace(error: &TreeWalkError, style: EvalTraceStyle) -> Option<String> {
    let frames = eval_trace_frames(error);
    if frames.is_empty() {
        return None;
    }

    let mut out = String::from("Evaluation trace:\n");
    let visible = match style {
        EvalTraceStyle::Summary => frames.len().min(SUMMARY_TRACE_FRAME_LIMIT),
        EvalTraceStyle::Full => frames.len(),
    };

    for (index, frame) in frames.iter().take(visible).enumerate() {
        out.push_str("  ");
        out.push_str(&(index + 1).to_string());
        out.push_str(". while evaluating: ");
        out.push_str(frame.message());
        if let (Some(source_name), Some(line), Some(column)) =
            (frame.source_name(), frame.line(), frame.column())
        {
            out.push_str(" at ");
            out.push_str(source_name);
            out.push(':');
            out.push_str(&line.to_string());
            out.push(':');
            out.push_str(&column.to_string());
        }
        out.push('\n');
    }

    if matches!(style, EvalTraceStyle::Summary) && frames.len() > visible {
        let omitted = frames.len() - visible;
        out.push_str("  ... ");
        out.push_str(&omitted.to_string());
        out.push_str(" more frame");
        if omitted != 1 {
            out.push('s');
        }
        out.push_str(" hidden; enable full evaluation tracing for the full trace\n");
    }

    Some(out)
}

/// Appends a logical evaluation trace to an already-rendered diagnostic report.
pub fn append_eval_trace_report(
    mut report: String,
    error: &TreeWalkError,
    style: EvalTraceStyle,
) -> String {
    if let Some(trace) = render_eval_trace(error, style) {
        if !report.ends_with('\n') {
            report.push('\n');
        }
        report.push('\n');
        report.push_str(&trace);
    }
    report
}

fn source_position(source: &EvalErrorSource, offset: u32) -> (Option<usize>, Option<usize>) {
    let offset = offset as usize;
    let bytes = source.bytes();
    if offset > bytes.len() {
        return (None, None);
    }

    let mut line = 1usize;
    let mut column = 1usize;
    for byte in &bytes[..offset] {
        if *byte == b'\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }
    (Some(line), Some(column))
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

fn eval_error_labels(error: &TreeWalkError) -> Box<dyn Iterator<Item = LabeledSpan> + '_> {
    let mut labels = Vec::with_capacity(
        error
            .labels()
            .len()
            .max(1)
            .saturating_add(error.contexts().len()),
    );
    if error.labels().is_empty() {
        labels.push(label_for_span(error.span(), "evaluation error"));
    } else {
        labels.extend(
            error
                .labels()
                .iter()
                .map(|label| label_for_span(label.span(), label.label())),
        );
    }
    labels.extend(
        error
            .contexts()
            .iter()
            .filter(|context| context_matches_error_source(error.source(), context))
            .map(context_label),
    );
    Box::new(labels.into_iter())
}

fn context_matches_error_source(
    error_source: Option<&crate::eval::EvalErrorSource>,
    context: &crate::eval::tree_walk::EvalErrorContext,
) -> bool {
    match (error_source, context.source()) {
        (Some(error_source), Some(context_source)) => context_source == error_source,
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn context_label(context: &crate::eval::tree_walk::EvalErrorContext) -> LabeledSpan {
    let label = format!(
        "while evaluating: {}",
        String::from_utf8_lossy(context.message())
    );
    LabeledSpan::new_with_span(Some(label), span_range(context.span()))
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
        IrErrorKind::UnsupportedDialectOp { .. } => "aos_nix::lower::unsupported_dialect_op",
        IrErrorKind::Ast(_) => "aos_nix::lower::ast",
    }
}

fn ir_error_help(kind: &IrErrorKind) -> Option<&'static str> {
    match kind {
        IrErrorKind::InvalidBindingKey => Some("Use a static single-segment binding key."),
        IrErrorKind::InvalidInheritSource => Some("Use a valid inherit source expression."),
        IrErrorKind::UnsupportedDialectOp { .. } => {
            Some("Lower this expression through a language dialect that supports the operation.")
        }
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
        TreeWalkErrorKind::ImportParse { .. } => "aos_nix::eval::import_parse",
        TreeWalkErrorKind::ImportScope { .. } => "aos_nix::eval::import_scope",
        TreeWalkErrorKind::ImportLower { .. } => "aos_nix::eval::import_lower",
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
        compile::{IrError, IrErrorKind, IrId, lower, resolve},
        eval::{eval_whnf_owned, tree_walk::EvalErrorContext},
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
    fn eval_diagnostic_reports_import_frontend_codes() {
        let source = "bad";
        let path = b"/child.nix".to_vec();
        for (kind, expected) in [
            (
                TreeWalkErrorKind::ImportParse {
                    id: IrId::new(1),
                    path: path.clone(),
                    message: "parse failed".to_owned(),
                },
                "aos_nix::eval::import_parse",
            ),
            (
                TreeWalkErrorKind::ImportScope {
                    id: IrId::new(1),
                    path: path.clone(),
                    message: "scope failed".to_owned(),
                },
                "aos_nix::eval::import_scope",
            ),
            (
                TreeWalkErrorKind::ImportLower {
                    id: IrId::new(1),
                    path: path.clone(),
                    message: "lower failed".to_owned(),
                },
                "aos_nix::eval::import_lower",
            ),
        ] {
            let diagnostic = EvalDiagnostic::new(
                "child.nix",
                source,
                TreeWalkError::new(kind, Span::new(0, 3)),
            );
            assert_eq!(
                diagnostic.code().map(|code| code.to_string()),
                Some(expected.to_owned())
            );
        }
    }

    #[test]
    fn eval_diagnostic_reports_operand_type_spans() {
        assert_eval_operand_labels("1 + \"x\"", "1", "\"x\"");
        assert_eval_operand_labels("1 > \"x\"", "1", "\"x\"");
        assert_eval_operand_labels("1 <= \"x\"", "1", "\"x\"");
    }

    #[test]
    fn eval_diagnostic_reports_add_error_context_labels() {
        let source = r#"builtins.addErrorContext "outer" (builtins.addErrorContext "inner" (builtins.throw "boom"))"#;
        let ir = lower(resolve(parse_str(source).unwrap()).unwrap()).unwrap();
        let error = eval_whnf_owned(&ir).expect_err("nested context should still throw");
        let diagnostic = EvalDiagnostic::new("expr.nix", source, error);

        let labels = diagnostic
            .labels()
            .expect("context diagnostic has labels")
            .collect::<Vec<_>>();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[0].label(), Some("evaluation error"));
        assert_eq!(labels[1].label(), Some("while evaluating: outer"));
        assert_eq!(
            labels[1].offset(),
            source.find("builtins.addErrorContext").unwrap()
        );
        assert_eq!(labels[2].label(), Some("while evaluating: inner"));
        assert_eq!(
            labels[2].offset(),
            source.rfind("builtins.addErrorContext").unwrap()
        );

        let report = render_fancy_report(&diagnostic).expect("diagnostic renders");
        assert!(report.contains("while evaluating: outer"), "{report}");
        assert!(report.contains("while evaluating: inner"), "{report}");
    }

    #[test]
    fn eval_trace_frames_preserve_order_and_source_positions() {
        let source = EvalErrorSource::new(b"expr.nix".to_vec(), b"a\nb\nc\n".to_vec());
        let error = TreeWalkError::new(
            TreeWalkErrorKind::Thrown {
                id: IrId::new(1),
                message: b"boom".to_vec(),
            },
            Span::new(0, 1),
        )
        .with_contexts(vec![
            EvalErrorContext::new(b"outer".to_vec())
                .with_span(Span::new(0, 1))
                .with_source(source.clone()),
            EvalErrorContext::new(b"inner".to_vec())
                .with_span(Span::new(2, 3))
                .with_source(source),
        ]);

        let frames = eval_trace_frames(&error);

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].message(), "outer");
        assert_eq!(frames[0].source_name(), Some("expr.nix"));
        assert_eq!(frames[0].line(), Some(1));
        assert_eq!(frames[0].column(), Some(1));
        assert_eq!(frames[1].message(), "inner");
        assert_eq!(frames[1].source_name(), Some("expr.nix"));
        assert_eq!(frames[1].line(), Some(2));
        assert_eq!(frames[1].column(), Some(1));
    }

    #[test]
    fn eval_trace_rendering_summarizes_and_expands_frames() {
        let source = EvalErrorSource::new(b"expr.nix".to_vec(), b"a\nb\nc\nd\n".to_vec());
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
                .with_source(source),
        ]);

        let summary =
            render_eval_trace(&error, EvalTraceStyle::Summary).expect("summary trace renders");
        assert!(
            summary.contains("while evaluating: one at expr.nix:1:1"),
            "{summary}"
        );
        assert!(
            summary.contains("while evaluating: three at expr.nix:3:1"),
            "{summary}"
        );
        assert!(summary.contains("1 more frame hidden"), "{summary}");
        assert!(!summary.contains("while evaluating: four"), "{summary}");

        let full = render_eval_trace(&error, EvalTraceStyle::Full).expect("full trace renders");
        assert!(
            full.contains("while evaluating: four at expr.nix:4:1"),
            "{full}"
        );
        assert!(!full.contains("hidden"), "{full}");
    }

    fn assert_eval_operand_labels(source: &str, left: &str, right: &str) {
        let ir = lower(resolve(parse_str(source).unwrap()).unwrap()).unwrap();
        let error = eval_whnf_owned(&ir).expect_err("type mismatch should fail");
        let diagnostic = EvalDiagnostic::new("expr.nix", source, error);

        let labels = diagnostic
            .labels()
            .expect("type diagnostic has operand labels")
            .collect::<Vec<_>>();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].label(), Some("left operand"));
        assert_eq!(labels[0].offset(), source.find(left).unwrap());
        assert_eq!(labels[0].len(), left.len());
        assert_eq!(labels[1].label(), Some("right operand"));
        assert_eq!(labels[1].offset(), source.find(right).unwrap());
        assert_eq!(labels[1].len(), right.len());
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
