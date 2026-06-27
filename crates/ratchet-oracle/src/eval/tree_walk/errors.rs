//! Evaluation error type, error context, and the exhaustive error-kind enum.

use super::*;

/// A numeric arithmetic operator used in tree-walk diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithmeticOp {
    /// Unary numeric negation.
    Neg,
    /// Binary numeric addition.
    Add,
    /// Binary numeric subtraction.
    Sub,
    /// Binary numeric multiplication.
    Mul,
    /// Binary numeric division.
    Div,
    /// Float-to-integer ceiling.
    Ceil,
    /// Float-to-integer floor.
    Floor,
}

/// A tree-walk evaluation failure with source location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeWalkError {
    pub(crate) kind: TreeWalkErrorKind,
    pub(crate) span: Span,
    pub(crate) contexts: Vec<EvalErrorContext>,
    pub(crate) labels: Vec<EvalErrorLabel>,
    pub(crate) source: Option<EvalErrorSource>,
}

impl TreeWalkError {
    /// Creates a tree-walk evaluation error.
    pub const fn new(kind: TreeWalkErrorKind, span: Span) -> Self {
        Self {
            kind,
            span,
            contexts: Vec::new(),
            labels: Vec::new(),
            source: None,
        }
    }

    /// Returns the error category.
    pub fn kind(&self) -> TreeWalkErrorKind {
        self.kind.clone()
    }

    /// Returns the source span associated with this error.
    pub const fn span(&self) -> Span {
        self.span
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.span = span;
        self
    }

    pub(crate) fn with_label(mut self, span: Span, label: &'static str) -> Self {
        self.labels.push(EvalErrorLabel { span, label });
        self
    }

    pub fn with_labels(mut self, labels: Vec<EvalErrorLabel>) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_contexts(mut self, contexts: Vec<EvalErrorContext>) -> Self {
        self.contexts = contexts;
        self
    }

    pub fn with_source(mut self, source: EvalErrorSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Returns diagnostic context messages from outermost to innermost.
    pub fn contexts(&self) -> &[EvalErrorContext] {
        &self.contexts
    }

    /// Returns additional source labels relevant to this error.
    pub fn labels(&self) -> &[EvalErrorLabel] {
        &self.labels
    }

    /// Returns the source file associated with this evaluation error, if known.
    pub const fn source(&self) -> Option<&EvalErrorSource> {
        self.source.as_ref()
    }

    pub(crate) fn try_prepend_context(
        mut self,
        id: IrId,
        span: Span,
        context: EvalErrorContext,
    ) -> Result<Self, Self> {
        self.contexts.try_reserve_exact(1).map_err(|_| {
            Self::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: self.contexts.len().saturating_add(1),
                },
                span,
            )
        })?;
        self.contexts.insert(0, context.with_span(span));
        Ok(self)
    }
}

impl fmt::Display for TreeWalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for context in &self.contexts {
            writeln!(
                formatter,
                "while evaluating: {}",
                String::from_utf8_lossy(context.message())
            )?;
        }
        write!(formatter, "{} at byte span {:?}", self.kind, self.span)
    }
}

impl std::error::Error for TreeWalkError {}

/// Source bytes for the module where an evaluation error was raised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalErrorSource {
    pub(crate) name: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
}

impl EvalErrorSource {
    pub fn new(name: Vec<u8>, bytes: Vec<u8>) -> Self {
        Self { name, bytes }
    }

    /// Returns the source name bytes, usually the canonical file path.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the source bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A secondary source label attached to a tree-walk evaluation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalErrorLabel {
    pub span: Span,
    pub label: &'static str,
}

impl EvalErrorLabel {
    /// Returns the byte span covered by this label.
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Returns the human-readable label text.
    pub const fn label(&self) -> &'static str {
        self.label
    }
}

/// A diagnostic context attached to a tree-walk evaluation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalErrorContext {
    pub(crate) message: Vec<u8>,
    pub(crate) span: Span,
    pub(crate) source: Option<EvalErrorSource>,
}

impl EvalErrorContext {
    pub fn new(message: Vec<u8>) -> Self {
        Self {
            message,
            span: Span::default(),
            source: None,
        }
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.span = span;
        self
    }

    pub fn with_source(mut self, source: EvalErrorSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Returns the context message bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the source span for the expression that attached this context.
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Returns the source file associated with this context span, if known.
    pub const fn source(&self) -> Option<&EvalErrorSource> {
        self.source.as_ref()
    }
}
