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
}

impl TreeWalkError {
    /// Creates a tree-walk evaluation error.
    pub const fn new(kind: TreeWalkErrorKind, span: Span) -> Self {
        Self {
            kind,
            span,
            contexts: Vec::new(),
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

    pub(crate) fn with_span(mut self, span: Span) -> Self {
        self.span = span;
        self
    }

    /// Returns diagnostic context messages from outermost to innermost.
    pub fn contexts(&self) -> &[EvalErrorContext] {
        &self.contexts
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
        self.contexts.insert(0, context);
        Ok(self)
    }
}

impl fmt::Display for TreeWalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for context in &self.contexts {
            write!(
                formatter,
                "while evaluating: {}\n",
                String::from_utf8_lossy(context.message())
            )?;
        }
        write!(formatter, "{} at byte span {:?}", self.kind, self.span)
    }
}

impl std::error::Error for TreeWalkError {}

/// A diagnostic context attached to a tree-walk evaluation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalErrorContext {
    pub(crate) message: Vec<u8>,
}

impl EvalErrorContext {
    pub(crate) fn new(message: Vec<u8>) -> Self {
        Self { message }
    }

    /// Returns the context message bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}
