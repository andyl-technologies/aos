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
///
/// The payload is boxed so the type is one pointer wide. `TreeWalkError` is the
/// `E` in every `Result<Value, TreeWalkError>` the evaluator threads, and an
/// inline payload — the 160-variant [`TreeWalkErrorKind`], the span, two
/// diagnostic `Vec`s, and the optional source, ~144 bytes together — would
/// force each of the ~20 call boundaries per op to return that `Result` through
/// memory (an sret hidden pointer), paid on the success path for an error that
/// is almost never raised. Boxing shrinks the type to a single pointer so the
/// success path stays register-sized; the allocation happens only when an error
/// is actually constructed, which is cold. See the per-op instruction-tax
/// ledger (RFC-0007 design-notes) for the accounting.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeWalkError {
    inner: Box<TreeWalkErrorInner>,
}

/// The boxed payload of a [`TreeWalkError`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct TreeWalkErrorInner {
    kind: TreeWalkErrorKind,
    span: Span,
    contexts: Vec<EvalErrorContext>,
    labels: Vec<EvalErrorLabel>,
    source: Option<EvalErrorSource>,
}

impl fmt::Debug for TreeWalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mirror the field layout a derived `Debug` on the flat struct produced,
        // so diagnostics and test output are unchanged by the boxing.
        formatter
            .debug_struct("TreeWalkError")
            .field("kind", &self.inner.kind)
            .field("span", &self.inner.span)
            .field("contexts", &self.inner.contexts)
            .field("labels", &self.inner.labels)
            .field("source", &self.inner.source)
            .finish()
    }
}

impl TreeWalkError {
    /// Creates a tree-walk evaluation error.
    pub fn new(kind: TreeWalkErrorKind, span: Span) -> Self {
        Self {
            inner: Box::new(TreeWalkErrorInner {
                kind,
                span,
                contexts: Vec::new(),
                labels: Vec::new(),
                source: None,
            }),
        }
    }

    /// Returns the error category.
    pub fn kind(&self) -> TreeWalkErrorKind {
        self.inner.kind.clone()
    }

    /// Returns whether this is the private FinalForce suspension channel.
    pub(crate) fn is_final_force_portal_suspend(&self) -> bool {
        matches!(
            self.inner.kind,
            TreeWalkErrorKind::FinalForcePortalSuspend { .. }
        )
    }

    /// Returns the source span associated with this error.
    pub fn span(&self) -> Span {
        self.inner.span
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.inner.span = span;
        self
    }

    pub(crate) fn with_label(mut self, span: Span, label: &'static str) -> Self {
        self.inner.labels.push(EvalErrorLabel { span, label });
        self
    }

    pub fn with_labels(mut self, labels: Vec<EvalErrorLabel>) -> Self {
        self.inner.labels = labels;
        self
    }

    pub fn with_contexts(mut self, contexts: Vec<EvalErrorContext>) -> Self {
        self.inner.contexts = contexts;
        self
    }

    pub fn with_source(mut self, source: EvalErrorSource) -> Self {
        self.inner.source = Some(source);
        self
    }

    /// Returns diagnostic context messages from outermost to innermost.
    pub fn contexts(&self) -> &[EvalErrorContext] {
        &self.inner.contexts
    }

    /// Returns additional source labels relevant to this error.
    pub fn labels(&self) -> &[EvalErrorLabel] {
        &self.inner.labels
    }

    /// Returns the source file associated with this evaluation error, if known.
    pub fn source(&self) -> Option<&EvalErrorSource> {
        self.inner.source.as_ref()
    }

    pub(crate) fn try_prepend_context(
        mut self,
        id: IrId,
        span: Span,
        context: EvalErrorContext,
    ) -> Result<Self, Self> {
        if self.is_final_force_portal_suspend() {
            return Ok(self);
        }
        self.inner.contexts.try_reserve_exact(1).map_err(|_| {
            Self::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: self.inner.contexts.len().saturating_add(1),
                },
                span,
            )
        })?;
        self.inner.contexts.insert(0, context.with_span(span));
        Ok(self)
    }
}

impl fmt::Display for TreeWalkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for context in &self.inner.contexts {
            writeln!(
                formatter,
                "while evaluating: {}",
                String::from_utf8_lossy(context.message())
            )?;
        }
        write!(
            formatter,
            "{} at byte span {:?}",
            self.inner.kind, self.inner.span
        )
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

#[cfg(test)]
mod size_pins {
    use super::TreeWalkError;
    use crate::value::Value;

    /// Pins the boxed-payload win: [`TreeWalkError`] is one pointer wide.
    ///
    /// Before boxing, the inline payload (160-variant kind + span + two `Vec`s +
    /// optional source) made the type ~144 bytes, which
    /// `#![allow(clippy::result_large_err)]` used to suppress. Boxing keeps the
    /// error a single pointer so `Result<Value, TreeWalkError>` returns in
    /// registers on the success path. See the per-op instruction-tax ledger
    /// (RFC-0007 design-notes).
    #[test]
    fn tree_walk_error_is_one_pointer_wide() {
        assert_eq!(
            std::mem::size_of::<TreeWalkError>(),
            std::mem::size_of::<usize>(),
        );
    }

    /// Pins that the evaluator's ubiquitous return type stays register-sized:
    /// at most the value payload plus the boxed-error pointer, versus the
    /// ~144-byte inline error before boxing.
    #[test]
    fn result_value_error_stays_register_sized() {
        assert!(
            std::mem::size_of::<Result<Value, TreeWalkError>>()
                <= std::mem::size_of::<Value>() + std::mem::size_of::<usize>()
        );
    }
}
