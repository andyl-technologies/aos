//! Evaluation outcome, derivation, trace, IFD-realization, and warning types.

use super::*;

/// A tree-walk evaluation result with its owning evaluator heap.
#[derive(Debug)]
pub struct EvalOutcome {
    pub(crate) value: Value,
    pub(crate) heap: EvalHeap,
    pub(crate) trace_output: Vec<EvalTraceOutput>,
    pub(crate) warning_output: Vec<EvalWarningOutput>,
    pub(crate) derivations: Vec<EvalDerivation>,
}

impl EvalOutcome {
    /// Returns the evaluated root value.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the heap that owns heap-backed values in this result.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns user-facing trace output emitted during evaluation.
    pub fn trace_output(&self) -> &[EvalTraceOutput] {
        &self.trace_output
    }

    /// Returns user-facing warning output emitted during evaluation.
    pub fn warning_output(&self) -> &[EvalWarningOutput] {
        &self.warning_output
    }

    /// Returns derivations observed while evaluating the root expression.
    pub fn derivations(&self) -> &[EvalDerivation] {
        &self.derivations
    }

    /// Consumes the outcome into its value and heap.
    pub fn into_parts(self) -> (Value, EvalHeap) {
        (self.value, self.heap)
    }

    /// Consumes the outcome into its value, heap, and user-facing trace output.
    pub fn into_full_parts(self) -> (Value, EvalHeap, Vec<EvalTraceOutput>) {
        (self.value, self.heap, self.trace_output)
    }

    /// Consumes the outcome into its value, heap, trace output, and warning output.
    pub fn into_output_parts(
        self,
    ) -> (
        Value,
        EvalHeap,
        Vec<EvalTraceOutput>,
        Vec<EvalWarningOutput>,
    ) {
        (
            self.value,
            self.heap,
            self.trace_output,
            self.warning_output,
        )
    }
}

/// A derivation recorded during tree-walk evaluation.
///
/// Recorded derivations include their ATerm bytes when byte materialization is
/// possible during evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalDerivation {
    pub(crate) absolute_path: String,
    pub(crate) aterm_bytes: Option<Vec<u8>>,
}

impl EvalDerivation {
    pub(crate) fn new(absolute_path: String, aterm_bytes: Option<Vec<u8>>) -> Self {
        Self {
            absolute_path,
            aterm_bytes,
        }
    }

    /// Returns the absolute `/nix/store` path of the `.drv`.
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the serialized `.drv` ATerm bytes when they are statically known.
    pub fn aterm_bytes(&self) -> Option<&[u8]> {
        self.aterm_bytes.as_deref()
    }
}

/// User-facing trace output emitted by `builtins.trace`-style builtins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalTraceOutput {
    pub(crate) kind: EvalTraceKind,
    pub(crate) message: Vec<u8>,
}

impl EvalTraceOutput {
    /// Creates a trace output record.
    pub(crate) fn new(kind: EvalTraceKind, message: Vec<u8>) -> Self {
        Self { kind, message }
    }

    /// Returns the builtin family that emitted this output.
    pub const fn kind(&self) -> EvalTraceKind {
        self.kind
    }

    /// Returns the rendered trace message bytes without the `trace: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// The trace-like builtin that produced user-facing output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvalTraceKind {
    /// Output from `builtins.trace`.
    Trace,
    /// Output from `builtins.traceVerbose`.
    TraceVerbose,
}

/// A request to realize a derivation output needed during evaluation.
///
/// Import-from-derivation (IFD) is the one point where evaluation must pause for
/// the build layer. The tree-walk evaluator does not build by itself; callers
/// may install an [`IfdRealizer`] that realizes the requested derivation output
/// and returns once the filesystem path can be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfdRealization<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) drv_path: &'a [u8],
    pub(crate) output_name: Option<&'a [u8]>,
    pub(crate) context_kind: ContextKind,
    pub(crate) op: &'static str,
}

impl<'a> IfdRealization<'a> {
    /// Returns the filesystem path that triggered the IFD demand.
    pub const fn path(&self) -> &'a [u8] {
        self.path
    }

    /// Returns the derivation path whose output must be realized.
    pub const fn drv_path(&self) -> &'a [u8] {
        self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub const fn output_name(&self) -> Option<&'a [u8]> {
        self.output_name
    }

    /// Returns the string-context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the filesystem-reading builtin that triggered the demand.
    pub const fn op(&self) -> &'static str {
        self.op
    }
}

/// A failure reported by an import-from-derivation realizer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct IfdRealizationError {
    pub(crate) message: String,
}

impl IfdRealizationError {
    /// Creates a realization error from a user-facing message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the realizer failure message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Detailed context for an import-from-derivation evaluator error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IfdErrorDetail {
    pub(crate) path: Box<[u8]>,
    pub(crate) drv_path: Box<[u8]>,
    pub(crate) output_name: Option<Box<[u8]>>,
    pub(crate) context_kind: ContextKind,
    pub(crate) message: Option<String>,
}

impl IfdErrorDetail {
    pub(crate) fn new(
        path: Vec<u8>,
        drv_path: Vec<u8>,
        output_name: Option<Vec<u8>>,
        context_kind: ContextKind,
        message: Option<String>,
    ) -> Self {
        Self {
            path: path.into_boxed_slice(),
            drv_path: drv_path.into_boxed_slice(),
            output_name: output_name.map(Vec::into_boxed_slice),
            context_kind,
            message,
        }
    }

    /// Returns the filesystem path that triggered the IFD demand.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the derivation path recorded in the string context.
    pub fn drv_path(&self) -> &[u8] {
        &self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub fn output_name(&self) -> Option<&[u8]> {
        self.output_name.as_deref()
    }

    /// Returns the context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the realizer diagnostic, if the realizer failed.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for IfdErrorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "path {:?}, derivation {:?}, output {:?}, context {:?}",
            self.path,
            self.drv_path,
            self.output_name.as_deref(),
            self.context_kind
        )?;
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        Ok(())
    }
}

/// Callback used to realize derivation outputs at IFD boundaries.
#[derive(Clone)]
pub struct IfdRealizer {
    realize:
        Arc<dyn for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError> + Send + Sync>,
}

impl IfdRealizer {
    /// Creates an IFD realizer from a callback.
    pub fn new<F>(realize: F) -> Self
    where
        F: for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            realize: Arc::new(realize),
        }
    }

    pub(crate) fn realize(&self, request: IfdRealization<'_>) -> Result<(), IfdRealizationError> {
        (self.realize)(request)
    }
}

impl fmt::Debug for IfdRealizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IfdRealizer")
            .finish_non_exhaustive()
    }
}

/// User-facing warning output emitted by `builtins.warn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalWarningOutput {
    pub(crate) message: Vec<u8>,
}

impl EvalWarningOutput {
    /// Creates a warning output record.
    pub(crate) fn new(message: Vec<u8>) -> Self {
        Self { message }
    }

    /// Returns the warning message bytes without the `evaluation warning: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}
