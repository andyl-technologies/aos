//! Native evaluator errors and source-location records.
//!
//! The native path distinguishes unsupported features from genuine Nix
//! evaluation failures so the integration layer knows when a transparent
//! fallback to C++ Nix is legal.

use thiserror::Error;

/// A byte span in a Nix source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrcSpan {
    /// Byte offset of the first byte covered by this span.
    pub start: u32,
    /// Byte offset one past the final byte covered by this span.
    pub end: u32,
}

/// The reason a native evaluator failure may be retried with C++ Nix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCliFallbackReason {
    /// The native evaluator has not implemented the requested feature yet.
    Unsupported,
    /// The native evaluator failed internally and C++ Nix remains authoritative.
    Internal,
}

/// The evaluator resource whose configured hard limit was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeResourceLimit {
    /// Deterministic evaluated-node step budget.
    Steps,
    /// In-engine wall-clock deadline.
    Time,
    /// Resident heap-memory ceiling.
    HeapMemory,
    /// Nested Nix call-depth ceiling.
    CallDepth,
}

/// Direction of an option access which requires another module provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeMissingOptionKind {
    /// A module wrote an option with no loaded declaration.
    UndeclaredWrite,
    /// A module read an absent top-level configuration root.
    AbsentRootRead,
}

/// One structured missing-option diagnostic from native evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMissingOption {
    /// Full write path, or the absent root for a read.
    pub path: String,
    /// Access direction used by the resolver fixpoint.
    pub kind: NativeMissingOptionKind,
    /// Authenticated module source when available.
    pub source_path: Option<String>,
}

/// One definition carried by a structured module conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeConflictDef {
    /// Canonical JSON rendering of the conflicting value.
    pub value: Option<String>,
    /// Authenticated definition source when available.
    pub source_path: Option<String>,
}

/// A failure produced by the native evaluator.
#[derive(Debug, Error)]
pub enum NativeEvalError {
    /// The evaluator reached a language or builtin feature that is not
    /// implemented yet and may be retried with `NixCli`.
    #[error("native Nix evaluator does not yet support {feature}")]
    Unsupported {
        /// The missing language or builtin feature.
        feature: String,
        /// The best source span available for the unsupported feature.
        span: Option<SrcSpan>,
    },

    /// The evaluated Nix program failed according to normal Nix semantics.
    #[error("native Nix evaluation failed: {message}")]
    EvalError {
        /// User-facing evaluation failure text.
        message: String,
    },

    /// Conservative pre-evaluation analysis proved a demanded binding cycle.
    #[error(
        "native Nix static divergence in {source_path}: demanded recursive binding '{binding}'"
    )]
    StaticDivergence {
        /// Binding whose strict demand closes the recursive cycle.
        binding: String,
        /// Root expression marker or canonical imported source path.
        source_path: String,
    },

    /// Module evaluation requested one or more option providers.
    #[error("native Nix evaluation found missing options")]
    MissingOptions {
        /// Structured, evaluator-derived missing accesses.
        missing: Vec<NativeMissingOption>,
    },

    /// A declared option was forced without a definition or default.
    #[error("native Nix option '{path}' has no definition or default")]
    UndefinedOption {
        /// Fully qualified option path.
        path: String,
        /// Declaration source when available.
        source_path: Option<String>,
    },

    /// Equal-priority module definitions disagree on a unique option value.
    #[error("native Nix option '{path}' has conflicting definitions")]
    Conflict {
        /// Fully qualified option path.
        path: String,
        /// Every definition participating in the conflict.
        defs: Vec<NativeConflictDef>,
    },

    /// A forced module assertion failed.
    #[error("native Nix module assertion failed: {message}")]
    Assertion {
        /// Assertion message authored by the module.
        message: String,
        /// Authenticated assertion source when available.
        source_path: Option<String>,
    },

    /// The evaluator stopped cleanly before crossing a configured hard limit.
    #[error("native Nix evaluator resource limit exceeded: {message}")]
    ResourceLimit {
        /// The resource whose limit was exhausted.
        resource: NativeResourceLimit,
        /// Stable user-facing limit diagnostic.
        message: String,
    },

    /// The evaluator hit an internal failure and the caller should fall back
    /// while surfacing a diagnostic.
    #[error("native Nix evaluator internal failure: {message}")]
    Internal {
        /// Diagnostic text for the internal failure.
        message: String,
    },
}

impl NativeEvalError {
    /// Creates an unsupported-feature error without a source span.
    pub fn unsupported(feature: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: feature.into(),
            span: None,
        }
    }

    /// Returns whether callers may retry this failure with C++ Nix.
    ///
    /// Unsupported native features and internal native failures may fall back
    /// because C++ Nix can still be authoritative. Normal Nix evaluation errors
    /// must surface as-is so native evaluation cannot hide semantic failures by
    /// retrying them.
    pub const fn permits_cli_fallback(&self) -> bool {
        self.cli_fallback_reason().is_some()
    }

    /// Returns the C++ Nix fallback reason for retryable failures.
    pub const fn cli_fallback_reason(&self) -> Option<NativeCliFallbackReason> {
        match self {
            Self::Unsupported { .. } => Some(NativeCliFallbackReason::Unsupported),
            Self::Internal { .. } => Some(NativeCliFallbackReason::Internal),
            Self::EvalError { .. } | Self::StaticDivergence { .. } => None,
            Self::MissingOptions { .. }
            | Self::UndefinedOption { .. }
            | Self::Conflict { .. }
            | Self::Assertion { .. } => None,
            Self::ResourceLimit { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_policy_tracks_error_taxonomy() {
        assert!(NativeEvalError::unsupported("missing primop").permits_cli_fallback());
        assert_eq!(
            NativeEvalError::unsupported("missing primop").cli_fallback_reason(),
            Some(NativeCliFallbackReason::Unsupported)
        );
        assert!(
            NativeEvalError::Internal {
                message: "bug".to_string()
            }
            .permits_cli_fallback()
        );
        assert_eq!(
            NativeEvalError::Internal {
                message: "bug".to_string()
            }
            .cli_fallback_reason(),
            Some(NativeCliFallbackReason::Internal)
        );
        assert!(
            !NativeEvalError::EvalError {
                message: "type error".to_string()
            }
            .permits_cli_fallback()
        );
        assert_eq!(
            NativeEvalError::EvalError {
                message: "type error".to_string()
            }
            .cli_fallback_reason(),
            None
        );
        assert!(
            !NativeEvalError::StaticDivergence {
                binding: "bottom".to_string(),
                source_path: "module.nix".to_string(),
            }
            .permits_cli_fallback()
        );
        assert!(
            !NativeEvalError::ResourceLimit {
                resource: NativeResourceLimit::Steps,
                message: "step budget".to_string(),
            }
            .permits_cli_fallback()
        );
    }
}
