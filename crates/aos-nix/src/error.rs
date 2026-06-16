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
}
