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

    /// Returns whether callers may retry this failure with C++ Nix.
    ///
    /// Unsupported native features and internal native failures may fall back
    /// because C++ Nix can still be authoritative. Normal Nix evaluation errors
    /// must surface as-is so native evaluation cannot hide semantic failures by
    /// retrying them.
    pub const fn permits_cli_fallback(&self) -> bool {
        matches!(self, Self::Unsupported { .. } | Self::Internal { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_policy_tracks_error_taxonomy() {
        assert!(NativeEvalError::unsupported("missing primop").permits_cli_fallback());
        assert!(
            NativeEvalError::Internal {
                message: "bug".to_string()
            }
            .permits_cli_fallback()
        );
        assert!(
            !NativeEvalError::EvalError {
                message: "type error".to_string()
            }
            .permits_cli_fallback()
        );
    }
}
