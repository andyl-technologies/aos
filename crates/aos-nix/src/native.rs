//! `aos-core` facing native evaluator shim.
//!
//! [`NixNative`] is the stable integration handle that will own the parser
//! cache, symbol interner, hash-consing tables, and evaluator arena as Phase 1
//! fills in. The current implementation is deliberately conservative: it never
//! fabricates a derivation and always reports unsupported evaluation.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::error::NativeEvalError;

/// In-process RFC-0007 evaluator handle.
#[derive(Debug, Clone)]
pub struct NixNative {
    verbose: u8,
}

impl NixNative {
    /// Creates a native evaluator handle.
    ///
    /// # Errors
    ///
    /// The Phase-1 shim has no fallible initialization. Future implementations
    /// may return errors when opening the persistent cache or validating store
    /// paths.
    pub fn new(verbose: u8) -> Result<Self> {
        Ok(Self { verbose })
    }

    /// Returns the configured verbosity level.
    pub fn verbose(&self) -> u8 {
        self.verbose
    }

    /// Evaluates `attr` from `file` to a derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] until the Phase-1 parser,
    /// oracle, and derivation serializer are implemented.
    pub fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
        Err(NativeEvalError::unsupported("native instantiation").into())
    }

    /// Evaluates a raw expression to a derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] until expression
    /// instantiation is implemented.
    pub fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
        Err(NativeEvalError::unsupported("native expression instantiation").into())
    }

    /// Evaluates a raw expression and renders it as strict JSON text.
    ///
    /// # Errors
    ///
    /// Returns [`NativeEvalError::Unsupported`] until expression evaluation is
    /// implemented.
    pub fn eval_expr(&self, _expr: &str) -> Result<String> {
        Err(NativeEvalError::unsupported("native expression evaluation").into())
    }

    /// Returns a stable implementation name for diagnostics.
    pub fn name(&self) -> &'static str {
        "aos-nix"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_unsupported() -> Result<()> {
        let native = NixNative::new(0)?;
        let err = native
            .eval_expr("1 + 1")
            .expect_err("stub must not claim native success");
        assert!(err.downcast_ref::<NativeEvalError>().is_some());
        assert_eq!(native.name(), "aos-nix");
        Ok(())
    }
}
