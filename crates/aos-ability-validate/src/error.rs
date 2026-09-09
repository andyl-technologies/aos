//! Aggregated structured validation failures.

use std::fmt;

use aos_ability_model::Diagnostic;

pub(crate) const MAX_DIAGNOSTICS: usize = 256;

pub(crate) fn push_diagnostic(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if diagnostics.len() < MAX_DIAGNOSTICS {
        diagnostics.push(diagnostic);
    }
}

/// Collects every safely discoverable semantic failure from one validation pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationErrors {
    diagnostics: Vec<Diagnostic>,
}

impl ValidationErrors {
    pub(crate) fn new(diagnostics: Vec<Diagnostic>) -> Self {
        debug_assert!(!diagnostics.is_empty());
        Self { diagnostics }
    }

    /// Returns structured diagnostics in deterministic discovery order.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Consumes the error and returns its structured diagnostics.
    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.diagnostics.len();
        write!(
            formatter,
            "ability validation failed with {count} diagnostic"
        )?;
        if count != 1 {
            formatter.write_str("s")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}
