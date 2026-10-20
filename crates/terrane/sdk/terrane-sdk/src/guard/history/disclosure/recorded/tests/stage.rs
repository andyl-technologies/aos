//! Labels failed fixture stages while retaining their genuine error source chains.

use std::error::Error;
use std::fmt;

/// Retains one actual fixture error beneath a concise failing-stage label.
#[derive(Debug)]
pub(super) struct Failure {
    phase: &'static str,
    source: Box<dyn Error>,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.phase, self.source)
    }
}

impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Wraps a failed stage without replacing, formatting away or reclassifying its error.
pub(super) fn failure(phase: &'static str, error: impl Into<Box<dyn Error>>) -> Failure {
    Failure {
        phase,
        source: error.into(),
    }
}
