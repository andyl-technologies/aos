//! Retains actual attempts separately from authenticated witness population.
//!
//! A transport or source-evidence refusal after an attempt cannot become an
//! unexecuted row during issuance. These sets retain that distinction without
//! minting a passing result or replacing the original provider custody.

use std::collections::BTreeSet;

use super::QualificationError;

/// Retains original attempted and independently authenticated case identities.
///
/// Only the owning runner changes these sets. The record is data, not native
/// authority, and cannot be decoded or promoted into an accepted certificate.
#[derive(Default)]
pub struct OriginalCollectionAttempts {
    attempted: BTreeSet<String>,
    authenticated: BTreeSet<String>,
}

impl OriginalCollectionAttempts {
    /// Borrows all actual attempts, including refused observation authentication.
    pub fn attempted_cases(&self) -> &BTreeSet<String> {
        &self.attempted
    }

    /// Borrows cases whose original evidence passed installed authentication.
    pub fn authenticated_cases(&self) -> &BTreeSet<String> {
        &self.authenticated
    }

    pub(super) fn attempted(&self, case: &str) -> bool {
        self.attempted.contains(case)
    }

    pub(super) fn begin(&mut self, case: String) {
        self.attempted.insert(case);
    }

    pub(super) fn authenticate(&mut self, case: &str) -> Result<(), QualificationError> {
        if !self.attempted.contains(case) || self.authenticated.contains(case) {
            return Err(QualificationError::Refused(
                "changed original collection authentication",
            ));
        }
        self.authenticated.insert(case.to_owned());
        Ok(())
    }

    pub(super) fn finish<T>(
        self,
        issue: impl FnOnce() -> Result<T, QualificationError>,
    ) -> (Self, Result<T, QualificationError>) {
        let issued = if self.complete() {
            issue()
        } else {
            Err(QualificationError::Refused(
                "original conformance attempt lacks authenticated evidence",
            ))
        };
        (self, issued)
    }

    fn complete(&self) -> bool {
        self.attempted == self.authenticated
    }
}

#[cfg(test)]
mod tests;
