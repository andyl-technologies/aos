//! Application-owned Controller startup coordination and runtime failure custody.
//!
//! The actual continuation remains first so its armed Drop fence runs before
//! any upper failure field can release. It still owns every actual capture,
//! profile/selector/launch admission and startup original. This private wrapper
//! keeps the original recipes above transport without introducing a public
//! startup or authority constructor.

use std::ops::{Deref, DerefMut};

use super::ControllerRuntimeError;

mod continuation;
use continuation::ControllerStartupContinuationV1;

/// Retains the actual application cause separately from lower startup custody.
pub(crate) struct ControllerRuntimeStartupV1 {
    continuation: ControllerStartupContinuationV1,
    runtime_failure: Option<ControllerRuntimeError>,
}

impl ControllerRuntimeStartupV1 {
    pub(crate) fn new(publisher: bool, nix: bool, issue: bool) -> Self {
        Self {
            continuation: ControllerStartupContinuationV1::new(publisher, nix, issue),
            runtime_failure: None,
        }
    }

    /// Projects the actual same-opening first cause before negative termination.
    ///
    /// The opening stays in the caller's armed local frame. Borrowing its
    /// original cause does not move a guard, replace native errors, or create
    /// another opening; process exit retains that frame without destructors.
    pub(crate) fn fail_resource_opening(
        &mut self,
        opening: &aos_sandbox::ControllerResourceBankOpeningV1,
    ) -> ! {
        if let Some(cause) = opening.failure() {
            let original = ControllerRuntimeOpeningFailureRef(cause);
            eprintln!("aos-sandboxd: {original:?}");
        }
        self.continuation.terminate_runtime_refusal()
    }

    /// Parks the original typed cause before the lower negative-only refusal.
    pub(crate) fn fail_runtime(&mut self, cause: ControllerRuntimeError) -> ! {
        let actual = self.runtime_failure.get_or_insert(cause);
        let _view = ControllerRuntimeStartupFailureRef(actual);
        self.continuation.terminate_runtime_refusal()
    }
}

impl Deref for ControllerRuntimeStartupV1 {
    type Target = ControllerStartupContinuationV1;

    fn deref(&self) -> &Self::Target {
        &self.continuation
    }
}

impl DerefMut for ControllerRuntimeStartupV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.continuation
    }
}

// A short cause view keeps the same deliberately coarse diagnostic without
// cloning, formatting, or moving the original application error payload.
struct ControllerRuntimeStartupFailureRef<'attempt>(&'attempt ControllerRuntimeError);

impl std::fmt::Debug for ControllerRuntimeStartupFailureRef<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _actual = self.0;
        formatter.write_str("resident runtime continuation refused")
    }
}

// Keep diagnostic content coarse while the Error source borrows the exact
// first native/comparison cause parked in the genuine original opening.
struct ControllerRuntimeOpeningFailureRef<'attempt>(&'attempt (dyn std::error::Error + 'static));

impl std::fmt::Debug for ControllerRuntimeOpeningFailureRef<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resident original Runtime receiving refused")
    }
}

impl std::fmt::Display for ControllerRuntimeOpeningFailureRef<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, formatter)
    }
}

impl std::error::Error for ControllerRuntimeOpeningFailureRef<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_failure_view_borrows_exact_original_error() {
        let cause = std::io::Error::from_raw_os_error(13);
        let view = ControllerRuntimeOpeningFailureRef(&cause);

        let source = std::error::Error::source(&view).expect("original native cause");
        assert!(std::ptr::eq(source, &cause as &(dyn std::error::Error + 'static)));
        assert_eq!(source.downcast_ref::<std::io::Error>()
            .expect("same native error type").raw_os_error(), Some(13));
    }

    #[test]
    fn runtime_failure_view_borrows_the_original_without_diagnostic_detail() {
        let cause = ControllerRuntimeError::InvalidCredential;
        let view = ControllerRuntimeStartupFailureRef(&cause);

        assert!(std::ptr::eq(view.0, &cause));
        assert_eq!(format!("{view:?}"), "resident runtime continuation refused");
    }
}
