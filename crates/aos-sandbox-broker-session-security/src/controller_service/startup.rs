//! Application-owned runtime failure custody above fixed startup admission.
//!
//! The lower continuation remains first so its armed Drop fence runs before
//! any upper failure field can release. It still owns every actual capture,
//! profile/selector/launch admission and startup original. This private wrapper
//! removes the reverse runtime-error dependency without moving those recipes or
//! introducing a public startup/authority constructor.

use std::ops::{Deref, DerefMut};

use super::ControllerRuntimeError;
use crate::production_startup::ControllerStartupContinuationV1;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_failure_view_borrows_the_original_without_diagnostic_detail() {
        let cause = ControllerRuntimeError::InvalidCredential;
        let view = ControllerRuntimeStartupFailureRef(&cause);

        assert!(std::ptr::eq(view.0, &cause));
        assert_eq!(format!("{view:?}"), "resident runtime continuation refused");
    }
}
