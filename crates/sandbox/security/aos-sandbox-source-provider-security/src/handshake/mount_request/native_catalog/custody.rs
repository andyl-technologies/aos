//! Failure-only loans and retained handoffs for actual original native custody.
//!
//! Failure-loan destruction latches progress and revokes the actual Session
//! without validation, recovery, allocation or Journal effects. The retained
//! handoff helper checks signed DATA and allocates a unique private shell while
//! the actual guard remains parked in Prepared.

use super::*;

/// Allocates the private shell while the actual guard remains in Prepared.
pub(in crate::handshake::mount_request) fn park_native_outcome_v5(
    prepared: &mut PreparedMountProviderRequestV2,
    signed: &SignedSourceProviderRequestV1,
) -> Result<(), SourceProviderSecurityError> {
    if prepared.native_currentness.is_none() {
        return if prepared.outcome.native_outcome.is_none() {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::SessionContinuity)
        };
    }
    if prepared.outcome.native_outcome.is_some() || &prepared.outcome.signed_request != signed {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    prepared.outcome.native_outcome = Some(std::sync::Arc::new(
        NativeAcquireOutcomeCustodyV3::empty_shell(signed.clone()),
    ));
    let shell = prepared
        .outcome
        .native_outcome
        .as_mut()
        .and_then(std::sync::Arc::get_mut)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;

    shell.park_guard(&mut prepared.native_currentness);
    Ok(())
}

/// Records the actual transport boundary without supplying send authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::handshake::mount_request) enum OriginalSendStateV5 {
    Unattempted,
    Attempted,
    Retryable,
    Accepted,
}

/// Groups only failure latching for concrete retained original shapes.
pub(in crate::handshake) trait FailOriginalProgressV5 {
    fn fail(&mut self);
}

impl FailOriginalProgressV5 for () {
    fn fail(&mut self) {}
}

impl FailOriginalProgressV5 for &mut Option<PendingNativeMountAcquireV3> {
    fn fail(&mut self) {
        if let Some(pending) = self.as_ref() {
            pending.failed.set(true);
        }
    }
}

impl FailOriginalProgressV5 for &mut PendingNativeMountAcquireV3 {
    fn fail(&mut self) {
        self.failed.set(true);
    }
}

impl FailOriginalProgressV5 for &ReservedMountProviderRequestV2 {
    fn fail(&mut self) {
        self.original_failed.set(true);
    }
}

impl FailOriginalProgressV5 for &mut ReservedMountProviderRequestV2 {
    fn fail(&mut self) {
        self.original_failed.set(true);
    }
}

impl FailOriginalProgressV5 for &mut Option<ReservedMountProviderRequestV2> {
    fn fail(&mut self) {
        if let Some(reserved) = self.as_ref() {
            reserved.original_failed.set(true);
        }
    }
}

impl FailOriginalProgressV5 for &OriginalNativeReceivedOutcomeV5 {
    fn fail(&mut self) {
        self.fail_original_custody_v5();
    }
}

impl FailOriginalProgressV5 for &mut OriginalNativeReceivedOutcomeV5 {
    fn fail(&mut self) {
        self.fail_original_custody_v5();
    }
}

impl FailOriginalProgressV5 for &mut Option<OriginalNativeReceivedOutcomeV5> {
    fn fail(&mut self) {
        if let Some(retained) = self.as_ref() {
            retained.fail_original_custody_v5();
        }
    }
}

/// Keeps actual Session and progress borrowed until a successful return.
pub(in crate::handshake) struct OriginalBoundaryV5<'session, P: FailOriginalProgressV5> {
    session: &'session mut CurrentRootMountSourceProviderSessionV1,
    progress: P,
    succeeded: bool,
}

impl<'session, P: FailOriginalProgressV5> OriginalBoundaryV5<'session, P> {
    pub(in crate::handshake) fn new(
        session: &'session mut CurrentRootMountSourceProviderSessionV1,
        progress: P,
    ) -> Self {
        Self {
            session,
            progress,
            succeeded: false,
        }
    }

    pub(in crate::handshake) fn run<R, E>(
        &mut self,
        operation: impl FnOnce(
            &mut CurrentRootMountSourceProviderSessionV1,
            &mut P,
        ) -> Result<R, E>,
    ) -> Result<R, E> {
        self.succeeded = false;
        let result = operation(self.session, &mut self.progress);
        self.succeeded = result.is_ok();

        result
    }
}

impl<P: FailOriginalProgressV5> Drop for OriginalBoundaryV5<'_, P> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.progress.fail();
            self.session.fail_original_catalog_v5();
            self.session.invalidate_native_acquire_commit_v3();
        }
    }
}
