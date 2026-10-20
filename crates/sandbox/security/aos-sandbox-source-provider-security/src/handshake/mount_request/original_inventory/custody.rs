//! Armed failure-only loans for the actual Query Session and progress slots.
//!
//! The private trait groups only failure latching. It supplies no constructor,
//! validation, authority conversion or caller-implemented policy.

use super::*;

/// Groups only latching of the concrete retained progress shapes below.
pub(super) trait FailProgressV6 {
    fn fail(&mut self);
}

impl FailProgressV6 for () {
    fn fail(&mut self) {}
}

impl FailProgressV6 for &mut Option<OriginalInventoryPreparationV6> {
    fn fail(&mut self) {
        if let Some(preparation) = self.as_ref() {
            preparation.failed.set(true);
        }
    }
}

impl FailProgressV6 for &mut OriginalInventoryPreparationV6 {
    fn fail(&mut self) {
        self.failed.set(true);
    }
}

impl FailProgressV6 for (&mut OriginalInventoryPreparationV6, &mut Option<OriginalInventorySendV6>) {
    fn fail(&mut self) {
        self.0.failed.set(true);
        if let Some(send) = self.1.as_ref() {
            send.failed.set(true);
        }
    }
}

impl FailProgressV6 for &mut OriginalInventorySendV6 {
    fn fail(&mut self) {
        self.failed.set(true);
    }
}

impl FailProgressV6 for (&OriginalInventorySendV6, &mut Option<OriginalInventoryReceivedOutcomeV6>) {
    fn fail(&mut self) {
        self.0.failed.set(true);
        if let Some(token) = self.1.as_ref() {
            token.failed.set(true);
        }
    }
}

impl FailProgressV6 for (&OriginalInventorySendV6, &OriginalInventoryReceivedOutcomeV6) {
    fn fail(&mut self) {
        self.0.failed.set(true);
        self.1.failed.set(true);
    }
}

/// Holds real references until the final successful boundary return.
pub(super) struct QueryBoundaryV6<'session, 'original, P: FailProgressV6> {
    session: &'session mut CurrentRootMountSourceProviderSessionV1,
    original: Original<'original>,
    progress: P,
    succeeded: bool,
}

impl<'session, 'original, P: FailProgressV6> QueryBoundaryV6<'session, 'original, P> {
    pub(super) fn new(
        session: &'session mut CurrentRootMountSourceProviderSessionV1,
        original: Original<'original>,
        progress: P,
    ) -> Self {
        Self {
            session,
            original,
            progress,
            succeeded: false,
        }
    }

    pub(super) fn run<R>(
        &mut self,
        operation: impl FnOnce(
            &mut CurrentRootMountSourceProviderSessionV1,
            &mut P,
        ) -> Result<R, SourceProviderSecurityError>,
    ) -> Result<R, SourceProviderSecurityError> {
        self.succeeded = false;
        let result = operation(self.session, &mut self.progress);
        self.succeeded = result.is_ok();

        result
    }
}

impl<P: FailProgressV6> Drop for QueryBoundaryV6<'_, '_, P> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.progress.fail();
            self.session.invalidate_original_inventory_continuation_v6(Some(self.original.1));
        }
    }
}
