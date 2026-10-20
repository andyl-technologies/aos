//! Restores the source runtime before revoking a failed original or Query boundary.
//!
//! The loan parks both attachment states. Its destructor performs only direct
//! ownership restoration and failure latching, never recovery or validation.

use super::*;
use crate::source_acquisition::{FixedMountSourceAcquisitionOwnerV2, SourceAcquisitionRuntimeV2};
use aos_sandbox_source_provider_security::CurrentRootMountSourceProviderSessionV1;

/// Keeps the exact runtime owned throughout fixed-journal reattachment.
pub(super) struct SourceRuntimeLoanV6<'slot, 'journal> {
    return_slot: &'slot mut Option<SourceAcquisitionRuntimeV2>,
    failure_gate: &'slot mut bool,
    detached: Option<SourceAcquisitionRuntimeV2>,
    attached: Option<FixedMountSourceAcquisitionOwnerV2<'journal>>,
    succeeded: bool,
}

impl<'slot, 'journal> SourceRuntimeLoanV6<'slot, 'journal> {
    pub(super) fn new(
        return_slot: &'slot mut Option<SourceAcquisitionRuntimeV2>,
        failure_gate: &'slot mut bool,
    ) -> Self {
        let detached = return_slot.take();

        Self {
            return_slot,
            failure_gate,
            detached,
            attached: None,
            succeeded: false,
        }
    }

    /// Attaches without moving retained custody through a fallible constructor.
    pub(super) fn attach(&mut self, journal: &'journal mut Journal) -> Result<()> {
        if self.detached.is_some() {
            FixedMountSourceAcquisitionOwnerV2::attach_parked_runtime_v6(
                journal,
                &mut self.detached,
                &mut self.attached,
            )
        } else {
            FixedMountSourceAcquisitionOwnerV2::borrow_kind2_parked_v6(
                journal,
                &mut self.attached,
            )
        }
    }

    pub(super) fn operate<R>(
        &mut self,
        operation: impl FnOnce(&mut FixedMountSourceAcquisitionOwnerV2<'journal>) -> Result<R>,
    ) -> Result<R> {
        self.succeeded = false;
        let owner = self.attached
            .as_mut()
            .ok_or_else(|| MountError::State("parked source owner is absent".to_owned()))?;

        let result = operation(owner);
        self.succeeded = result.is_ok();

        result
    }
}

impl Drop for SourceRuntimeLoanV6<'_, '_> {
    fn drop(&mut self) {
        let runtime = match self.attached.take() {
            Some(owner) => Some(owner.into_runtime()),
            None => self.detached.take(),
        };
        *self.return_slot = runtime;
        *self.failure_gate = !self.succeeded;
    }
}

/// Shares failure revocation after the sole source loan restores its actual owner.
pub(super) struct QueryEntryBoundaryV6<'broker, 'session, W> {
    pub(super) broker: &'broker mut MountBroker<W>,
    pub(super) session: &'session mut CurrentRootMountSourceProviderSessionV1,
    succeeded: bool,
}

impl<'broker, 'session, W> QueryEntryBoundaryV6<'broker, 'session, W> {
    pub(super) fn new(
        broker: &'broker mut MountBroker<W>,
        session: &'session mut CurrentRootMountSourceProviderSessionV1,
    ) -> Self {
        Self {
            broker,
            session,
            succeeded: false,
        }
    }

    pub(super) fn finish<R>(&mut self, result: Result<R>) -> Result<R> {
        self.succeeded = result.is_ok();
        result
    }
}

impl<W> Drop for QueryEntryBoundaryV6<'_, '_, W> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.broker.source_runtime_failed = true;
            if let Some(runtime) = self.broker.source_runtime.as_mut() {
                runtime.invalidate_original_inventory_v6(self.session);
            } else {
                self.session.invalidate_original_inventory_continuation_v6(None);
            }
        }
    }
}
