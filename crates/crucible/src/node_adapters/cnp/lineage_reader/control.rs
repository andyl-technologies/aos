//! Retains complete selected host state beside its original two-group capsule.

use super::{
    LineageReferenceQualification,
    transport::{OriginalContext, OriginalSender},
};
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    reference_lineage::LineageSourceGuard,
    reference_service::{ReferenceProfile, ReferenceServiceBootstrap},
};
use std::ops::{Deref, DerefMut};

pub(super) use super::super::control::{
    PreparedActivation, PublicWindow, StagedInput, canonical_bytes, content, original_id,
};

/// Owns original selected controls, opaque admissions and all retained proof rows.
///
/// This capsule is transferred whole to its prior host reservation on borrower
/// drop. Neither a native group capsule alone nor a response DTO owns this state.
pub(super) struct ReaderState {
    pub(super) guard: LineageSourceGuard,
    pub(super) runtime: super::super::control::CnpRuntimeCustody,
    pub(super) profile: ReferenceProfile,
    pub(super) bootstrap: ReferenceServiceBootstrap,
    pub(super) realization: Id,
    pub(super) qualification: Box<dyn LineageReferenceQualification>,
    pub(super) collection: Option<crate::node_admission::InstalledConformancePlan>,
    pub(super) supervision: U64,
    pub(super) transport: super::negotiation::ReaderTransport,
    pub(super) input_lineages:
        std::collections::BTreeMap<Id, crate::node_contract::OriginalInputLineage>,
}

impl Deref for ReaderState {
    type Target = super::super::control::CnpRuntimeCustody;
    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

impl DerefMut for ReaderState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.runtime
    }
}

impl ReaderState {
    /// Services the actual original groups while retaining all historical controls.
    ///
    /// # Errors
    /// Retains complete custody on unknown kernel census or signal/wait failure.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        self.quarantine_public()
    }

    pub(super) fn verify_native_custody(&self) -> Result<(), ProviderError> {
        self.transport.verify_registrar(&self.guard)?;
        self.guard
            .with_original_realization(&self.realization, |_| Ok(()))
    }

    pub(super) fn controller(&self) -> Result<OriginalContext<'_>, ProviderError> {
        Ok(OriginalContext::new(
            &self.profile,
            &self.bootstrap,
            &self.guard,
        ))
    }

    pub(super) fn controller_mut(&mut self) -> Result<OriginalSender<'_>, ProviderError> {
        let collecting = self
            .collection
            .as_ref()
            .map(|plan| (self.qualification.as_ref(), plan));
        Ok(OriginalSender::new(&mut self.guard, collecting))
    }

    // Cleanup remains original custody supervision after execution authority is
    // revoked. It cannot enter the normal collecting dispatch path or resume work.
    pub(super) fn cleanup_controller_mut(&mut self) -> Result<OriginalSender<'_>, ProviderError> {
        Ok(OriginalSender::new(&mut self.guard, None))
    }

    pub(super) fn quarantine_public(&mut self) -> Result<bool, ProviderError> {
        self.guard.revoke_read_handles();
        if self.runtime.status == crucible_node_provider::reference_device::DeviceStatus::Reaped {
            return Ok(true);
        }
        if self.runtime.status
            != crucible_node_provider::reference_device::DeviceStatus::Quarantined
        {
            // Every source cleanup is attempted once with original deterministic
            // IDs. Failure retains the same journal and companion custody; polls
            // cannot redispatch a replacement effect or signal its numeric PID.
            self.runtime.status =
                crucible_node_provider::reference_device::DeviceStatus::Quarantined;
            self.close_native_application()?;
        }
        if self.guard.poll_reclamation()? {
            self.runtime.status = crucible_node_provider::reference_device::DeviceStatus::Reaped;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
