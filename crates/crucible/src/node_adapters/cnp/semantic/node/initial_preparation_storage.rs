//! Observes the same completed initial preparation after its move into a node.
//!
//! The host-query ticket binds the actual Source, plan and read owner. Moved
//! registry and supervisor handles authenticate their original SDK owners; their
//! former stack addresses are not identities. This path creates no Query,
//! Input, Capture, activation or restoration permission.

use super::*;
use crate::node_adapters::cnp::semantic::{
    CnpPreparationStorageScratch, CnpRetainedStorageReport, CnpSemanticConformanceNode,
    PacketCompleteSemanticSource,
};
use crate::node_admission::{CompleteOriginalFreshRestoreHostWindow, InstalledConformancePlan};
use crate::node_contract::RuntimeError;
use crucible_node_provider::{
    ProviderError, connection::OriginalProtocolSupervisor,
    retained_metadata::RetainedProtocolMetadataFacts,
};
use std::{cell::Ref, mem::size_of};

impl CnpSemanticNode {
    fn authenticate_original_initial_node_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), RuntimeError> {
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        source.storage_origin_with_error::<RuntimeError>()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let installed = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if Rc::as_ptr(installed).cast::<()>() != Rc::as_ptr(source).cast::<()>()
            || !std::ptr::eq(installed.installation(), source.installation())
            || !native.completed_ack_protocol_started
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        native.read_owner.original_fresh_query_custody_data()?;
        let runtime = native
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        runtime.dormant_storage_data()?;
        if runtime.quarantined {
            return Err(RuntimeError::OutstandingObligations);
        }
        let registry = self
            .retained_registry
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let supervisor = self
            .retained_supervisor
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let operational = self
            .retained_operational
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let extension = native
            .extension_handshake
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        registry
            .authenticate_original(extension)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let witness = native
            .protocol_supervisor
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let witness = witness.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        witness
            .authenticate_original_operational_handle_data(operational)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // This direct typed observer binds the retained concrete supervisor to
        // the same controller/witness without an erased callback or allocation.
        controller
            .original_live_host_metadata_facts_with_retained_supervisor(supervisor, Some(witness))
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let admission = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let query = admission
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_restoration_query_data(source)?;
        if query.original_data().is_none()
            || query.terminal_data().is_none()
            || query.response_data().is_none()
            || query.report_data().is_none()
            || query.allocation_reference_data().is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()
    }

    /// Matches the actual dormant node to its same original host-query ticket.
    ///
    /// # Errors
    /// Refuses foreign ticket, Source, plan, read owner or incomplete SDK custody.
    pub(crate) fn inspect_original_initial_preparation_data(
        &self,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_initial_node_data(source)?;
        self.preparation
            .authenticate_original_fresh_query_plan_data(plan)?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        ticket.authenticate_original_initial_node_owner_data(
            source,
            plan,
            Rc::as_ptr(&native.read_owner).cast(),
        )
    }

    /// Counts actual node ownership through the exact initial Source visitor.
    ///
    /// # Errors
    /// Refuses foreign or active custody, unresolved owners or finite census bounds.
    pub(crate) fn retained_original_initial_requested_storage_precredit_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        scratch: &CnpPreparationStorageScratch,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.authenticate_original_initial_node_data(source)?;
        self.original_retained_node_selected_precredit_data(
            scratch,
            None,
            None,
            Some(source),
            maximum,
        )
    }
}

impl CnpSemanticConformanceNode {
    /// Inspects the same moved initial preparation without renewing its ticket.
    ///
    /// # Errors
    /// Refuses another Source, plan, read owner, SDK witness or nondormant node.
    pub fn inspect_original_initial_preparation_data(
        &self,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.0
            .inspect_original_initial_preparation_data(ticket, source, plan)
    }

    /// Counts the same node through its exact initial-lifecycle Source visitor.
    ///
    /// # Errors
    /// Refuses foreign or active custody, unavailable witnesses or census bounds.
    pub fn retained_original_initial_requested_storage_precredit_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        scratch: &CnpPreparationStorageScratch,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.0
            .retained_original_initial_requested_storage_precredit_data(source, scratch, maximum)
    }
}

impl CnpSemanticPreparation {
    /// Names the initial-node inspector and its complete typed owning counters.
    ///
    /// # Errors
    /// Refuses checked fixed-layout overflow before any owning observation.
    pub fn original_initial_node_retained_counter_scratch_data() -> Result<usize, RuntimeError> {
        use super::super::packet_complete_source::OriginalCompletedCanonicalAckWorldAdmission;
        let terms = [
            Self::original_conformance_node_retained_counter_scratch_data()?,
            PacketCompleteSemanticSource::original_initial_source_counter_scratch_data(),
            super::super::CnpSemanticLaunchGuard::original_initial_lifecycle_storage_counter_scratch_data(),
            CompleteOriginalFreshRestoreHostWindow::original_initial_node_counter_scratch_data(),
            OriginalCompletedCanonicalAckWorldAdmission::original_restoration_query_counter_scratch_data(),
            size_of::<&CnpSemanticNode>(),
            size_of::<&CnpSemanticPreparation>(),
            size_of::<&CnpPreparationStorageScratch>(),
            size_of::<Option<&Rc<PacketCompleteSemanticSource>>>(),
            size_of::<&Rc<PacketCompleteSemanticSource>>(),
            size_of::<Ref<'static, Option<OriginalProtocolSupervisor>>>(),
            size_of::<Result<Ref<'static, Option<OriginalProtocolSupervisor>>, std::cell::BorrowError>>(),
            size_of::<RetainedProtocolMetadataFacts>(),
            size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>(),
            size_of::<Result<CnpRetainedStorageReport, RuntimeError>>(),
            size_of::<Result<Option<usize>, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<&InstalledConformancePlan>(),
            size_of::<&CompleteOriginalFreshRestoreHostWindow>(),
        ];
        let local = std::mem::size_of_val(&terms)
            .checked_add(size_of::<std::slice::Iter<'static, usize>>())
            .ok_or(RuntimeError::ResourceLimit)?;
        terms.iter().try_fold(local, |sum, term| {
            sum.checked_add(*term).ok_or(RuntimeError::ResourceLimit)
        })
    }
}
