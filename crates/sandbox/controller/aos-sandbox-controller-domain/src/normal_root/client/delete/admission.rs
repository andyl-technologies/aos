//! Retains the actual preparatory exchange through durable Delete acceptance.
//!
//! The complete live Root original lends model DATA only after its actual
//! signed-plan/192/native conjunction. The same Bank loan must retain this
//! client beside the exclusive Source/C17 scope through readiness, Controller
//! COMMIT readback and Source ControllerCommitted. No decoded frame creates
//! an append lender, effect permission or completed cleanup.

use super::*;
use aos_sandbox_model::{ObjectDigest, OperationId, RawPairedClockSample};

mod host_confirmation;
mod cleanup_current;
mod mount;
mod completion;
mod completion_exchange;
pub(super) use mount::DeleteMountResourceBindingDataV4;

#[derive(Clone, Copy)]
pub(crate) struct DeleteSourceClockBoundDataV3 {
    pub(crate) after: RawPairedClockSample,
    pub(crate) expires: i64,
    pub(crate) cutoff: u64,
}

impl DeleteSourceClockBoundDataV3 {
    pub(crate) fn require_sample_v3(&self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        self.after.validate_later_sample(sample).map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        if sample.wall_seconds() >= self.expires || sample.boottime_nanoseconds() >= self.cutoff {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

/// Describes the actual completed exchange for pure Source plan construction.
///
/// Private fields keep its normal producer intrinsic to the held Root client.
/// This is not a native authority token: native callers separately retain and
/// recheck the same actual Root/Source/C17 originals at every crossing.
pub(crate) struct DeleteSourceBindingDataV3 {
    project: aos_sandbox_model::ProjectId,
    operation: OperationId,
    batch: ObjectDigest,
    sandbox: [u8; 16],
    public_request: ObjectDigest,
    root_plan: ObjectDigest,
    source_pending: [u8; 64],
    after: RawPairedClockSample,
    expires: i64,
    cutoff: u64,
}

impl DeleteSourceBindingDataV3 {
    pub(crate) fn clock_bound_data_v3(&self) -> DeleteSourceClockBoundDataV3 {
        DeleteSourceClockBoundDataV3 { after: self.after, expires: self.expires, cutoff: self.cutoff }
    }

    pub(crate) fn coordinates_data_v3(&self) -> (aos_sandbox_model::ProjectId, OperationId, ObjectDigest) {
        (self.project, self.operation, self.batch)
    }

    pub(crate) fn require_pending_data_v3(
        &self,
        pending: &crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'_>,
    ) -> Result<(), JournalError> {
        if pending.coordinates() != (self.project, self.operation, self.batch) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn sandbox_data_v3(&self) -> [u8; 16] { self.sandbox }

    pub(crate) fn public_request_data_v3(&self) -> ObjectDigest { self.public_request }

    pub(crate) fn root_plan_data_v3(&self) -> ObjectDigest { self.root_plan }

    pub(crate) fn source_pending_data_v3(&self) -> &[u8; 64] { &self.source_pending }

    /// Checks the unchanged accepted horizon using the real latest sample.
    pub(crate) fn require_later_clock_data_v3(
        &self,
        later: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.after.validate_later_sample(later)
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        if later.wall_seconds() >= self.expires || later.boottime_nanoseconds() >= self.cutoff {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

impl RootDeleteClientOriginalV1<'_> {
    /// Selects the actual 192-bound signed26, never supplied approval DATA.
    pub(crate) fn current_source_binding_data_v3(
        &self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<DeleteSourceBindingDataV3, Cause> {
        if self.first.is_some() || self.terminal_complete || self.turn.is_some() {
            return Err(self.closed.into());
        }
        self.require_same_pending(fence, controller, launch)?;
        let approved = self.preparatory_approval_complete[0].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let signed = self.resource_signing_complete[0].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let received = self.resource_draft_complete[0].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let draft = aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::
            DeleteRootResourceDraftDataV2::decode_v2(&received.bytes)?;
        let context = aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::
            DeleteRootResourceContextDataV2::decode_v2(draft.context)?;
        let batch = DeleteBatchViewV1::decode(fence.batch_bytes()?)
            ?;
        let aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(sandbox) =
            batch.root()? else { return Err(self.closed.into()); };
        let signed_data = aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::
            DeleteRootResourceSignedDataV2 { draft: &signed.draft_digest,
                canonical_signature: signed.signed.canonical_signature() };
        approved.approval.require_resources_v3(received.frame, draft, signed_data)
            ?;
        let open = self.open_data()?;
        let challenge = self.challenge.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        if signed.preparation.method_v2() != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG {
            return Err(self.closed.into());
        }
        let expires = open.authorization_expires.min(context.policy_expires_seconds)
            .min(signed.signed.plan().expires_seconds()).min(signed.lease.authority_expires_seconds());
        let binding = DeleteSourceBindingDataV3 {
            project: batch.project(), operation: batch.operation(),
            batch: ObjectDigest::from_bytes(aos_sandbox_protocol::domain_ledger::delete_batch::
                native_value_digest(batch.bytes())), sandbox: *sandbox.as_bytes(),
            public_request: ObjectDigest::from_bytes(batch.request_digest()), root_plan: signed.signed.digest(),
            source_pending: *fence.native_position_data_v1()?,
            after: approved.after_clock, expires, cutoff: challenge.source.cutoff,
        };
        binding.require_later_clock_data_v3(approved.after_clock)?;
        Ok(binding)
    }
}

use super::initial_inventory::RootDeleteClientInitialOriginalV2;
use crate::lifecycle::delete_pending::{DeleteSourceReadinessPhaseV3, SourceDeleteReadinessPlanV3};

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
pub(super) struct DeleteApplyResourceBindingDataV3 {
    pub(super) current: aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3,
    pub(super) catalog: aos_sandbox_protocol::semantics::CatalogBindingV1,
    pub(super) sender_before: RawPairedClockSample,
}

#[derive(Clone, Copy)]
pub(super) struct DeleteNetworkResourceBindingDataV4 {
    pub(super) predecessor: aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootNetworkPredecessorDataV4,
    pub(super) before: RawPairedClockSample,
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn require_resource_purpose_v4(&self, purpose: DeleteResourcePurposeV3)
        -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some() || self.terminal_complete || self.resource_purpose != purpose {
            Err(self.closed)
        } else { Ok(()) }
    }

    pub(crate) fn begin_network_resource_exchange_once_v4(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        preparation: &crate::DeleteStoragePreparationIoOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some() || self.terminal_complete || self.turn.is_some()
            || self.resource_purpose != DeleteResourcePurposeV3::Apply7
            || self.network_activation_admission.is_some() || self.network_activation.is_some() {
            self.first.get_or_insert(First::Reentry); return Err(self.closed);
        }
        self.network_activation_admission = Some((|| {
            self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))?;
            let bytes = std::mem::size_of::<DeleteNetworkResourceBindingDataV4>().checked_mul(3)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<blake3::Hasher>().checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        if !matches!(self.network_activation_admission, Some(Ok(()))) {
            self.first.get_or_insert(First::NetworkActivationAdmission); return Err(self.closed);
        }
        self.network_activation = Some((|| {
            self.require_apply_resource_approval_v3()?;
            let current = self.apply_activation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?.current;
            if preparation.completed_native_v3()? != &current.session {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let approval = self.preparatory_approval_complete[1].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?.approval;
            let predecessor = aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootNetworkPredecessorDataV4 {
                current, approval,
            };
            predecessor.commitment_v4()?;
            Ok(DeleteNetworkResourceBindingDataV4 { predecessor, before: approval.clock })
        })());
        if !matches!(self.network_activation, Some(Ok(_))) {
            self.first.get_or_insert(First::NetworkActivation); return Err(self.closed);
        }
        self.resource_purpose = DeleteResourcePurposeV3::Network9;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum RootAdmissionFirst { Geometry, Funding, Binding, Association, Entry, Before, Frontier, Time, Body, After, Disposal, CurrentEncoding, CurrentSend, CleanupCurrent, Terminal, TerminalCore, Reentry }

/// Owns fresh native Root/C bookends for the finite Source readiness schedule.
pub(super) struct DeleteSourceAcceptanceRootStateV3 {
    binding: Option<Result<DeleteSourceBindingDataV3, Cause>>,
    cursor: u8,
    mount_retired: bool,
    cleanup: cleanup_current::CleanupCurrentSendOriginalV4,
    terminal: completion_exchange::SourceCompletionExchangeOriginalV4,
    terminal_core: Option<crate::journal::ControllerDeleteTerminalOriginalV4>,
    current_entry: Option<Result<(), RootDeleteClientClosedV1>>,
    current_encoding: Option<Result<[u8;352], Cause>>,
    current_bytes: [u8;352],
    current_io: crate::policy_compiler::bounded_stream_io::FixedDeadlineStreamIoV1<352>,
    current_send: Option<Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>,
    current_after: Option<Result<(), RootDeleteClientClosedV1>>,
    demand: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), JournalError>>,
    association: Option<Result<(), JournalError>>,
    entry: Option<Result<(), JournalError>>,
    interval: Option<Box<RootDeleteClientInitialOriginalV2>>,
    frontier: Option<Result<(), JournalError>>,
    before_time: Option<Result<(), Cause>>,
    after_time: Option<Result<(), Cause>>,
    before: Option<RawPairedClockSample>,
    after: Option<RawPairedClockSample>,
    disposal: Option<Result<(), JournalError>>,
    first: Option<RootAdmissionFirst>,
    accepted: Option<Result<[u8; 64], Cause>>,
    accepted_current: Option<Result<(), Cause>>,
}

impl DeleteSourceAcceptanceRootStateV3 {
    fn fixed_receiving_demand_v3(batch_bytes: usize) -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(DeleteBatchViewV1::decode_receiving_bytes_v1(batch_bytes)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let names = DeleteBatchViewV1::nested_decode_metadata_entries_v1(batch_bytes)
            .and_then(|names| u64::try_from(names).ok()).ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::MetadataEntries, names))
    }

    fn new() -> Self {
        Self { binding: None, cursor: 0, mount_retired: false, cleanup: Default::default(), terminal: Default::default(), terminal_core: None, current_entry: None, current_encoding: None, current_bytes: [0;352],
            current_io: Default::default(), current_send: None, current_after: None, demand: None, funding: None, association: None, entry: None,
            interval: None, frontier: None, before_time: None, after_time: None, before: None, after: None,
            disposal: None, first: None, accepted: None, accepted_current: None }
    }

    pub(super) fn c_failure_selected_v3(&self) -> bool {
        matches!(self.first, Some(RootAdmissionFirst::Funding | RootAdmissionFirst::Entry | RootAdmissionFirst::Frontier | RootAdmissionFirst::Disposal))
            || matches!(self.first, Some(RootAdmissionFirst::CleanupCurrent)) && self.cleanup.funding_failed_v4()
            || matches!(self.first, Some(RootAdmissionFirst::Terminal)) && self.terminal.funding_failed_v4()
            || matches!(self.first, Some(RootAdmissionFirst::TerminalCore))
                && self.terminal_core.as_ref().is_some_and(|core| core.financial_failure_is_selected_v4())
            || matches!(self.first, Some(RootAdmissionFirst::Before | RootAdmissionFirst::After))
                && self.interval.as_ref().is_some_and(|interval| interval.c_failure_selected())
    }

    pub(super) fn property_failure_view_v3(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(RootAdmissionFirst::Before | RootAdmissionFirst::After)) {
            self.interval.as_ref()?.property_failure_view()
        } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            RootAdmissionFirst::Geometry => cause(&self.demand),
            RootAdmissionFirst::Funding => cause(&self.funding),
            RootAdmissionFirst::Binding => self.binding.as_ref()?.as_ref().err()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            RootAdmissionFirst::Association => self.accepted_current.as_ref().and_then(|result| result.as_ref().err())
                .or_else(|| self.accepted.as_ref()?.as_ref().err())
                .map(|cause| cause.as_ref() as &(dyn Error + 'static))
                .or_else(|| cause(&self.association)),
            RootAdmissionFirst::Entry => cause(&self.entry),
            RootAdmissionFirst::Frontier => cause(&self.frontier),
            RootAdmissionFirst::Before | RootAdmissionFirst::After => self.interval.as_ref()
                .and_then(|interval| interval.failure())
                .or_else(|| self.after_time.as_ref()?.as_ref().err()
                    .map(|cause| cause.as_ref() as &(dyn Error + 'static))),
            RootAdmissionFirst::Time => self.before_time.as_ref()?.as_ref().err()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            RootAdmissionFirst::CurrentEncoding => self.current_encoding.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            RootAdmissionFirst::CurrentSend => self.current_io.failure().or_else(|| cause(&self.current_send)),
            RootAdmissionFirst::CleanupCurrent => self.cleanup.failure_v4(),
            RootAdmissionFirst::Terminal => self.terminal.failure_v4(),
            RootAdmissionFirst::TerminalCore => self.terminal_core.as_ref()?.failure(),
            RootAdmissionFirst::Disposal => cause(&self.disposal),
            RootAdmissionFirst::Body | RootAdmissionFirst::Reentry => None,
        }
    }
}

impl RootDeleteClientOriginalV1<'_> {
    /// Pays and parks the actual Root-bound readiness header before its decode.
    pub(crate) fn prepare_source_admission_once_v3(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some() || self.source_admission_admission.is_some() || self.source_admission.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        self.source_admission_admission = Some((|| {
            let fixed = DeleteSourceAcceptanceRootStateV3::fixed_receiving_demand_v3(fence.batch_bytes()?.len())?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(), fixed)
        })());
        if !matches!(self.source_admission_admission, Some(Ok(()))) {
            self.first = Some(First::SourceAdmissionFunding);
            return Err(self.closed);
        }
        self.source_admission = Some(Box::new(DeleteSourceAcceptanceRootStateV3::new()));
        let binding = self.current_source_binding_data_v3(fence, controller, launch);
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.binding = Some(binding);
        if !matches!(state.binding, Some(Ok(_))) {
            state.first = Some(RootAdmissionFirst::Binding);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        Ok(())
    }

    /// Lends only the paid actual exchange DATA for the same native caller.
    pub(crate) fn source_binding_data_v3(&self) -> Result<&DeleteSourceBindingDataV3, RootDeleteClientClosedV1> {
        if self.first.is_some() { return Err(self.closed); }
        self.source_admission.as_ref().filter(|state| state.first.is_none())
            .and_then(|state| state.binding.as_ref()).and_then(|result| result.as_ref().ok())
            .ok_or(self.closed)
    }

    pub(crate) fn begin_controller_admission_interval_once_v3(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), RootDeleteClientClosedV1> {
        fence.require_source_ready_v3().map_err(|_| self.closed)?;
        self.begin_admission_interval_once_v3(fence, controller, launch,
            RootNativeAdmissionPhaseV3::ControllerAdmission)
    }

    pub(crate) fn begin_source_controller_committed_interval_once_v3(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.begin_admission_interval_once_v3(fence, controller, launch,
            RootNativeAdmissionPhaseV3::SourceControllerCommitted(accepted))
    }

    fn require_accepted_pending_v3(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), JournalError> {
        let comparison = (|| -> Result<(), Cause> {
            let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let held = state.accepted.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let actual = accepted.completed_native_v3(controller, fence)?;
            if actual != held { return Err(JournalError::StaleAuthoritySnapshot.into()); }
            let (funding, _, _) = fence.controller_accepted_cut_v3(controller, launch,
                self.profile.lower_original_v1(), accepted)?;
            let open = self.open_data()?;
            open.require_batch_v2(fence.batch_bytes()?)?;
            let (clock, expires) = fence.authorization_horizon_v1();
            let same_funding = self.funding.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|bytes| OperationIntakeFundingDataV1::decode_v1(bytes)
                    .is_ok_and(|held| held == funding));
            if open.authorization_clock != clock || open.authorization_expires != expires
                || &open.source_pending != fence.native_position_data_v1()? || !same_funding {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(())
        })();
        let state = self.source_admission.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        state.accepted_current = Some(comparison);
        if matches!(state.accepted_current, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn retire_controller_admission_interval_once_v3(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != 3
            || state.accepted.is_some() || !matches!(state.after_time, Some(Ok(())))
            || state.interval.as_ref().is_none_or(|interval| !interval.completed_interval_v2()) {
            return Err(self.closed);
        }
        state.accepted = Some(accepted.completed_native_v3(controller, fence).copied());
        if !matches!(state.accepted, Some(Ok(_))) {
            state.first = Some(RootAdmissionFirst::Association);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        state.disposal = Some((|| {
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(state.interval.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(state.disposal, Some(Ok(()))) {
            state.first = Some(RootAdmissionFirst::Disposal);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        drop(self.turn.take());
        state.binding.as_mut().and_then(|result| result.as_mut().ok()).ok_or(self.closed)?.after =
            state.after.ok_or(self.closed)?;
        state.cursor = 4;
        Ok(())
    }

    /// Opens one finite paid Source phase using the same Root/C native kernel.
    pub(crate) fn begin_source_readiness_interval_once_v3(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        phase: DeleteSourceReadinessPhaseV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if phase == DeleteSourceReadinessPhaseV3::ControllerCommitted { return Err(self.closed); }
        self.begin_admission_interval_once_v3(fence, controller, launch,
            RootNativeAdmissionPhaseV3::Source(phase))
    }

    fn begin_admission_interval_once_v3(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        phase: RootNativeAdmissionPhaseV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let expected = match phase {
            RootNativeAdmissionPhaseV3::Source(phase) => source_phase_index(phase),
            RootNativeAdmissionPhaseV3::ControllerAdmission => 3,
            RootNativeAdmissionPhaseV3::SourceControllerCommitted(_) => 4,
            RootNativeAdmissionPhaseV3::StoragePreparation(_) => 5,
            RootNativeAdmissionPhaseV3::PreparationCurrent(_) => 6,
            RootNativeAdmissionPhaseV3::NetworkApply(_) => 7,
            RootNativeAdmissionPhaseV3::HostConfirmation(_) => 8,
            RootNativeAdmissionPhaseV3::CleanupCurrent(_) => 9,
            RootNativeAdmissionPhaseV3::MountReap(_) => 9,
            RootNativeAdmissionPhaseV3::StorageApply(_) => 10,
            RootNativeAdmissionPhaseV3::SourceCompletion(phase, _) => 11 + phase.index_v4() as u8,
            RootNativeAdmissionPhaseV3::SourceFinal(_) => 13,
        };
        let association = match phase {
            RootNativeAdmissionPhaseV3::SourceControllerCommitted(accepted)
                | RootNativeAdmissionPhaseV3::StoragePreparation(accepted)
                | RootNativeAdmissionPhaseV3::StorageApply(accepted)
                | RootNativeAdmissionPhaseV3::NetworkApply(accepted)
                | RootNativeAdmissionPhaseV3::HostConfirmation(accepted)
                | RootNativeAdmissionPhaseV3::CleanupCurrent(accepted)
                | RootNativeAdmissionPhaseV3::MountReap(accepted)
                | RootNativeAdmissionPhaseV3::SourceCompletion(_, accepted)
                | RootNativeAdmissionPhaseV3::SourceFinal(accepted)
                | RootNativeAdmissionPhaseV3::PreparationCurrent(accepted) =>
                self.require_accepted_pending_v3(fence, controller, launch, accepted),
            _ => self.require_same_pending(fence, controller, launch),
        };
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != expected
            || state.interval.is_some() || self.turn.is_some() {
            state.first.get_or_insert(RootAdmissionFirst::Reentry);
            return Err(self.closed);
        }
        state.association = Some(association);
        if !matches!(state.association, Some(Ok(()))) {
            state.first = Some(RootAdmissionFirst::Association);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        state.demand = Some(RootDeleteClientInitialOriginalV2::receiving_recipe_v2(self.profile, 0, 0)
            .and_then(|demand| demand.checked_add(Self::peer_traffic_v1(2)?)
                .map_err(JournalError::ReceivingAccounting)));
        let demand = match state.demand.as_ref().and_then(|result| result.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => { state.first = Some(RootAdmissionFirst::Geometry); self.first = Some(First::SourceAdmission); return Err(self.closed); }
        };
        state.funding = Some(fence.reserve_preaccept_additional_v1(controller, launch,
            self.profile.lower_original_v1(), demand));
        if !matches!(state.funding, Some(Ok(()))) {
            state.first = Some(RootAdmissionFirst::Funding);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        match fence.prepare_preaccept_turn_v1(controller, launch,
            self.profile.lower_original_v1(), ResourceVector::ZERO) {
            Ok(turn) => { self.turn = Some(turn); state.entry = Some(Ok(())); }
            Err(error) => {
                state.entry = Some(Err(error));
                state.first = Some(RootAdmissionFirst::Entry);
                self.first = Some(First::SourceAdmission);
                return Err(self.closed);
            }
        }
        state.interval = Some(Box::new(RootDeleteClientInitialOriginalV2::new()));
        state.frontier = None;
        state.before = None;
        state.after = None;
        state.before_time = None;
        state.after_time = None;
        state.disposal = None;
        if let (Some(interval), Some(stable), Some(turn)) =
            (state.interval.as_mut(), self.stable.as_ref(), self.turn.as_mut()) {
            interval.begin_native_interval_once_v2(&mut self.connection, stable, turn,
                controller, self.profile, open, challenge);
            if interval.before_sample_data_v2().is_err() {
                state.first.get_or_insert(RootAdmissionFirst::Before);
            }
            state.before_time = Some((|| {
                let sample = interval.before_sample_data_v2()?;
                state.binding.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?.require_later_clock_data_v3(sample)?;
                state.binding.as_mut().and_then(|result| result.as_mut().ok())
                    .ok_or(JournalError::ProtectedBoundary)?.after = sample;
                state.before = Some(sample);
                Ok(())
            })());
            if !matches!(state.before_time, Some(Ok(()))) {
                state.first.get_or_insert(RootAdmissionFirst::Time);
                interval.mark_external_primary_refusal_v2();
            }
        }
        // A reached native before returns the attempt even on refusal, so the
        // enclosing loan can always run the independently prepaid afters.
        Ok(())
    }

    pub(crate) fn require_source_readiness_before_v3(&mut self,
        phase: DeleteSourceReadinessPhaseV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != source_phase_index(phase)
            || state.before.is_none() || state.after.is_some() {
            return Err(self.closed);
        }
        self.require_admission_native_frontier_v3().map_err(|_| self.closed)
    }

    pub(crate) fn require_controller_admission_before_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        fence.require_source_ready_v3()?;
        self.require_same_pending(fence, controller, launch)?;
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != 3
            || state.before.is_none() || state.after.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let bound = state.binding.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.clock_bound_data_v3();
        self.require_admission_native_frontier_v3()?;
        Ok(bound)
    }

    fn require_admission_native_frontier_v3(&mut self) -> Result<(), JournalError> {
        if self.first.is_some() || self.source_admission.as_ref().is_none_or(|state| state.first.is_some()) {
            return Err(JournalError::ProtectedBoundary);
        }
        let frontier = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .require_prepaid_delete_plan_signing_frontier_v2().map_err(JournalError::ControllerNative);
        let state = self.source_admission.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        state.frontier = Some(frontier);
        if !matches!(state.frontier, Some(Ok(()))) {
            state.first.get_or_insert(RootAdmissionFirst::Frontier);
            self.first.get_or_insert(First::SourceAdmission);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn refuse_source_readiness_primary_v3(&mut self) {
        if let Some(state) = self.source_admission.as_mut() {
            state.first.get_or_insert(RootAdmissionFirst::Body);
            if let Some(interval) = state.interval.as_mut() { interval.mark_external_primary_refusal_v2(); }
        }
    }

    /// Runs the already-paid Root/C after independently of the Source body.
    pub(crate) fn finish_source_readiness_interval_once_v3(&mut self, controller: &mut Journal)
        -> Result<(), RootDeleteClientClosedV1> {
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        let interval = state.interval.as_mut().ok_or(self.closed)?;
        if state.after_time.is_some() { return Err(self.closed); }
        if let (Some(stable), Some(turn)) = (self.stable.as_ref(), self.turn.as_mut()) {
            interval.finish_native_interval_once_v2(&mut self.connection, stable, turn,
                controller, self.profile, open, challenge);
        }
        state.after_time = Some((|| {
            let sample = interval.after_sample_data_v2()?;
            state.binding.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?.require_later_clock_data_v3(sample)?;
            if let Some(before) = state.before { before.validate_later_sample(sample)?; }
            state.after = Some(sample);
            Ok(())
        })());
        if !interval.completed_interval_v2() || !matches!(state.after_time, Some(Ok(()))) {
            state.first.get_or_insert(RootAdmissionFirst::After);
        }
        if state.first.is_none() {
            Ok(())
        } else {
            self.first.get_or_insert(First::SourceAdmission);
            Err(self.closed)
        }
    }

    pub(crate) fn require_source_readiness_after_v3(&self,
        plan: &SourceDeleteReadinessPlanV3,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        controller.ensure_healthy()?;
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let binding = state.binding.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        plan.require_binding_data_v3(binding)?;
        plan.require_before_v3(plan.source_before_data_v3(), controller.snapshot_sequence())?;
        if self.first.is_some() || state.first.is_some() || state.cursor != source_phase_index(plan.phase_v3())
            || state.after.is_none() || !matches!(state.after_time, Some(Ok(())))
            || state.interval.as_ref().is_none_or(|interval| !interval.completed_interval_v2()) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_source_readiness_post_clock_v3(&self,
        source_latest: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let after = state.after.ok_or(JournalError::ProtectedBoundary)?;
        source_latest.validate_later_sample(after).map_err(|_| JournalError::StaleAuthoritySnapshot)
    }

    /// Reuses native scratch only after the same Source phase physically closes.
    pub(crate) fn retire_source_readiness_interval_once_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        phase: DeleteSourceReadinessPhaseV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        fence.require_source_readiness_phase_complete_v3(phase).map_err(|_| self.closed)?;
        if state.first.is_some() || state.cursor != source_phase_index(phase) || state.after.is_none() {
            return Err(self.closed);
        }
        state.disposal = Some((|| {
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(state.interval.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(state.disposal, Some(Ok(()))) {
            state.first = Some(RootAdmissionFirst::Disposal);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        drop(self.turn.take());
        state.cursor = state.cursor.checked_add(1).ok_or(self.closed)?;
        // Preserve the immediately preceding actual sample as the next lower
        // clock bound, retaining the original absolute cutoff and wall expiry.
        state.binding.as_mut().and_then(|result| result.as_mut().ok()).ok_or(self.closed)?.after =
            state.after.ok_or(self.closed)?;
        Ok(())
    }
}

fn source_phase_index(phase: DeleteSourceReadinessPhaseV3) -> u8 {
    match phase {
        DeleteSourceReadinessPhaseV3::Binding => 0,
        DeleteSourceReadinessPhaseV3::Prepared => 1,
        DeleteSourceReadinessPhaseV3::Ready => 2,
        DeleteSourceReadinessPhaseV3::ControllerCommitted => 4,
    }
}

#[derive(Clone, Copy)]
enum RootNativeAdmissionPhaseV3<'accepted> {
    Source(DeleteSourceReadinessPhaseV3),
    ControllerAdmission,
    SourceControllerCommitted(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    StoragePreparation(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    StorageApply(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    NetworkApply(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    HostConfirmation(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    CleanupCurrent(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    MountReap(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    SourceCompletion(crate::lifecycle::delete_pending::DeleteSourceCompletionPhaseV4,
        &'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    SourceFinal(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
    PreparationCurrent(&'accepted crate::journal::ControllerDeleteAdmissionOriginalV3),
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn begin_network_apply_interval_once_v4(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.require_network_resource_approval_v4().map_err(|_| self.closed)?;
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))
            .map_err(|_| self.closed)?;
        self.begin_storage_interval_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::Network9)
    }

    pub(crate) fn begin_storage_preparation_interval_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.begin_storage_interval_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::Preparation26)
    }

    pub(crate) fn begin_storage_apply_interval_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.require_storage_cleanup_successors_v4().map_err(|_| self.closed)?;
        self.require_apply_resource_approval_v3().map_err(|_| self.closed)?;
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))
            .map_err(|_| self.closed)?;
        self.begin_storage_interval_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::Apply7)
    }

    fn begin_storage_interval_inner_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        purpose: DeleteResourcePurposeV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        fence.require_source_controller_committed_v3().map_err(|_| self.closed)?;
        let phase = match purpose {
            DeleteResourcePurposeV3::MountReap62 => RootNativeAdmissionPhaseV3::MountReap(accepted),
            DeleteResourcePurposeV3::Preparation26 => RootNativeAdmissionPhaseV3::StoragePreparation(accepted),
            DeleteResourcePurposeV3::Apply7 => RootNativeAdmissionPhaseV3::StorageApply(accepted),
            DeleteResourcePurposeV3::Network9 => RootNativeAdmissionPhaseV3::NetworkApply(accepted),
        };
        self.begin_admission_interval_once_v3(fence, controller, launch, phase)
    }

    pub(crate) fn require_storage_preparation_before_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        self.require_storage_before_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::Preparation26)
    }

    pub(crate) fn require_storage_apply_before_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        self.require_storage_cleanup_successors_v4()?;
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))?;
        self.require_apply_resource_approval_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        self.require_storage_before_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::Apply7)
    }

    pub(crate) fn require_network_apply_before_v4(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))?;
        self.require_network_resource_approval_v4().map_err(|_| JournalError::ProtectedBoundary)?;
        self.require_storage_before_inner_v3(fence, controller, launch, accepted, DeleteResourcePurposeV3::Network9)
    }

    fn require_storage_before_inner_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        purpose: DeleteResourcePurposeV3,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        fence.require_source_controller_committed_v3()?;
        self.require_accepted_pending_v3(fence, controller, launch, accepted)?;
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != storage_phase_index_v3(purpose)?
            || state.before.is_none() || state.after.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut bound = state.binding.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.clock_bound_data_v3();
        if matches!(purpose, DeleteResourcePurposeV3::Apply7 | DeleteResourcePurposeV3::Network9 | DeleteResourcePurposeV3::MountReap62) {
            let signed = self.resource_signing_complete[resource_slot_v3(purpose)].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            bound.expires = bound.expires.min(signed.signed.plan().expires_seconds())
                .min(signed.lease.authority_expires_seconds());
            bound.require_sample_v3(bound.after)?;
        }
        self.require_admission_native_frontier_v3()?;
        Ok(bound)
    }

    pub(crate) fn storage_preparation_native_turn_v3(&self) -> Result<u64, JournalError> {
        self.turn.as_ref().map(|turn| turn.native_turn_ordinal_data_v3())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_storage_preparation_after_v3(&self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        latest: RawPairedClockSample,
    ) -> Result<(), Cause> {
        self.require_storage_after_inner_v3(fence, controller, accepted, latest, DeleteResourcePurposeV3::Preparation26)
    }

    pub(crate) fn require_storage_apply_after_v3(&self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        latest: RawPairedClockSample,
    ) -> Result<(), Cause> {
        self.require_apply_resource_approval_v3()?;
        self.require_storage_after_inner_v3(fence, controller, accepted, latest, DeleteResourcePurposeV3::Apply7)
    }

    pub(crate) fn require_network_apply_after_v4(&self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        latest: RawPairedClockSample,
    ) -> Result<(), Cause> {
        self.require_network_resource_approval_v4()?;
        self.require_storage_after_inner_v3(fence, controller, accepted, latest, DeleteResourcePurposeV3::Network9)
    }

    fn require_storage_after_inner_v3(&self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        latest: RawPairedClockSample, purpose: DeleteResourcePurposeV3,
    ) -> Result<(), Cause> {
        fence.require_source_controller_committed_v3()?;
        accepted.completed_native_v3(controller, fence)?;
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let after = state.after.ok_or(JournalError::ProtectedBoundary)?;
        latest.validate_later_sample(after)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != storage_phase_index_v3(purpose)?
            || !matches!(state.after_time, Some(Ok(())))
            || state.interval.as_ref().is_none_or(|interval| !interval.completed_interval_v2()) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    pub(crate) fn preparation_request_bound_v3(&self) -> Option<usize> {
        self.storage_request_bound_inner_v3(DeleteResourcePurposeV3::Preparation26)
    }

    pub(crate) fn apply_request_bound_v3(&self) -> Option<usize> {
        self.require_storage_cleanup_successors_v4().ok()?;
        self.require_apply_resource_approval_v3().ok()?;
        self.storage_request_bound_inner_v3(DeleteResourcePurposeV3::Apply7)
    }

    pub(crate) fn network_request_bound_v4(&self) -> Option<usize> {
        self.require_network_resource_approval_v4().ok()?;
        self.storage_request_bound_inner_v3(DeleteResourcePurposeV3::Network9)
    }

    fn storage_request_bound_inner_v3(&self, purpose: DeleteResourcePurposeV3) -> Option<usize> {
        let receipt = self.resource_signing_complete[resource_slot_v3(purpose)].as_ref()?.as_ref().ok()?;
        let body = usize::try_from(receipt.signed.plan().grants().first()?.maximum_request_bytes()).ok()?;
        let fields = [body, receipt.signed.canonical_plan().len(), receipt.signed.canonical_signature().len(),
            receipt.lease.canonical_lease().len(), receipt.lease.canonical_signature().len()];
        delete_preparation_packet_bound_v3(fields)
    }

    pub(crate) fn preparation_request_envelope_v3(&self) -> Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope, Cause> {
        self.storage_request_envelope_inner_v3(DeleteResourcePurposeV3::Preparation26)
    }

    pub(crate) fn apply_request_envelope_v3(&self) -> Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope, Cause> {
        self.require_apply_resource_approval_v3()?;
        self.storage_request_envelope_inner_v3(DeleteResourcePurposeV3::Apply7)
    }

    pub(crate) fn network_request_envelope_v4(&self) -> Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope, Cause> {
        self.require_network_resource_approval_v4()?;
        self.storage_request_envelope_inner_v3(DeleteResourcePurposeV3::Network9)
    }

    fn storage_request_envelope_inner_v3(&self, purpose: DeleteResourcePurposeV3)
        -> Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope, Cause> {
        use buffa::Message as _;
        let receipt = self.resource_signing_complete[resource_slot_v3(purpose)].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let cutoff = self.source_admission.as_ref().and_then(|state| state.binding.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?.cutoff;
        let body = aos_sandbox_protocol::dispatch_template::inject_deadline(
            receipt.preparation.deadline_free_body_v2(), cutoff)?;
        let protocol = match purpose {
            DeleteResourcePurposeV3::MountReap62 => aos_sandbox_model::ProtocolId::MountBroker,
            DeleteResourcePurposeV3::Network9 => aos_sandbox_model::ProtocolId::NetworkBroker,
            DeleteResourcePurposeV3::Preparation26 | DeleteResourcePurposeV3::Apply7 => aos_sandbox_model::ProtocolId::StorageBroker,
        };
        let bytes = aos_sandbox_protocol::encode_authorized_request_envelope(
            protocol, receipt.preparation.method_v2(), &body, &[],
            aos_sandbox_protocol::AuthorizationArtifactBytes {
                broker_plan: receipt.signed.canonical_plan(), broker_plan_signature: receipt.signed.canonical_signature(),
                ownership_lease: receipt.lease.canonical_lease(), ownership_lease_signature: receipt.lease.canonical_signature(),
            })?;
        Ok(aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope::decode_from_slice(&bytes)?)
    }

    pub(crate) fn require_preparation_inventory_v3(&self,
        cut: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), Cause> {
        let approved = self.resource_draft_complete[0].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if cut.role != 3 || cut.owner_cut_data_v2()? != approved.frame.owners[2] {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok(())
    }

    pub(crate) fn require_network_inventory_v4(&self,
        cut: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), Cause> {
        self.require_network_resource_approval_v4()?;
        let approved = self.resource_draft_complete[2].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if cut.role != 4 || cut.owner_cut_data_v2()? != approved.frame.owners[3] {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok(())
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn retire_network_apply_interval_once_v4(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), Cause> {
        self.require_network_resource_approval_v4()?;
        self.retire_storage_interval_inner_v3(fence, controller, accepted, DeleteResourcePurposeV3::Network9)
    }

    pub(crate) fn retire_storage_preparation_interval_once_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), Cause> {
        self.retire_storage_interval_inner_v3(fence, controller, accepted, DeleteResourcePurposeV3::Preparation26)
    }

    pub(crate) fn retire_storage_apply_interval_once_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), Cause> {
        self.require_apply_resource_approval_v3()?;
        self.retire_storage_interval_inner_v3(fence, controller, accepted, DeleteResourcePurposeV3::Apply7)
    }

    fn retire_storage_interval_inner_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        purpose: DeleteResourcePurposeV3,
    ) -> Result<(), Cause> {
        fence.require_source_controller_committed_v3()?;
        accepted.completed_native_v3(controller, fence)?;
        let state = self.source_admission.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some() || state.first.is_some() || state.cursor != storage_phase_index_v3(purpose)?
            || !matches!(state.after_time, Some(Ok(())))
            || state.interval.as_ref().is_none_or(|interval| !interval.completed_interval_v2()) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        state.disposal = Some((|| {
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(state.interval.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(state.disposal, Some(Ok(()))) {
            state.first = Some(RootAdmissionFirst::Disposal);
            self.first = Some(First::SourceAdmission);
            return Err(JournalError::ProtectedBoundary.into());
        }
        drop(self.turn.take());
        state.binding.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(JournalError::ProtectedBoundary)?.after = state.after.ok_or(JournalError::ProtectedBoundary)?;
        state.cursor = storage_phase_index_v3(purpose)?.checked_add(1).ok_or(JournalError::ProtectedBoundary)?;
        Ok(())
    }
}

fn storage_phase_index_v3(purpose: DeleteResourcePurposeV3) -> Result<u8, JournalError> {
    match purpose {
        DeleteResourcePurposeV3::Preparation26 => Ok(5),
        // Network, Host disposal and Mount Reap must finish before Storage7.
        DeleteResourcePurposeV3::Network9 => Ok(7),
        DeleteResourcePurposeV3::MountReap62 => Ok(9),
        DeleteResourcePurposeV3::Apply7 => Ok(10),
    }
}

impl RootDeleteClientOriginalV1<'_> {
    // Network activation consumes the sole Apply selector. Only the forthcoming
    // genuine9/Host/Mount completion borrower may restore it; no such entrance
    // exists in this component. Approval alone therefore cannot enter SDK7.
    fn require_storage_cleanup_successors_v4(&self) -> Result<(), JournalError> {
        if self.first.is_some() || self.resource_purpose != DeleteResourcePurposeV3::Apply7
            || self.network_activation.as_ref().is_none_or(|result| result.is_err())
            || !matches!(self.preparatory_approval_complete[2], Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if !state.mount_retired || state.cursor != 10 || state.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Rechecks actual held7 approval without adopting supplied wire DATA.
    fn require_apply_resource_approval_v3(&self) -> Result<(), Cause> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::Apply7)
    }

    fn require_network_resource_approval_v4(&self) -> Result<(), Cause> {
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::Network9)
    }

    fn require_cleanup_resource_approval_v4(&self, purpose: DeleteResourcePurposeV3)
        -> Result<(), Cause> {
        use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::{
            DeleteRootResourceDraftDataV2, DeleteRootResourceSignedDataV2,
        };
        if self.first.is_some() || self.terminal_complete
            || self.resource_purpose != purpose {
            return Err(self.closed.into());
        }
        let approved = self.preparatory_approval_complete[resource_slot_v3(purpose)].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let sent = self.resource_signing_complete[resource_slot_v3(purpose)].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let received = self.resource_draft_complete[resource_slot_v3(purpose)].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let challenge = *self.challenge.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let initial = *self.initial_complete.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?;
        let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&received.bytes, purpose)?;
        let signed = DeleteRootResourceSignedDataV2 { draft: &sent.draft_digest,
            canonical_signature: sent.signed.canonical_signature() };
        let method = match purpose {
            DeleteResourcePurposeV3::MountReap62 => {
                self.require_mount_predecessor_v4()?;
                let binding = self.mount_activation.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(self.closed)?;
                approved.approval.require_mount_exchange_v4(received.frame, challenge, initial,
                    binding.current, binding.approved9, draft, signed)?;
                aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
            }
            DeleteResourcePurposeV3::Apply7 => {
                let binding = self.apply_activation.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(self.closed)?;
                approved.approval.require_apply_exchange_v3(received.frame, challenge, initial,
                    binding.current, binding.current.draft, draft, signed)?;
                aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            }
            DeleteResourcePurposeV3::Network9 => {
                let binding = self.network_activation.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(self.closed)?;
                approved.approval.require_network_exchange_v4(received.frame, challenge, initial,
                    binding.predecessor, binding.predecessor.current.draft, draft, signed)?;
                aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NETWORK_APPLY
            }
            DeleteResourcePurposeV3::Preparation26 => return Err(self.closed.into()),
        };
        if sent.preparation.method_v2() != method
            || approved.after_clock.wall_seconds() >= sent.signed.plan().expires_seconds()
            || approved.after_clock.wall_seconds() >= sent.lease.authority_expires_seconds() {
            return Err(self.closed.into());
        }
        Ok(())
        }
}

// This sole finite helper describes the exact descriptor-free26 fields; it
// cannot encode a request, sign a plan or create any receiving permission.
fn delete_preparation_packet_bound_v3(fields: [usize; 5]) -> Option<usize> {
    // Each bytes/message field has a protobuf tag (at most five bytes) and a
    // u64 length varint (at most ten). Include the outer authorization message
    // and method scalar. The signed Session field comes from its format owner.
    let clear = fields.into_iter().try_fold(15usize,
        |sum, width| sum.checked_add(width)?.checked_add(15))?.checked_add(15)?;
    let packet = aos_sandbox_protocol::session::authenticated_request_packet_bound_from_clear_v1(clear)?;
    (packet <= aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES).then_some(packet)
}

#[cfg(test)]
mod preparation_packet_tests {
    use super::*;
    use buffa::Message as _;

    #[test]
    fn complete_actual_envelope_and_signed_field_fit_the_source_bound() {
        use aos_sandbox_api::aos::sandbox::local::v1::{BrokerRequestEnvelope, BrokerAuthorizationArtifactsV1, BrokerMethod};
        for width in [1, 127, 128, 16_383, 16_384] {
            let envelope = BrokerRequestEnvelope {
                method: BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG.into(),
                body: vec![0; width],
                authorization: Some(BrokerAuthorizationArtifactsV1 {
                    broker_plan: vec![0; width], broker_plan_signature: vec![0; width],
                    ownership_lease: vec![0; width], ownership_lease_signature: vec![0; width],
                    ..Default::default()
                }).into(),
                signed_session_request: vec![0; aos_sandbox_broker_session_protocol::SIGNED_BROKER_REQUEST_BYTES],
                ..Default::default()
            };

            let bound = delete_preparation_packet_bound_v3([width; 5]).unwrap();
            assert!(envelope.encode_to_vec().len() <= bound);
        }
    }

    #[test]
    fn overflow_and_outside_the_actual_wire_ceiling_have_no_quote() {
        assert!(delete_preparation_packet_bound_v3([usize::MAX; 5]).is_none());
        assert!(delete_preparation_packet_bound_v3([
            aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES; 5]).is_none());
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn completed_preparation_current_data_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        session: [u8;64], identity: ([u8;32],[u8;32]),
    ) -> Result<aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3, Cause> {
        use aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3;
        if self.require_accepted_pending_v3(fence, controller, launch, accepted).is_err() {
            if let Some(state) = self.source_admission.as_mut() { state.first.get_or_insert(RootAdmissionFirst::Association); }
            self.first.get_or_insert(First::SourceAdmission);
            return Err(JournalError::ProtectedBoundary.into());
        }
        let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some() || self.terminal_complete || self.turn.is_some() || state.first.is_some()
            || state.cursor != 6 || state.interval.is_some() || !matches!(state.disposal,Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let challenge = self.challenge.as_ref().and_then(|result|result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        let signed = self.resource_signing_complete[0].as_ref().and_then(|result|result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        let frame = DeleteRootPreparationCurrentDataV3 { challenge:challenge.source.nonce, opening:challenge.open,
            draft:signed.draft_digest, controller:*accepted.completed_native_v3(controller,fence)?,
            source:*fence.controller_committed_native_data_v3()?, session, request:identity.0, outcome:identity.1 };
        frame.encode_v3()?;
        Ok(frame)
    }
}

impl RootDeleteClientOriginalV1<'_> {
    // This constructor is selected only by the actual completed26 upper loan.
    // The new interval is SAME C17/Root, not a continued old SDK window.
    pub(crate) fn send_preparation_current_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        frame: aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some() || self.turn.is_some() || self.source_admission.as_ref().is_none_or(|state|
            state.first.is_some() || state.cursor != 6 || state.interval.is_some()
                || state.current_entry.is_some() || state.current_encoding.is_some()) {
            self.first.get_or_insert(First::Reentry); return Err(self.closed);
        }
        let cutoff = self.challenge.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?.source.cutoff;
        if self.require_accepted_pending_v3(fence, controller, launch, accepted).is_err() {
            if let Some(state) = self.source_admission.as_mut() { state.first.get_or_insert(RootAdmissionFirst::Association); }
            self.first.get_or_insert(First::SourceAdmission); return Err(self.closed);
        }
        // The real constructor's enlarged inline layout was prepaid before its
        // initial Box. This finite write pays its actual nonrefundable traffic.
        let fee = ResourceVector::ZERO.with(D::NetworkBytes, 352).with(D::OutputBytes, 352);
        let paid = fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(), fee);
        if let Some(state) = self.source_admission.as_mut() {
            state.funding = Some(paid);
            if !matches!(state.funding, Some(Ok(()))) {
                state.first.get_or_insert(RootAdmissionFirst::Funding); self.first.get_or_insert(First::SourceAdmission);
                return Err(self.closed);
            }
        }
        let entered = self.begin_admission_interval_once_v3(fence, controller, launch,
            RootNativeAdmissionPhaseV3::PreparationCurrent(accepted));
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.current_entry = Some(entered);
        if !matches!(state.current_entry, Some(Ok(()))) { return Err(self.closed); }
        // Native-before may already have refused. The result remains on this
        // real owner and every reached attempt still runs its after below.
        state.current_encoding = Some((|| {
            if state.first.is_some() || state.before.is_none() || state.after.is_some() { return Err(JournalError::ProtectedBoundary.into()); }
            let actual = accepted.completed_native_v3(controller, fence)?;
            if actual != &frame.controller || fence.controller_committed_native_data_v3()? != &frame.source {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(frame.encode_v3()?)
        })());
        if let Some(Ok(bytes)) = &state.current_encoding {
            state.current_bytes = *bytes;
            state.current_send = Some(match self.connection.stream_mut() {
                Ok(stream) => state.current_io.run_once(stream, &mut state.current_bytes, cutoff,
                    crate::policy_compiler::bounded_stream_io::DeadlineStreamDirectionV1::Write),
                Err(cause) => Err(cause),
            });
            if !matches!(state.current_send, Some(Ok(()))) { state.first.get_or_insert(RootAdmissionFirst::CurrentSend); }
        } else { state.first.get_or_insert(RootAdmissionFirst::CurrentEncoding); }
        if state.first.is_some() {
            if let Some(interval) = state.interval.as_mut() { interval.mark_external_primary_refusal_v2(); }
        }
        let after = self.finish_source_readiness_interval_once_v3(controller);
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        state.current_after = Some(after);
        if !matches!(state.current_after, Some(Ok(()))) || state.first.is_some() || !state.current_io.completed_exact() {
            self.first.get_or_insert(First::SourceAdmission); return Err(self.closed);
        }
        state.disposal = Some((|| {
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(state.interval.take()); token.complete_after_upper_disposal_v1(); Ok(())
        })());
        if !matches!(state.disposal, Some(Ok(()))) { state.first = Some(RootAdmissionFirst::Disposal); self.first = Some(First::SourceAdmission); return Err(self.closed); }
        drop(self.turn.take());
        state.binding.as_mut().and_then(|r| r.as_mut().ok()).ok_or(self.closed)?.after = state.after.ok_or(self.closed)?;
        state.cursor = 7;
        Ok(())
    }
}

impl RootDeleteClientOriginalV1<'_> {
    /// Selects the second retained resource slot from the actual completed26 owner.
    ///
    /// The caller keeps that native original borrowed through its Apply loan.
    /// This selection creates no signer, Session, append window or permission;
    /// the same-D draft, exact current lease and Root approval still precede7.
    pub(crate) fn begin_apply_resource_exchange_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        preparation: &crate::DeleteStoragePreparationIoOriginalV3,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        response: &aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogResponse,
    ) -> Result<(), RootDeleteClientClosedV1> {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        use aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3;
        use buffa::Message as _;

        if self.first.is_some() || self.terminal_complete || self.turn.is_some()
            || self.resource_purpose != DeleteResourcePurposeV3::Preparation26
            || self.apply_activation_admission.is_some() || self.apply_activation.is_some()
            || self.source_admission.as_ref().is_none_or(|state|
                state.first.is_some() || state.cursor != 7 || state.interval.is_some()
                    || !matches!(state.current_after, Some(Ok(())))
                    || !matches!(state.disposal, Some(Ok(()))) || !state.current_io.completed_exact()) {
            self.first.get_or_insert(First::Reentry); return Err(self.closed);
        }
        if self.require_accepted_pending_v3(fence, controller, launch, accepted).is_err() {
            if let Some(state) = self.source_admission.as_mut() { state.first.get_or_insert(RootAdmissionFirst::Association); }
            self.first.get_or_insert(First::SourceAdmission); return Err(self.closed);
        }
        // Price encoding of the actual retained response and the exact hashing
        // backing before canonical bytes or a new comparison result can grow.
        self.apply_activation_admission = Some((|| {
            let response_bytes = usize::try_from(response.try_encoded_len()
                .map_err(|_| JournalError::JournalTooLarge)?)
                .map_err(|_| JournalError::JournalTooLarge)?;
            let bytes = response_bytes.checked_mul(3)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<blake3::Hasher>().checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        if !matches!(self.apply_activation_admission, Some(Ok(()))) {
            self.first = Some(First::ApplyActivationAdmission); return Err(self.closed);
        }
        self.apply_activation = Some((|| {
            let state = self.source_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let current = DeleteRootPreparationCurrentDataV3::decode_v3(&state.current_bytes)?;
            let identity = preparation.completed_receipt_identity_data_v3()?;
            let sent = self.resource_signing_complete[0].as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            if preparation.completed_native_v3()? != &current.session
                || identity != (current.request, current.outcome)
                || outcome.request().signed_request_digest() != current.request
                || blake3::hash(outcome.canonical_packet()).as_bytes() != &current.outcome
                || outcome.request().method() != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                || sent.draft_digest != current.draft
                || accepted.completed_native_v3(controller, fence)? != &current.controller
                || fence.controller_committed_native_data_v3()? != &current.source {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
                return Err(JournalError::ProtectedBoundary.into());
            };
            // Reuse the actual SDK's decoded response. Encode-equality binds it
            // to the complete authenticated outcome without a second parser.
            if response.encode_to_vec() != *exact_body { return Err(JournalError::ProtectedBoundary.into()); }
            let digest = response.catalog_digest.as_slice().try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let catalog = aos_sandbox_protocol::semantics::CatalogBindingV1::from_publisher(
                response.catalog_generation, ObjectDigest::from_bytes(digest))?;
            let sender_before = state.before.ok_or(JournalError::ProtectedBoundary)?;
            Ok(DeleteApplyResourceBindingDataV3 { current, catalog, sender_before })
        })());
        if !matches!(self.apply_activation, Some(Ok(_))) {
            self.first = Some(First::ApplyActivation); return Err(self.closed);
        }
        self.resource_purpose = DeleteResourcePurposeV3::Apply7;
        Ok(())
    }

    pub(super) fn require_resource_flight_pending_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
    ) -> Result<(), JournalError> {
        match (self.resource_purpose, accepted) {
            (DeleteResourcePurposeV3::Preparation26, None) => self.require_same_pending(fence, controller, launch),
            (DeleteResourcePurposeV3::Apply7 | DeleteResourcePurposeV3::Network9 | DeleteResourcePurposeV3::MountReap62, Some(accepted)) => {
                if self.require_accepted_pending_v3(fence, controller, launch, accepted).is_err() {
                    if let Some(state) = self.source_admission.as_mut() { state.first.get_or_insert(RootAdmissionFirst::Association); }
                    self.first.get_or_insert(First::SourceAdmission);
                    return Err(JournalError::ProtectedBoundary);
                }
                let binding = self.apply_activation.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                if self.resource_purpose == DeleteResourcePurposeV3::MountReap62 {
                    self.require_mount_predecessor_v4()?;
                }
                if self.resource_purpose == DeleteResourcePurposeV3::Network9 {
                    let network = self.network_activation.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?;
                    let approval = self.preparatory_approval_complete[1].as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?;
                    if network.predecessor.current != binding.current || network.predecessor.approval != approval.approval {
                        return Err(JournalError::StaleAuthoritySnapshot);
                    }
                }
                if accepted.completed_native_v3(controller, fence)
                    .map_err(|_| JournalError::ProtectedBoundary)? != &binding.current.controller
                    || fence.controller_committed_native_data_v3()? != &binding.current.source {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                Ok(())
            }
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}
