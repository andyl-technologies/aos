//! Keeps the fresh D Root connection on its genuine intrinsic C17 flight.
//!
//! Opening and a completed initial-six ACK with actual native posts lend only
//! a short challenge association for one real query. Neither creates a floor,
//! fresh six-owner proof or accepted
//! lifecycle state. The socket and first native Root binding remain resident
//! across those queries; failed or unfinished flights abort before unwinding.

use std::error::Error;

use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerDeletePreacceptTurnOriginalV1,
    ControllerOperationIntakeFailureViewV1,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    delete_batch::DeleteBatchViewV1,
    delete_root::{
        source_current::source_delete_current_batch_digest_v1,
        transport::{DeleteRootChallengeDataV2, DeleteRootOpenDataV2, DeleteRootWireErrorV2},
    },
    resource_bank::{OperationIntakeFundingDataV1, ResourceBankDataError},
};

use super::peer_receiving::sample::PeerSampleV1;
use super::peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1, StableRootPeerV1};
use super::root_connection::ControllerRootConnectionOriginalV1;
use super::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::journal::{Journal, JournalError, SourceDeletePendingFenceV1};

mod opening;
mod initial_inventory;
mod shape;
mod resource_signing;
mod admission;
pub(crate) use admission::{DeleteSourceBindingDataV3, DeleteSourceClockBoundDataV3};
use opening::RootDeleteClientOpeningV1;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Delete Root client is incomplete or retains a refusal")]
pub(crate) struct RootDeleteClientClosedV1;

#[derive(Clone, Copy)]
pub(super) enum First {
    Before,
    ClockBefore,
    Open,
    Connect,
    PeerBefore,
    Reporting,
    SendOpen,
    Preparation,
    Admission,
    Chunk,
    Challenge,
    Copy,
    SendBatch,
    PeerAfter,
    After,
    ClockAfter,
    Settlement,
    Disposal,
    Association,
    ChallengeGate,
    ControllerCut,
    SendControllerCut,
    Authorization,
    SendAuthorization,
    InitialFrameAdmission,
    InitialAdmission,
    Initial,
    InitialDisposal,
    FreshTransferAdmission,
    FreshTransfer,
    FreshTransferDisposal,
    ResourceDraftAdmission,
    ResourceDraft,
    ResourceDraftDisposal,
    ResourceSigningAdmission,
    ResourceSigning,
    ResourceSigningDisposal,
    ApplyActivationAdmission,
    ApplyActivation,
    NetworkActivationAdmission,
    NetworkActivation,
    MountActivationAdmission,
    MountHistoryAdmission,
    MountActivation,
    PreparatoryApprovalAdmission,
    PreparatoryApproval,
    PreparatoryApprovalDisposal,
    SourceAdmissionFunding,
    SourceAdmission,
    Reentry,
}

/// Keeps actual native Root/C17 originals beside their verified challenge.
///
/// Only `begin_pending_once_v1` constructs this owner from a live intrinsic
/// pending fence. No decoded challenge or caller-supplied position is adopted.
#[must_use]
pub(crate) struct RootDeleteClientOriginalV1<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    connection: ControllerRootConnectionOriginalV1,
    stable: Option<StableRootPeerV1>,
    open: Option<Result<DeleteRootOpenDataV2, DeleteRootWireErrorV2>>,
    funding: Option<
        Result<
            [u8; aos_sandbox_protocol::domain_ledger::resource_bank::OPERATION_INTAKE_FUNDING_BYTES_V1],
            ResourceBankDataError,
        >,
    >,
    open_encoding: [u8; 208],
    challenge_encoding: [u8; 224],
    controller_next: u64,
    controller_end: u64,
    challenge: Option<Result<DeleteRootChallengeDataV2, DeleteRootWireErrorV2>>,
    turn: Option<ControllerDeletePreacceptTurnOriginalV1<'profile>>,
    opening: Option<Box<RootDeleteClientOpeningV1>>,
    initial: Option<Box<initial_inventory::RootDeleteClientInitialOriginalV2>>,
    initial_frame_admission: Option<Result<(), JournalError>>,
    initial_admission: Option<Result<(), JournalError>>,
    initial_complete: Option<Result<aos_sandbox_protocol::domain_ledger::delete_root::initial_inventory::DeleteRootInitialAckDataV3, JournalError>>,
    initial_six: [u8; 32],
    fresh_transfer: Option<Box<initial_inventory::RootDeleteClientInitialOriginalV2>>,
    fresh_transfer_admission: Option<Result<(), JournalError>>,
    fresh_transfer_complete: Option<Result<aos_sandbox_protocol::domain_ledger::delete_root::
        final_inventory::DeleteRootFreshTransferDataV2, JournalError>>,
    resource_purpose: DeleteResourcePurposeV3,
    network_activation_admission: Option<Result<(), JournalError>>,
    network_activation: Option<Result<admission::DeleteNetworkResourceBindingDataV4, Box<dyn Error + Send + Sync>>>,
    mount_stop_source: Option<crate::lifecycle::LifecycleHistoricalReadOriginalV1>,
    mount_stop_history: Option<crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1>,
    mount_activation_admission: Option<Result<(), JournalError>>,
    mount_history_admission: Option<Result<(), JournalError>>,
    mount_activation: Option<Result<admission::DeleteMountResourceBindingDataV4, Box<dyn Error + Send + Sync>>>,
    apply_activation_admission: Option<Result<(), JournalError>>,
    apply_activation: Option<Result<admission::DeleteApplyResourceBindingDataV3, Box<dyn Error + Send + Sync>>>,
    resource_draft: [Option<Box<initial_inventory::RootDeleteClientInitialOriginalV2>>; 4],
    resource_draft_admission: [Option<Result<(), JournalError>>; 4],
    resource_draft_complete: [Option<Result<initial_inventory::ResourceDraftReceiptV2, JournalError>>; 4],
    resource_signing: [Option<Box<resource_signing::DeleteResourceSigningStateV2>>; 4],
    preparatory_approval: [Option<Box<initial_inventory::RootDeleteClientInitialOriginalV2>>; 4],
    preparatory_approval_admission: [Option<Result<(), JournalError>>; 4],
    preparatory_approval_complete: [Option<Result<initial_inventory::DeletePreparatoryApprovalReceiptV3, JournalError>>; 4],
    source_admission_admission: Option<Result<(), JournalError>>,
    source_admission: Option<Box<admission::DeleteSourceAcceptanceRootStateV3>>,
    resource_signing_admission: [Option<Result<(), JournalError>>; 4],
    resource_signing_complete: [Option<Result<resource_signing::DeleteResourceSignedReceiptV2, JournalError>>; 4],
    before: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    admission: Option<Result<(), JournalError>>,
    association: Option<Result<(), JournalError>>,
    challenge_clock: Option<rustix::time::Timespec>,
    challenge_gate: Option<
        Result<
            std::time::Duration,
            aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1,
        >,
    >,
    disposal: Option<Result<(), JournalError>>,
    first: Option<First>,
    opening_complete: bool,
    terminal_complete: bool,
    closed: RootDeleteClientClosedV1,
}

impl<'profile> RootDeleteClientOriginalV1<'profile> {
    /// Enters the actual same-C17 Root opening without borrowing the fence later.
    ///
    /// The entire native/receive/parser reservoir and an independent Root after
    /// are paid before construction. Once native custody exists, even a failed
    /// opening returns this owning attempt; its original causes never unwind.
    ///
    /// # Errors
    /// Returns only a preconstruction financial/fence refusal. Every reached
    /// native failure instead remains in the returned original.
    pub(crate) fn begin_pending_once_v1(
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, JournalError> {
        let bytes = fence.batch_bytes()?.len();
        let fixed = Self::fixed_demand_v1(profile, bytes, fence.authorization_input_data_v2().len())?;
        fence.reserve_preaccept_additional_v1(
            controller,
            launch,
            profile.lower_original_v1(),
            fixed,
        )?;
        // These two rows per sample cover the first peer observation and its
        // independent after, including any earlier clock/profile/native error.
        fence.reserve_preaccept_additional_v1(
            controller,
            launch,
            profile.lower_original_v1(),
            Self::peer_traffic_v1(2)?,
        )?;
        let turn = fence.prepare_preaccept_turn_v1(
            controller,
            launch,
            profile.lower_original_v1(),
            ResourceVector::ZERO,
        )?;
        let mut original = Self {
            profile,
            connection: Default::default(),
            stable: None,
            open: None,
            funding: None,
            open_encoding: [0; 208],
            challenge_encoding: [0; 224],
            controller_next: 0,
            controller_end: 0,
            challenge: None,
            turn: Some(turn),
            opening: Some(Box::new(RootDeleteClientOpeningV1::new())),
            initial: None,
            initial_frame_admission: None,
            initial_admission: None,
            initial_complete: None,
            fresh_transfer: None,
            fresh_transfer_admission: None,
            fresh_transfer_complete: None,
            resource_purpose: DeleteResourcePurposeV3::Preparation26,
            apply_activation_admission: None, apply_activation: None,
            network_activation_admission: None, network_activation: None,
            mount_stop_source: None, mount_stop_history: None,
            mount_activation_admission: None, mount_history_admission: None, mount_activation: None,
            resource_draft: std::array::from_fn(|_| None), resource_draft_admission: std::array::from_fn(|_| None), resource_draft_complete: std::array::from_fn(|_| None),
            resource_signing: std::array::from_fn(|_| None), resource_signing_admission: std::array::from_fn(|_| None), resource_signing_complete: std::array::from_fn(|_| None),
            preparatory_approval: std::array::from_fn(|_| None), preparatory_approval_admission: std::array::from_fn(|_| None), preparatory_approval_complete: std::array::from_fn(|_| None),
            source_admission_admission: None, source_admission: None,
            initial_six: [0; 32],
            before: None,
            after: None,
            admission: None,
            association: None,
            challenge_clock: None,
            challenge_gate: None,
            disposal: None,
            first: None,
            opening_complete: false,
            terminal_complete: false,
            closed: RootDeleteClientClosedV1,
        };
        original.open_pending_once(fence, controller, launch);
        Ok(original)
    }

    fn open_pending_once(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) {
        // The independent clock, Root and C posts are all armed/funded before
        // primary work. Their attempts below are not conditioned on success.
        let origin = self
            .opening
            .as_mut()
            .map(|opening| opening.begin_clock_once());
        if !matches!(origin, Some(Ok(()))) {
            self.first.get_or_insert(First::ClockBefore);
        }
        self.before = Some((|| {
            self.turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_before_once_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)
        })());
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        if self.first.is_none() {
            let primary = self.open_primary(fence, controller, launch);
            if primary.is_err() && self.first.is_none() {
                self.first = Some(First::Association);
            }
        }
        self.observe_owed_root_after();
        self.after = Some((|| {
            self.turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_after_once_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)
        })());
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        let post = self.opening.as_mut().map(|opening| {
            opening.finish_clock_once(
                self.open
                    .as_ref()
                    .and_then(|open| open.as_ref().ok())
                    .copied(),
                self.challenge
                    .as_ref()
                    .and_then(|challenge| challenge.as_ref().ok())
                    .copied(),
            )
        });
        if !matches!(post, Some(Ok(()))) {
            self.first.get_or_insert(First::ClockAfter);
        }
        if self.first.is_none() {
            self.settle_opening(controller);
        }
    }

    fn open_primary(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.open = Some((|| {
            let batch = fence
                .batch_bytes()
                .map_err(|_| DeleteRootWireErrorV2::Association)?;
            let view = DeleteBatchViewV1::decode(batch)?;
            self.initial_six = view.named_commitments_v2()
                .ok_or(DeleteRootWireErrorV2::Association)?.initial_six;
            let (clock, expires) = fence.authorization_horizon_v1();
            let open = DeleteRootOpenDataV2 {
                project: *view.project().as_bytes(),
                operation: *view.operation().as_bytes(),
                batch: source_delete_current_batch_digest_v1(batch)?,
                batch_bytes: u64::try_from(batch.len())
                    .map_err(|_| DeleteRootWireErrorV2::Format)?,
                authorization_clock: clock,
                authorization_expires: expires,
                source_pending: *fence
                    .native_position_data_v1()
                    .map_err(|_| DeleteRootWireErrorV2::Association)?,
            };
            open.require_batch_v2(batch)?;
            Ok(open)
        })());
        if !matches!(self.open, Some(Ok(_))) {
            self.first = Some(First::Open);
            return Err(self.closed);
        }
        self.association = Some((|| {
            let (funding, next, end) = fence.controller_funding_cut_data_v3(
                controller,
                launch,
                self.profile.lower_original_v1(),
            )?;
            self.funding = Some(funding.encode_v1());
            if !matches!(self.funding, Some(Ok(_))) {
                return Err(JournalError::ProtectedBoundary);
            }
            self.controller_next = next;
            self.controller_end = end;
            Ok(())
        })());
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(First::Association);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let local = self.opening.as_mut().ok_or(self.closed)?;
        if local.prepare_open_once(open).is_err() {
            self.first = Some(First::Open);
            return Err(self.closed);
        }
        local.connected = Some(self.connection.connect_once());
        if !matches!(local.connected, Some(Ok(()))) {
            self.first = Some(First::Connect);
            return Err(self.closed);
        }
        let cutoff = local.cutoff()?;
        local.peer_before_result = Some(local.peer_before.observe_delete_once_v1(
            self.profile,
            self.connection.stream().map_err(|_| self.closed)?,
            None,
            None,
            false,
            cutoff,
        ));
        if !matches!(local.peer_before_result, Some(Ok(()))) {
            self.first = Some(First::PeerBefore);
            return Err(self.closed);
        }
        local.reporting = Some(
            self.connection
                .stream_mut()
                .map_err(|_| self.closed)?
                .enable_subject_reporting(),
        );
        if !matches!(local.reporting, Some(Ok(()))) {
            self.first = Some(First::Reporting);
            return Err(self.closed);
        }
        let cutoff = local.cutoff()?;
        local.sent_open_result = Some(local.sent_open.run_once(
            self.connection.stream_mut().map_err(|_| self.closed)?,
            &mut local.encoded_open,
            cutoff,
            crate::policy_compiler::bounded_stream_io::DeadlineStreamDirectionV1::Write,
        ));
        if !matches!(local.sent_open_result, Some(Ok(()))) {
            self.first = Some(First::SendOpen);
            return Err(self.closed);
        }
        self.receive_challenge(fence, controller, launch)?;
        let local = self.opening.as_ref().ok_or(self.closed)?;
        self.challenge = Some(
            DeleteRootChallengeDataV2::decode_v2(local.received.bytes()).and_then(|challenge| {
                challenge.require_open_v2(open)?;
                Ok(challenge)
            }),
        );
        if !matches!(self.challenge, Some(Ok(_))) {
            self.first = Some(First::Challenge);
            return Err(self.closed);
        }
        // The complete canonical bytes are copied once after their actual peak
        // was prepaid. No variable descriptor, batch header or caller key is trusted.
        let local = self.opening.as_mut().ok_or(self.closed)?;
        local
            .copy_batch_once(fence.batch_bytes().map_err(|_| self.closed)?)
            .map_err(|_| {
                self.first = Some(First::Copy);
                self.closed
            })?;
        local.sent_batch_result = Some(local.sent_batch.run_once(
            self.connection.stream_mut().map_err(|_| self.closed)?,
            &mut local.batch,
            cutoff,
            crate::policy_compiler::bounded_stream_io::DeadlineStreamDirectionV1::Write,
        ));
        if !matches!(local.sent_batch_result, Some(Ok(()))) {
            self.first = Some(First::SendBatch);
            return Err(self.closed);
        }
        let challenge = self
            .challenge
            .as_ref()
            .and_then(|challenge| challenge.as_ref().ok())
            .copied()
            .ok_or(self.closed)?;
        let funding = self
            .funding
            .as_ref()
            .and_then(|funding| funding.as_ref().ok())
            .ok_or(self.closed)?;
        local
            .send_controller_cut_once(
                self.connection.stream_mut().map_err(|_| self.closed)?,
                challenge,
                funding,
                self.controller_next,
                self.controller_end,
                cutoff,
            )
            .map_err(|stage| {
                self.first = Some(stage);
                self.closed
            })?;
        local.send_authorization_once(
            self.connection.stream_mut().map_err(|_| self.closed)?,
            fence, open, challenge, cutoff,
        ).map_err(|stage| { self.first = Some(stage); self.closed })?;
        // Preserve the actual sent/received arrays before positive local
        // disposal. Later native query loans borrow these exact version2 bytes.
        self.open_encoding = local.encoded_open;
        self.challenge_encoding.copy_from_slice(local.received.bytes());
        Ok(())
    }

    fn observe_owed_root_after(&mut self) {
        let Some(local) = self.opening.as_mut() else {
            return;
        };
        let Ok(stream) = self.connection.stream() else {
            return;
        };
        let cutoff = local.cutoff().unwrap_or(0);
        let result = if matches!(local.peer_before_result, Some(Ok(()))) {
            local.peer_after.observe_delete_against_sample_once_v1(
                self.profile,
                stream,
                &local.peer_before,
                None,
                true,
                cutoff,
            )
        } else {
            local
                .peer_after
                .observe_delete_once_v1(self.profile, stream, None, None, true, cutoff)
        };
        local.peer_after_result = Some(result);
        if !matches!(local.peer_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::PeerAfter);
        }
    }

    fn settle_opening(&mut self, controller: &Journal) {
        let Some(local) = self.opening.as_mut() else {
            self.first = Some(First::Settlement);
            return;
        };
        local.settlement = Some(
            local
                .peer_before
                .settle_positive_once()
                .and_then(|()| local.peer_after.settle_positive_once()),
        );
        if !matches!(local.settlement, Some(Ok(()))) {
            self.first = Some(First::Settlement);
            return;
        }
        self.stable = local.peer_before.take_initial_binding();
        if self.stable.is_none() {
            self.first = Some(First::Settlement);
            return;
        }
        // All fallible native posts have completed. The token holds the same
        // C17 slot while completed *local* originals are actually destroyed.
        // The still-paid Root stream/stable binding remain in this original.
        self.disposal = Some((|| {
            let coordinator = controller.controller_coordinator_for_bank_read_v1()?;
            let token = self
                .turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(coordinator)
                .map_err(JournalError::ControllerNative)?;
            drop(self.opening.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(self.disposal, Some(Ok(()))) {
            self.first = Some(First::Disposal);
            return;
        }
        drop(self.turn.take());
        self.opening_complete = true;
    }

    fn open_data(&self) -> Result<DeleteRootOpenDataV2, RootDeleteClientClosedV1> {
        self.open
            .as_ref()
            .and_then(|open| open.as_ref().ok())
            .copied()
            .ok_or(self.closed)
    }

    /// Lends the actual verified challenge for exactly one same-fence query.
    ///
    /// This short loan is not a six-owner proof or accepted Root floor. Each
    /// query keeps its real signed request/terminal after this borrow ends.
    ///
    /// # Errors
    /// Refuses incomplete opening/initial ACK, earlier uncertainty, another actual pending
    /// batch/native position/C cut, expired original horizon or later reentry.
    pub(crate) fn borrow_challenge_v1<'query>(
        &'query mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<RootDeleteChallengeLoanV1<'query>, RootDeleteClientClosedV1> {
        if !self.opening_complete || self.first.is_some() || self.terminal_complete
            || !matches!(self.initial_complete, Some(Ok(_))) {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        self.association = Some(self.require_same_pending(fence, controller, launch));
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(First::Association);
            return Err(self.closed);
        }
        let challenge = self
            .challenge
            .as_ref()
            .and_then(|challenge| challenge.as_ref().ok())
            .ok_or(self.closed)?;
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.challenge_clock = Some(now);
        self.challenge_gate = Some(crate::policy_compiler::bounded_stream_io::remaining(
            now,
            challenge.source.cutoff,
        ));
        if !matches!(self.challenge_gate, Some(Ok(_))) {
            self.first = Some(First::ChallengeGate);
            return Err(self.closed);
        }
        Ok(RootDeleteChallengeLoanV1 {
            open: self
                .open
                .as_ref()
                .and_then(|open| open.as_ref().ok())
                .ok_or(self.closed)?,
            challenge,
            funding: self
                .funding
                .as_ref()
                .and_then(|funding| funding.as_ref().ok())
                .ok_or(self.closed)?,
            controller_next: self.controller_next,
            controller_end: self.controller_end,
            open_encoding: &self.open_encoding,
            challenge_encoding: &self.challenge_encoding,
        })
    }

    fn require_same_pending(
        &self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), JournalError> {
        let open = self
            .open_data()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        open.require_batch_v2(fence.batch_bytes()?)
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        let (clock, expires) = fence.authorization_horizon_v1();
        let (funding, next, end) =
            fence.controller_funding_cut_data_v3(controller, launch, self.profile.lower_original_v1())?;
        let same_funding = self
            .funding
            .as_ref()
            .and_then(|funding| funding.as_ref().ok())
            .is_some_and(|bytes| OperationIntakeFundingDataV1::decode_v1(bytes).is_ok_and(|held| held == funding));
        if open.authorization_clock != clock
            || open.authorization_expires != expires
            || &open.source_pending != fence.native_position_data_v1()?
            || !same_funding
            || self.controller_next != next
            || self.controller_end != end
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let opening = self.opening.as_deref();
        match self.first? {
            First::InitialFrameAdmission => cause(&self.initial_frame_admission),
            First::InitialAdmission => cause(&self.initial_admission),
            First::Initial => self.initial.as_ref().and_then(|local| local.failure())
                .or_else(|| self.connection.failure()),
            First::InitialDisposal => cause(&self.initial_complete),
            First::FreshTransferAdmission => cause(&self.fresh_transfer_admission),
            First::FreshTransfer => self.fresh_transfer.as_ref().and_then(|local| local.failure()),
            First::FreshTransferDisposal => cause(&self.fresh_transfer_complete),
            First::SourceAdmissionFunding => cause(&self.source_admission_admission),
            First::SourceAdmission => self.source_admission.as_ref().and_then(|state| state.failure()),
            First::PreparatoryApprovalAdmission => cause(&self.preparatory_approval_admission[resource_slot_v3(self.resource_purpose)]),
            First::PreparatoryApproval => self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|local| local.failure()),
            First::PreparatoryApprovalDisposal => cause(&self.preparatory_approval_complete[resource_slot_v3(self.resource_purpose)]),
            First::ResourceSigningAdmission => cause(&self.resource_signing_admission[resource_slot_v3(self.resource_purpose)]),
            First::NetworkActivationAdmission => cause(&self.network_activation_admission),
            First::NetworkActivation => self.network_activation.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::MountActivationAdmission => cause(&self.mount_activation_admission),
            First::MountHistoryAdmission => cause(&self.mount_history_admission),
            First::MountActivation => self.mount_stop_source.as_ref().and_then(|source| source.failure())
                .or_else(|| self.mount_stop_history.as_ref().and_then(|history| history.failure()))
                .or_else(|| self.mount_activation.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _)),
            First::ApplyActivationAdmission => cause(&self.apply_activation_admission),
            First::ApplyActivation => self.apply_activation.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::ResourceSigning => self.resource_signing[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|local| local.failure()),
            First::ResourceSigningDisposal => cause(&self.resource_signing_complete[resource_slot_v3(self.resource_purpose)]),
            First::ResourceDraftAdmission => cause(&self.resource_draft_admission[resource_slot_v3(self.resource_purpose)]),
            First::ResourceDraft => self.resource_draft[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|local| local.failure()),
            First::ResourceDraftDisposal => cause(&self.resource_draft_complete[resource_slot_v3(self.resource_purpose)]),
            First::Before => cause(&self.before),
            First::After => cause(&self.after),
            First::Admission => cause(&self.admission),
            First::Open => {
                cause(&self.open).or_else(|| opening.and_then(|local| local.open_failure()))
            }
            First::Connect => self.connection.failure(),
            First::Challenge => cause(&self.challenge),
            First::Disposal => cause(&self.disposal),
            First::Association => cause(&self.funding).or_else(|| cause(&self.association)),
            First::ChallengeGate => cause(&self.challenge_gate),
            first => opening.and_then(|local| local.failure(first)),
        }
        .or(Some(&self.closed))
    }

    pub(crate) fn intake_failure_view_v1<'cause>(
        &'cause self,
        fence: &'cause SourceDeletePendingFenceV1<'_, '_, '_, '_>,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'cause>> {
        if self.financial_failure_is_selected_v2() {
            return fence.intake_failure_view_v1(self.profile.lower_original_v1());
        }
        if matches!(self.first, Some(First::PreparatoryApprovalDisposal))
            || matches!(self.first, Some(First::PreparatoryApproval))
                && self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::ResourceSigningDisposal))
            || matches!(self.first, Some(First::ResourceSigning))
                && self.resource_signing[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::ResourceDraftDisposal))
            || matches!(self.first, Some(First::ResourceDraft))
                && self.resource_draft[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::FreshTransferDisposal))
            || matches!(self.first, Some(First::FreshTransfer))
                && self.fresh_transfer.as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::InitialDisposal))
            || matches!(self.first, Some(First::Initial))
                && self.initial.as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::Before | First::After | First::Disposal)) {
            return self.turn.as_ref()?.failure_view_v1();
        }
        None
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::SourceAdmission)) {
            return self.source_admission.as_ref()?.property_failure_view_v3();
        }
        if matches!(self.first, Some(First::PreparatoryApproval)) {
            return self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_ref()?.property_failure_view();
        }
        if matches!(self.first, Some(First::ResourceSigning)) {
            return self.resource_signing[resource_slot_v3(self.resource_purpose)].as_ref()?.property_failure_view();
        }
        if matches!(self.first, Some(First::Initial)) {
            return self.initial.as_ref()?.property_failure_view();
        }
        if matches!(self.first, Some(First::FreshTransfer)) {
            return self.fresh_transfer.as_ref()?.property_failure_view();
        }
        if matches!(self.first, Some(First::ResourceDraft)) {
            return self.resource_draft[resource_slot_v3(self.resource_purpose)].as_ref()?.property_failure_view();
        }
        self.opening.as_deref()?.property_failure_view(self.first?)
    }
}

/// Keeps a short borrow of the actual native opening and completed initial ACK.
///
/// No public constructor or decoded-DATA adopter exists. Callers use the
/// borrowed nonce/cutoff solely to form their actual signed Session request.
pub(crate) struct RootDeleteChallengeLoanV1<'query> {
    open_encoding: &'query [u8; 208],
    challenge_encoding: &'query [u8; 224],
    open: &'query DeleteRootOpenDataV2,
    challenge: &'query DeleteRootChallengeDataV2,
    funding: &'query [u8; aos_sandbox_protocol::domain_ledger::resource_bank::OPERATION_INTAKE_FUNDING_BYTES_V1],
    controller_next: u64,
    controller_end: u64,
}

impl RootDeleteChallengeLoanV1<'_> {
    pub(crate) fn open_encoding_v2(&self) -> &[u8; 208] { self.open_encoding }
    pub(crate) fn challenge_encoding_v2(&self) -> &[u8; 224] { self.challenge_encoding }

    pub(crate) fn nonce_v1(&self) -> &[u8; 16] {
        &self.challenge.source.nonce
    }
    pub(crate) fn cutoff_v1(&self) -> u64 {
        self.challenge.source.cutoff
    }
    pub(crate) fn open_v2(&self) -> &DeleteRootOpenDataV2 {
        self.open
    }
    pub(crate) fn challenge_v2(&self) -> &DeleteRootChallengeDataV2 {
        self.challenge
    }
    pub(crate) fn controller_funding_cut_v3(&self) -> (&[u8], u64, u64) {
        (self.funding, self.controller_next, self.controller_end)
    }
}

impl Drop for RootDeleteClientOriginalV1<'_> {
    fn drop(&mut self) {
        if !self.terminal_complete {
            std::process::abort();
        }
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

// Closed layout selection only. The genuine upper continuation alone can
// select Apply7; every original26 receipt remains resident in its own slot.
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3 as DeleteResourcePurposeV3;

fn resource_slot_v3(purpose: DeleteResourcePurposeV3) -> usize {
    match purpose { DeleteResourcePurposeV3::Preparation26 => 0, DeleteResourcePurposeV3::Apply7 => 1, DeleteResourcePurposeV3::Network9 => 2, DeleteResourcePurposeV3::MountReap62 => 3 }
}
