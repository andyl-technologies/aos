//! Owns the same-J Controller InputsReady and the following original Root turn.
//!
//! The genuine Ready retains Source/Cache, the complete B flight, Assignment
//! and authenticated Storage Session. No decoded frame or history index can
//! create this purpose, replace an original writer or release its parents.

use std::error::Error;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1;
use super::*;
use crate::normal_root::{ProductionControllerNormalRootProfileV1, CreateStorageRootPeerReceivingOriginalsV1};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::cache_programmes::OriginalCreateStorageCacheLoanV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use super::client_session::CreateStorageEndpointRevalidationShapeDataV1;

mod transport;
mod subject;
mod cache_audit;
pub use cache_audit::create_storage_cache_current_fixed_receiving_demand_v1;
pub use cache_audit::create_storage_cache_current_dynamic_receiving_demand_v1;
mod current_turn;
mod use_tail;
mod use_signing;
mod use_preparation;
pub use use_signing::{OriginalCreateStorageUseSigningV1, CreateStorageUseSigningInputsDataV1};
pub(in crate::controller_resource_reservation) use use_signing::signing_originals_receiving_demand_v1;
pub(in crate::controller_resource_reservation::create_intake::ready)
use use_tail::releases::OriginalCreateStorageCacheReleaseAdmissionV1;
pub(in crate::controller_resource_reservation::create_intake) use use_tail::{OriginalCreateStorageRootUseAdmittedV1, OriginalCreateStorageRootSignedBoundV1, OriginalCreateStorageRootOutcomeV1, OriginalCreateStorageRootClosedV1};
pub use use_tail::{CreateStorageRootUseTailShapeDataV1, create_storage_root_use_tail_shape_v1};
pub(in crate::controller_resource_reservation::create_intake) use current_turn::OriginalCreateStorageRootUseAuthorizationV1;

use super::cache_current_proof::OriginalCreateStorageCacheCurrentProofV1;
use subject::RootExactSubjectReceiveV1;
use transport::ControllerRootTransportOriginalsV1;
use super::cache_receiving::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1};
use super::super::history::{CreateStorageWriterPositionV1, inputs_ready::InputsReadyOriginalsV1};

/// Describes the installed coordinator's actual newly retained fixed carriers.
///
/// These compiled extents are DATA supplied only by the concrete installed
/// driver before its new stages. They neither select an account nor construct
/// the genuine Ready or a Root/Storage permission.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageControllerDriverShapeDataV1 {
    /// Actual additional construction and retained coordinator bytes.
    pub bytes: usize,
    /// Actual additional resident namespace entries, excluding Rust controls.
    pub metadata_cells: usize,
}

/// Reports a closed original Root turn while every reached original stays held.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Controller to Root exchange is closed with custody retained")]
pub struct CreateStorageRootExchangeClosedV1;

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct RootExchangeOriginalsV1 {
    driver_shape: Option<CreateStorageControllerDriverShapeDataV1>,
    driver_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    driver_fixed: Option<Result<(), ResourceReservationErrorV1>>,
    entered: bool,
    shared_peak: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    inputs: InputsReadyOriginalsV1,
    returned: Option<Result<(), ResourceReservationErrorV1>>,
    after: CacheCurrentnessOriginalV1,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    closed: Option<CreateStorageRootExchangeClosedV1>,
    turn: RootTurnStateV1,
    peer: CreateStorageRootPeerReceivingOriginalsV1,
    cache_current_proof: OriginalCreateStorageCacheCurrentProofV1,
    use_cache_current_proof: OriginalCreateStorageCacheCurrentProofV1,
}

// These are the two actual simultaneously retained failed/owed samples.
// A complete positive sample drops its real native originals before reuse.
#[derive(Default)]
struct RootPeerCurrentnessSampleV1 {
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    after: CacheCurrentnessOriginalV1,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    post_cutoff: Option<Result<(), ResourceReservationErrorV1>>,
}

impl RootPeerCurrentnessSampleV1 {
    fn receiving_control_cells_v1() -> usize {
        // Inline currentness controls are covered by bytes, not name entries.
        0
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure().or_else(|| cause(&self.before_result))
            .or_else(|| self.after.failure()).or_else(|| cause(&self.after_result))
            .or_else(|| cause(&self.post_cutoff))
    }
}

#[derive(Default)]
struct RootTurnStateV1 {
    transport: ControllerRootTransportOriginalsV1,
    subject_enabled: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    hello_receive: RootExactSubjectReceiveV1,
    invitation_receive: RootExactSubjectReceiveV1,
    authorization_receive: RootExactSubjectReceiveV1,
    use_turn: current_turn::RootUseAuthorizedOriginalsV1,
    use_tail: use_tail::RootUseTailOriginalsV1,
    signing: use_signing::CreateStorageSigningOriginalsV1,
    preparation: use_preparation::PreparationRootOriginalsV1,
    preparation_terminal: use_preparation::PreparationRootOriginalsV1,
    use_gate: current_turn::RootCurrentTurnGateOriginalsV1,
    receiving: Option<RootReceivePurposeV1>,
    held_match: Option<Result<(), ResourceReservationErrorV1>>,
    invitation: Option<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::current_proofs::CurrentProofsChallengeDataV1,
        aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>,
    invitation_complete: bool,
    samples: [Option<RootPeerCurrentnessSampleV1>; 2],
    peer_shape: Option<CreateStorageEndpointRevalidationShapeDataV1>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    peer_preparation: Option<Result<(), ResourceReservationErrorV1>>,
    expected_controller: Option<CreateStorageWriterPositionV1>,
    expected_cache: Option<cache_receiving::OriginalCacheAssociationV1>,
    closed: Option<CreateStorageRootExchangeClosedV1>,
    ready_complete: bool,
    entered: bool,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    primary: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    first: Option<RootTurnFailureV1>,
    hello_peer: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    hello_clock: Option<Result<(), ResourceReservationErrorV1>>,
    initial_peer: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    owed_post: Option<RootPostFrontierV1>,
    last_native_clock: Option<aos_sandbox_model::RawPairedClockSample>,
    property_used: usize,
    property_paid: usize,
    property_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    property_funding: Option<Result<(), ResourceReservationErrorV1>>,
    cache_current: cache_audit::CacheCurrentAdmissionOriginalsV1,
    initial_cache_current: Option<cache_audit::CacheCurrentAdmissionOriginalsV1>,
    use_cache_complete: bool,
}

// Each value is armed only after its actual result was parked by this
// closed program. A generic caller cannot request a healthy-before bypass.
#[derive(Clone, Copy)]
enum RootPostFrontierV1 { UseSigningBefore, UseSigningAfter, InitialPeer, Open, HelloChunk, HelloComparison, Index, Chunk, InvitationComparison, CacheCurrentBefore, CacheCurrentAfter, CurrentBefore, CurrentSendPost, CurrentComparison, UseTailBefore, UseTailAfter, UseTailInvitation, UseTailInvitationEntry, UseProofsBefore, UseProofsAfter, UseAdmittedEntry, UseAdmittedComparison, SignedBefore, SignedAfter, SignedBoundEntry, SignedBoundComparison, PreparationBefore, PreparationAfter, PreparationTerminalBefore, PreparationTerminalAfter, OutcomeAdmission, OutcomeBefore, OutcomeAfter, OutcomeAckEntry, OutcomeComparison, UseCommitRefusal, HandoffRefusal, ClosedAdmission, ClosedBefore, ClosedAfter, ClosedEntry, ClosedComparison, SourceReleaseAdmission, SourceReleaseBefore, SourceReleaseAfter, CacheReleaseAdmission, CacheReleaseBefore, CacheReleaseAfter }

#[derive(Clone, Copy)]
enum RootReceivePurposeV1 { Hello, Invitation, Authorization, UseInvitation, UseAdmitted, SignedBound, OutcomeAcknowledged, Closed }

#[derive(Clone, Copy)]
enum RootTurnFailureV1 { Fixed, PropertyAdmission, Native, Connect, Peer, Open, Hello, HelloPeer, HelloClock, Index, Chunk, Invitation, HeldMatch }

// Keeps the same real U borrower through Root's old additional charges.
// CacheAudit borrows only the U original for this short interval; the parent
// facade retains its Cache highwater and genuine C/Source associations.
pub(super) enum RootUseReceivingV1<'turn, 'profile> {
    Original(&'turn mut super::UseReceivingOriginalsV1),
    CacheAudit(aos_sandbox_broker::controller_receiving::bank_launch::
        ControllerCacheRootObservationFundingLoanV1<'turn>),
    CurrentCacheAudit(Box<aos_sandbox_broker::controller_receiving::bank_launch::
        ControllerCacheAuditFundingLoanV1<'turn, 'profile>>),
}

impl<'profile> RootUseReceivingV1<'_, 'profile> {
    fn require_reserved_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Original(original) => original.require_reserved_v1(),
            Self::CacheAudit(original) => original.require_reserved_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::CurrentCacheAudit(original) => original.require_storage_use_reserved_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
        }
    }

    fn reserve_once(&mut self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Original(original) => original.reserve_once(demand),
            Self::CacheAudit(original) => original.reserve_additional_v1(demand)
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::CurrentCacheAudit(original) => original.borrow_root_observation_funding_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?
                .reserve_additional_v1(demand).map_err(|_| ResourceReservationErrorV1::Conflict),
        }
    }

    // Only reached Cache-U Root callers add these actual enum/borrow/return
    // controls at their old upper fixed admission, never an unrelated J fee.
    pub(super) fn cache_audit_receiving_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        size_of::<Self>().checked_mul(4)?
            // The actual Current arm maps the genuine fallible short loan into
            // this upper error before reserving the same original U.
            .checked_add(size_of::<Result<
                aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheRootObservationFundingLoanV1<'_>,
                ResourceReservationErrorV1,
            >>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), ResourceReservationErrorV1>>().checked_mul(4)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(2)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(3)?)
    }
}

/// Borrows the real Controller, Source, Cache and J for one Root transport turn.
///
/// Its private constructor splits the actual joined Ready fields alongside the
/// owning Root peer reservoir. It exposes neither a writer nor an account and
/// cannot be created from a decoded Hello, nonce, receipt or declared amount.
#[doc(hidden)]
pub struct OriginalCreateStorageRootExchangeV1<'turn, 'original, 'cache> {
    parent: &'original ProjectPreparationReservationAttemptV1,
    intake: &'turn mut Q04OriginalIntakeAttemptV1,
    controller: &'original Journal,
    source: &'original ProtectedSourceDomainJournalOwnerV1,
    profile: &'original ProductionControllerNormalRootProfileV1,
    cache: &'turn mut OriginalCreateStorageCacheLoanV1<'cache>,
    use_receiving: Option<RootUseReceivingV1<'turn, 'original>>,
    state: &'turn mut RootTurnStateV1,
}

impl<'turn, 'original, 'cache> OriginalCreateStorageRootExchangeV1<'turn, 'original, 'cache> {
    pub(crate) fn root_peer_profile_v1(&self) -> Result<&'original ProductionControllerNormalRootProfileV1, CreateStorageRootExchangeClosedV1> {
        self.require_fixed()?;
        Ok(self.profile)
    }

    // Queueing may consume the remaining interval. The actual provider checks
    // this same absolute cutoff after acquiring the physical worker slot.
    pub(crate) fn root_peer_cutoff_v1(&self) -> Result<u64, CreateStorageRootExchangeClosedV1> {
        self.require_fixed()?;
        let original = self.state.expected_cache.ok_or(CreateStorageRootExchangeClosedV1)?
            .original_cutoff_v1();
        let cutoff = self.state.transport.hello_body().ok()
            .map_or(original, |hello| original.min(hello.cutoff));
        Ok(self.state.use_tail.outcome_turn.cutoff_v1().map_or(cutoff, |outcome| cutoff.min(outcome)))
    }

    pub(crate) fn root_peer_transport_v1(&self) -> Result<&RetainedUnixStream, CreateStorageRootExchangeClosedV1> {
        self.require_fixed()?;
        self.state.transport.stream().map_err(|_| CreateStorageRootExchangeClosedV1)
    }

    pub(crate) fn root_peer_chunk_v1(&self) -> Result<&aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk, CreateStorageRootExchangeClosedV1> {
        self.state.receiver().ok_or(CreateStorageRootExchangeClosedV1)?.buffer.pending_chunk().map_err(|_| CreateStorageRootExchangeClosedV1)
    }

    pub(crate) fn require_root_peer_owed_observation_v1(&mut self) -> Result<(), CreateStorageRootExchangeClosedV1> {
        self.require_fixed()?;
        let valid = match self.state.owed_post {
            Some(RootPostFrontierV1::UseSigningBefore) => self.state.signing.before_is_owed(),
            Some(RootPostFrontierV1::UseSigningAfter) => self.state.signing.after_is_owed(),
            Some(RootPostFrontierV1::InitialPeer) => matches!(self.state.initial_peer, Some(Err(_))),
            Some(RootPostFrontierV1::Open) => self.state.transport.open_attempted(),
            Some(RootPostFrontierV1::HelloChunk) => self.state.receiver().is_some_and(RootExactSubjectReceiveV1::has_entered_attempt),
            Some(RootPostFrontierV1::HelloComparison) => self.state.hello_peer.is_some()
                || self.state.hello_clock.is_some() || self.state.transport.hello_attempted()
                || self.state.subject_enabled.is_some(),
            Some(RootPostFrontierV1::Index) => self.state.transport.index_attempted(),
            Some(RootPostFrontierV1::Chunk) => self.state.transport.chunk_attempted(),
            Some(RootPostFrontierV1::InvitationComparison) => self.state.invitation.is_some(),
            Some(RootPostFrontierV1::CacheCurrentBefore) => self.state.cache_current.root_before_is_owed_v1(),
            Some(RootPostFrontierV1::CacheCurrentAfter) => self.state.cache_current.root_after_is_owed_v1(),
            Some(RootPostFrontierV1::CurrentBefore) => self.state.use_gate.before_is_owed_v1(),
            Some(RootPostFrontierV1::CurrentSendPost) => self.state.use_gate.send_post_is_owed_v1(),
            Some(RootPostFrontierV1::CurrentComparison) => self.state.use_gate.comparison_post_is_owed_v1(),
            Some(RootPostFrontierV1::UseTailBefore) => self.state.use_tail.before_is_owed(),
            Some(RootPostFrontierV1::UseTailAfter) => self.state.use_tail.after_is_owed(),
            Some(RootPostFrontierV1::UseTailInvitation) => self.state.use_tail.invitation_post_is_owed(),
            Some(RootPostFrontierV1::UseTailInvitationEntry) => self.state.use_tail.invitation_entry_post_is_owed(),
            Some(RootPostFrontierV1::UseProofsBefore) => self.state.use_tail.proofs_before_is_owed_v1(),
            Some(RootPostFrontierV1::UseProofsAfter) => self.state.use_tail.proofs_after_is_owed_v1(),
            Some(RootPostFrontierV1::UseAdmittedEntry) => self.state.use_tail.admitted_entry_is_owed_v1(),
            Some(RootPostFrontierV1::UseAdmittedComparison) => self.state.use_tail.admitted_comparison_is_owed_v1(),
            Some(RootPostFrontierV1::SignedBefore) => self.state.use_tail.signed_turn.before_is_owed(),
            Some(RootPostFrontierV1::SignedAfter) => self.state.use_tail.signed_turn.after_is_owed(),
            Some(RootPostFrontierV1::SignedBoundEntry) => self.state.use_tail.signed_turn.entry_is_owed(),
            Some(RootPostFrontierV1::SignedBoundComparison) => self.state.use_tail.signed_turn.comparison_is_owed(),
            Some(RootPostFrontierV1::CacheReleaseAdmission) => self.state.use_tail.releases.cache_admission_is_owed_v1(),
            Some(RootPostFrontierV1::CacheReleaseBefore) => self.state.use_tail.releases.cache_before_is_owed_v1(),
            Some(RootPostFrontierV1::CacheReleaseAfter) => self.state.use_tail.releases.cache_after_is_owed_v1(),
            Some(RootPostFrontierV1::SourceReleaseAdmission) => self.state.use_tail.releases.admission_is_owed_v1(),
            Some(RootPostFrontierV1::SourceReleaseBefore) => self.state.use_tail.releases.before_is_owed_v1(),
            Some(RootPostFrontierV1::SourceReleaseAfter) => self.state.use_tail.releases.after_is_owed_v1(),
            Some(RootPostFrontierV1::UseCommitRefusal) => self.state.use_tail.commit_refusal.post_is_owed_v1(),
            Some(RootPostFrontierV1::HandoffRefusal) => self.state.use_tail.handoff_refusal.post_is_owed_v1(),
            Some(RootPostFrontierV1::ClosedAdmission) => self.state.use_tail.closed_turn.admission_is_owed_v1(),
            Some(RootPostFrontierV1::ClosedBefore) => self.state.use_tail.closed_turn.before_is_owed_v1(),
            Some(RootPostFrontierV1::ClosedAfter) => self.state.use_tail.closed_turn.after_is_owed_v1(),
            Some(RootPostFrontierV1::ClosedEntry) => self.state.use_tail.closed_turn.entry_is_owed_v1(),
            Some(RootPostFrontierV1::ClosedComparison) => self.state.use_tail.closed_turn.comparison_is_owed_v1(),
            Some(RootPostFrontierV1::OutcomeAdmission) => self.state.use_tail.outcome_turn.admission_is_owed(),
            Some(RootPostFrontierV1::OutcomeBefore) => self.state.use_tail.outcome_turn.before_is_owed(),
            Some(RootPostFrontierV1::OutcomeAfter) => self.state.use_tail.outcome_turn.after_is_owed(),
            Some(RootPostFrontierV1::OutcomeAckEntry) => self.state.use_tail.outcome_turn.entry_is_owed(),
            Some(RootPostFrontierV1::OutcomeComparison) => self.state.use_tail.outcome_turn.comparison_is_owed(),
            Some(RootPostFrontierV1::PreparationBefore) => self.state.preparation.before_is_owed(),
            Some(RootPostFrontierV1::PreparationAfter) => self.state.preparation.after_is_owed(),
            Some(RootPostFrontierV1::PreparationTerminalBefore) => self.state.preparation_terminal.before_is_owed(),
            Some(RootPostFrontierV1::PreparationTerminalAfter) => self.state.preparation_terminal.after_is_owed(),
            None => false,
        };
        if !valid {
            self.state.closed.get_or_insert(CreateStorageRootExchangeClosedV1);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.state.owed_post = None;
        Ok(())
    }

    pub(crate) fn require_fixed_root_peer_preparation_v1(&mut self,
        actual: CreateStorageEndpointRevalidationShapeDataV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if self.state.peer_preparation.is_some() {
            if self.state.peer_shape != Some(actual) || self.require_fixed().is_err() {
                self.state.closed.get_or_insert(CreateStorageRootExchangeClosedV1);
                return Err(CreateStorageRootExchangeClosedV1);
            }
            return if matches!(self.state.peer_preparation, Some(Ok(()))) { Ok(()) }
                else { Err(CreateStorageRootExchangeClosedV1) };
        }
        self.state.peer_preparation = Some(if self.require_fixed().is_ok() && self.state.peer_shape == Some(actual) {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) });
        if matches!(self.state.peer_preparation, Some(Ok(()))) { Ok(()) } else { Err(CreateStorageRootExchangeClosedV1) }
    }

    pub(crate) fn enter_root_peer_sample_once_v1(&mut self) -> Result<usize, CreateStorageRootExchangeClosedV1> {
        self.require_fixed()?;
        if !matches!(self.state.peer_preparation, Some(Ok(()))) { return Err(CreateStorageRootExchangeClosedV1); }
        let ordinal = self.state.samples.iter().position(Option::is_none).ok_or(CreateStorageRootExchangeClosedV1)?;
        let expected = self.state.expected_cache.ok_or(CreateStorageRootExchangeClosedV1)?;
        let position = match self.state.expected_controller {
            Some(position) => Ok(position),
            None if self.state.use_tail.outcome_turn.failed_position_post_is_active_v1()
                || self.state.use_tail.commit_refusal.failed_position_post_is_active_v1()
                || self.state.use_tail.handoff_refusal.failed_position_post_is_active_v1()
                || self.state.use_tail.releases.failed_position_post_is_active_v1() => {
                // This is a retained failed comparison, never a prior Controller head.
                // The actual independent Root post must still enter and keep
                // its own native and J/Cache after destinations on refusal.
                Err(ResourceReservationErrorV1::Conflict)
            }
            None => return Err(CreateStorageRootExchangeClosedV1),
        };
        let next = self.state.property_used.checked_add(1).ok_or(CreateStorageRootExchangeClosedV1)?;
        let paid = if self.use_receiving.is_some() { self.state.use_tail.paid_root_observations_v1() }
            else { self.state.property_paid };
        if next > paid { return Err(CreateStorageRootExchangeClosedV1); }
        self.state.property_used = next;
        self.state.samples[ordinal] = Some(Default::default());
        let sample = self.state.samples[ordinal].as_mut().ok_or(CreateStorageRootExchangeClosedV1)?;
        sample.before_result = Some(sample.before.observe_operation_once(CacheControlOriginalsV1 {
            parent: self.parent, intake: self.intake, controller: self.controller,
            source: self.source, profile: self.profile,
        }, &(self.cache).currentness_original_v1(), expected, position));
        // The actual destination exists before the first observation. Even a
        // negative before pass retains its ordinal for the independently owed
        // after pass; the provider checks this result before primary growth.
        Ok(ordinal)
    }

    pub(crate) fn require_root_peer_sample_entry_v1(&self, ordinal: usize) -> Result<(), CreateStorageRootExchangeClosedV1> {
        let sample = self.state.samples.get(ordinal).and_then(Option::as_ref).ok_or(CreateStorageRootExchangeClosedV1)?;
        if matches!(sample.before_result, Some(Ok(()))) && sample.before.failure().is_none() { Ok(()) }
        else { Err(CreateStorageRootExchangeClosedV1) }
    }

    pub(crate) fn after_root_peer_sample_once_v1(&mut self, ordinal: usize) -> Result<(), CreateStorageRootExchangeClosedV1> {
        let expected = self.state.expected_cache.ok_or(CreateStorageRootExchangeClosedV1)?;
        let position = match self.state.expected_controller {
            Some(position) => Ok(position),
            None if self.state.use_tail.outcome_turn.failed_position_post_is_active_v1()
                || self.state.use_tail.commit_refusal.failed_position_post_is_active_v1()
                || self.state.use_tail.handoff_refusal.failed_position_post_is_active_v1()
                || self.state.use_tail.releases.failed_position_post_is_active_v1() => {
                // This is a retained failed comparison, never a prior Controller head.
                // The actual independent Root post must still enter and keep
                // its own native and J/Cache after destinations on refusal.
                Err(ResourceReservationErrorV1::Conflict)
            }
            None => return Err(CreateStorageRootExchangeClosedV1),
        };
        // A checked Hello may impose an earlier cutoff than the accepted
        // Controller operation. A pre-syscall timeout alone does not prove
        // that the native result and independently owed posts finished in time.
        let cutoff = self.state.transport.hello_body().ok().map(|hello| hello.cutoff);
        let cutoff = match (cutoff, self.state.use_tail.outcome_turn.cutoff_v1()) {
            (Some(root), Some(outcome)) => Some(root.min(outcome)),
            (root, outcome) => root.or(outcome),
        };
        let sample = self.state.samples.get_mut(ordinal).and_then(Option::as_mut).ok_or(CreateStorageRootExchangeClosedV1)?;
        if sample.after_result.is_some() { return Err(CreateStorageRootExchangeClosedV1); }
        sample.after_result = Some(sample.after.observe_operation_once(CacheControlOriginalsV1 {
            parent: self.parent, intake: self.intake, controller: self.controller,
            source: self.source, profile: self.profile,
        }, &(self.cache).currentness_original_v1(), expected, position));
        sample.post_cutoff = Some((|| {
            let clock = sample.after.completed_clock_data_v1()?;
            // The same Cache/J association already requires clock below the
            // accepted original cutoff. Add the stricter checked Root cutoff.
            if cutoff.is_some_and(|cutoff| clock.boottime_nanoseconds() >= cutoff) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if matches!(sample.after_result, Some(Ok(()))) && sample.after.failure().is_none()
            && matches!(sample.post_cutoff, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CreateStorageRootExchangeClosedV1)
        }
    }

    pub(crate) fn require_root_peer_sample_disposal_v1(&mut self, ordinal: usize,
        actual_profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if !std::ptr::eq(actual_profile, self.profile) { return Err(CreateStorageRootExchangeClosedV1); }
        let sample = self.state.samples.get(ordinal).and_then(Option::as_ref).ok_or(CreateStorageRootExchangeClosedV1)?;
        if sample.failure().is_some() || !matches!(sample.before_result, Some(Ok(())))
            || !matches!(sample.after_result, Some(Ok(())))
            || !matches!(sample.post_cutoff, Some(Ok(()))) { return Err(CreateStorageRootExchangeClosedV1); }
        // The caller has completed its actual pure Root peer comparison. Both
        // independent native bookends are positive, so these exact fresh
        // originals can now close before the next bounded sample. No refund,
        // ledger reset, failed-owner replacement or new permission occurs.
        self.state.last_native_clock = Some(sample.after.completed_clock_data_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?);
        drop(self.state.samples[ordinal].take());
        Ok(())
    }

    fn prepay_root_peer_observations_v1(&mut self, following: usize)
        -> Result<(), CreateStorageRootExchangeClosedV1>
    {
        self.require_fixed()?;
        if self.use_receiving.is_some() {
            return self.prepay_use_root_observations_once(following);
        }
        if matches!(self.state.property_funding, Some(Err(_))) {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let required = self.state.property_used.checked_add(following)
            .ok_or(CreateStorageRootExchangeClosedV1)?;
        if required <= self.state.property_paid { return Ok(()); }

        // Only completed positive DATA comparisons are replaced here. The
        // same ledger retains every prior debit; failed admission stays resident.
        self.state.property_geometry = Some((|| {
            let base = self.state.use_gate.base_without_traffic_v1()
                .or_else(|| self.state.cache_current.base_without_traffic_v1()).or_else(||
                self.state.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let (wire, logs) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(required)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            base.checked_add(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::LogBytes, logs))
                .map_err(ResourceReservationErrorV1::Accounting)
        })());
        self.state.property_funding = Some(match self.state.property_geometry.as_ref() {
            Some(Ok(bound)) => self.intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::RootExchange, *bound),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if matches!(self.state.property_funding, Some(Ok(()))) {
            self.state.property_paid = required;
            Ok(())
        } else {
            self.state.first.get_or_insert(RootTurnFailureV1::PropertyAdmission);
            Err(CreateStorageRootExchangeClosedV1)
        }
    }

    fn require_fixed(&self) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if self.state.closed.is_some() || !matches!(self.state.fixed, Some(Ok(()))) {
            Err(CreateStorageRootExchangeClosedV1)
        } else { Ok(()) }
    }
}

impl RootExchangeOriginalsV1 {
    pub(super) fn inputs_started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake) fn use_tail_funding_failure_is_selected_v1(&self) -> bool {
        self.turn.use_tail.funding_failure_is_selected()
            || self.turn.use_tail.releases.funding_failure_is_selected_v1()
            || self.turn.signing.funding_failed()
            || (self.turn.initial_cache_current.is_some()
                && self.use_cache_current_proof.audit_failure_is_selected_v1()
                && self.turn.cache_current.use_semantic_funding_failed_v1())
    }


    pub(super) fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        // The append's actual positive return is available to the independent
        // after sampler. It does not require that sampler to have run already.
        self.inputs.position()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.driver_geometry).or_else(|| cause(&self.driver_fixed))
            .or_else(|| cause(&self.shared_peak)).or_else(|| cause(&self.geometry)).or_else(|| cause(&self.funding))
            .or_else(|| self.before.failure()).or_else(|| cause(&self.before_result))
            .or_else(|| self.inputs.failure()).or_else(|| cause(&self.returned))
            .or_else(|| self.after.failure()).or_else(|| cause(&self.after_result))
            .or_else(|| self.selected_turn_failure_v1())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    // The property guard and ordinary diagnostic use this exact same reached
    // stage selector. A later owed property failure cannot replace an earlier
    // Cache audit, signer, body or admission failure.
    fn selected_turn_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if self.turn.use_tail.closed_turn.started() {
            self.turn.use_tail.closed_turn.failure(&self.turn.use_tail, &self.peer,
                &self.turn.property_geometry, &self.turn.property_funding)
                .or_else(|| self.turn.use_tail.failure(&self.peer,
                    &self.turn.property_geometry, &self.turn.property_funding))
        } else if self.turn.use_tail.handoff_refusal.started() {
            self.turn.use_tail.handoff_refusal.failure(&self.peer)
        } else if self.turn.use_tail.releases.started() {
            self.turn.use_tail.releases.failure(&self.peer)
        } else if self.turn.use_tail.commit_refusal.started() {
            self.turn.use_tail.commit_refusal.failure(&self.peer)
        } else if self.turn.use_tail.outcome_turn.started() {
            self.turn.use_tail.outcome_turn.failure(&self.turn.use_tail, &self.peer)
                .or_else(|| self.turn.use_tail.failure(&self.peer,
                    &self.turn.property_geometry, &self.turn.property_funding))
        } else if self.turn.preparation_terminal.started() {
            self.turn.preparation_terminal.failure(&self.peer)
        } else if self.turn.preparation.started() {
            self.turn.preparation.failure(&self.peer)
                .or_else(|| self.turn.use_tail.failure(&self.peer,
                    &self.turn.property_geometry, &self.turn.property_funding))
        } else if self.turn.use_tail.signed_turn.started() {
            self.turn.use_tail.signed_turn.failure(&self.turn.use_tail, &self.peer)
                .or_else(|| self.turn.use_tail.failure(&self.peer,
                    &self.turn.property_geometry, &self.turn.property_funding))
        } else if self.turn.signing.started() {
            self.turn.signing.failure(&self.peer)
        } else if self.use_cache_current_proof.has_entered_v1() && !self.turn.use_cache_complete {
            self.turn.cache_current.failure(&self.use_cache_current_proof, &self.peer)
                .or_else(|| self.turn.use_tail.failure(&self.peer,
                    &self.turn.property_geometry, &self.turn.property_funding))
        } else if self.turn.use_tail.started() {
            self.turn.use_tail.failure(&self.peer, &self.turn.property_geometry, &self.turn.property_funding)
        } else if self.turn.use_gate.has_entered_v1() {
            self.turn.use_gate.failure(&self.turn.use_turn, &self.turn.authorization_receive,
                &self.peer, &self.turn.property_geometry, &self.turn.property_funding)
        } else if self.cache_current_proof.has_entered_v1() {
            self.turn.cache_current.failure(&self.cache_current_proof, &self.peer)
        } else {
            self.turn.failure(&self.peer)
        }
    }

    pub(super) fn require_authenticated_hello_v1(&self)
        -> Result<&aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootOpenBodyDataV1, ResourceReservationErrorV1>
    {
        if !self.turn.ready_complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.turn.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn inputs_ready_receipt_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>, ResourceReservationErrorV1>
    {
        self.require_authenticated_hello_v1()?;
        self.inputs.native_receipt_v1()
    }

    pub(super) fn authenticated_cache_challenge_v1(&self,
        actual_held: &[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CACHE_HELD_RECEIPT_BYTES_V1],
    ) -> Result<&[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::ROOT_HELLO_FRAME_BYTES_V1], ResourceReservationErrorV1> {
        self.require_authenticated_hello_v1()?;
        if !self.turn.invitation_complete { return Err(ResourceReservationErrorV1::Conflict); }
        let invitation = self.turn.invitation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        invitation.require_challenge_bytes(self.turn.transport.hello_frame(), actual_held)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(self.turn.transport.hello_frame())
    }

    pub(super) fn authenticated_hello_frame_v1(&self)
        -> Result<&[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::ROOT_HELLO_FRAME_BYTES_V1], ResourceReservationErrorV1>
    {
        self.require_authenticated_hello_v1()?;
        Ok(self.turn.transport.hello_frame())
    }
}

impl RootTurnStateV1 {
    fn receiver(&self) -> Option<&RootExactSubjectReceiveV1> {
        match self.receiving? {
            RootReceivePurposeV1::Hello => Some(&self.hello_receive),
            RootReceivePurposeV1::Invitation => Some(&self.invitation_receive),
            RootReceivePurposeV1::Authorization => Some(&self.authorization_receive),
            RootReceivePurposeV1::UseInvitation => Some(&self.use_tail.invitation),
            RootReceivePurposeV1::UseAdmitted => Some(&self.use_tail.admitted),
            RootReceivePurposeV1::SignedBound => Some(&self.use_tail.signed_bound),
            RootReceivePurposeV1::OutcomeAcknowledged => Some(&self.use_tail.outcome_ack),
            RootReceivePurposeV1::Closed => Some(&self.use_tail.closed),
        }
    }

    // Field-splits one actual receiver beside the SAME retained stream. No
    // endpoint, payer or role can be supplied through this mechanical selector.
    fn receiver_transport_mut(&mut self, purpose: RootReceivePurposeV1)
        -> (&mut RootExactSubjectReceiveV1, &mut ControllerRootTransportOriginalsV1)
    {
        let receiver = match purpose {
            RootReceivePurposeV1::Hello => &mut self.hello_receive,
            RootReceivePurposeV1::Invitation => &mut self.invitation_receive,
            RootReceivePurposeV1::Authorization => &mut self.authorization_receive,
            RootReceivePurposeV1::UseInvitation => &mut self.use_tail.invitation,
            RootReceivePurposeV1::UseAdmitted => &mut self.use_tail.admitted,
            RootReceivePurposeV1::SignedBound => &mut self.use_tail.signed_bound,
            RootReceivePurposeV1::OutcomeAcknowledged => &mut self.use_tail.outcome_ack,
            RootReceivePurposeV1::Closed => &mut self.use_tail.closed,
        };
        (receiver, &mut self.transport)
    }

    fn failure<'cause>(&'cause self, peer: &'cause CreateStorageRootPeerReceivingOriginalsV1) -> Option<&'cause (dyn Error + 'static)> {
        match self.first {
            Some(RootTurnFailureV1::Fixed) => cause(&self.geometry).or_else(|| cause(&self.fixed)),
            Some(RootTurnFailureV1::PropertyAdmission) => cause(&self.property_geometry)
                .or_else(|| cause(&self.property_funding)),
            Some(RootTurnFailureV1::Native) => self.samples.iter().flatten().find_map(RootPeerCurrentnessSampleV1::failure),
            Some(RootTurnFailureV1::Peer | RootTurnFailureV1::HelloPeer) => peer.failure(),
            Some(RootTurnFailureV1::HelloClock) => cause(&self.hello_clock),
            Some(RootTurnFailureV1::HeldMatch) => cause(&self.held_match),
            Some(RootTurnFailureV1::Invitation) => self.invitation_receive.failure(peer)
                .or_else(|| cause(&self.invitation)),
            Some(RootTurnFailureV1::Hello) => self.hello_receive.failure(peer)
                .or_else(|| cause(&self.subject_enabled)).or_else(|| self.transport.failure()),
            Some(_) => self.transport.failure(),
            None => None,
        }.or_else(|| self.samples.iter().flatten().find_map(RootPeerCurrentnessSampleV1::failure))
            .or_else(|| cause(&self.peer_preparation))
            .or_else(|| cause(&self.property_geometry)).or_else(|| cause(&self.property_funding))
            .or_else(|| cause(&self.primary)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Borrows the actual failed InputsReady or Root turn without new work.
    #[doc(hidden)]
    pub fn original_root_exchange_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.owner.root_exchange.failure()
    }

    /// Keeps the chronological Root property's nested native cause guarded.
    ///
    /// The view holds the original worker's guard. It is returned only when
    /// that exact stored property marker is the selected Root-stage failure.
    #[doc(hidden)]
    pub fn original_root_property_failure_view(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    {
        let root = &self.original.owner.root_exchange;
        let selected = root.failure()? as *const dyn Error as *const ();
        let turn = root.selected_turn_failure_v1()? as *const dyn Error as *const ();
        let peer = root.peer.failure()? as *const dyn Error as *const ();
        if selected != turn || turn != peer { return None; }
        root.peer.property_failure_view_v1()
    }

    /// Admits the installed driver's actual fixed new owners before its work.
    ///
    /// # Errors
    /// Rejects another admission, a failed original or overflowing actual
    /// compiled extents. The whole geometry and same-J payment remain resident.
    #[doc(hidden)]
    pub fn admit_installed_controller_driver_once(&mut self, actual: CreateStorageControllerDriverShapeDataV1)
        -> Result<(), CreateStorageRootExchangeClosedV1>
    {
        if self.failure().is_some() || self.original.owner.root_exchange.driver_shape.is_some() {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let state = &mut self.original.owner.root_exchange;
        state.driver_shape = Some(actual);
        state.driver_geometry = Some((|| {
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(actual.bytes)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::MetadataEntries, u64::try_from(actual.metadata_cells)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?))
        })());
        state.driver_fixed = Some(match &state.driver_geometry {
            Some(Ok(demand)) => self.original.owner.intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::RootExchange, *demand),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if matches!(state.driver_fixed, Some(Ok(()))) { Ok(()) } else { Err(CreateStorageRootExchangeClosedV1) }
    }

    /// Commits InputsReady from the same completed original B exactly once.
    ///
    /// The complete bundle remains borrowed from its actual Security flight.
    /// This append grants no Root validation, signing challenge or Prepare.
    /// The genuine Ready must remain on the installed coordinator's stack
    /// through Root, Storage and all cross-owner terminal/release posts.
    ///
    /// # Errors
    /// Retains a changed B, unfinished predecessor, admission, Native append,
    /// exact readback or independent original currentness failure. An entered
    /// negative stage permanently closes this original's later primary work.
    #[doc(hidden)]
    pub fn produce_inputs_ready_once(&mut self, bytes: &[u8]) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if self.failure().is_some() || self.original.owner.root_exchange.entered
            || !matches!(self.original.owner.root_exchange.driver_fixed, Some(Ok(()))) {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let expected_position = self.original.current_controller_history_position_v1();
        let expected = self.original.owner.cache_capture.currentness_association_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        self.original.owner.bundle.require_completed_bytes_v1(bytes)
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let shared_peak = self.original.require_operation_currentness_peak_v1(&self.cache);
        let state = &mut self.original.owner.root_exchange;
        state.entered = true;
        state.shared_peak = Some(shared_peak);
        state.geometry = Some((|| {
            state.shared_peak.as_ref().and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let fixed = std::mem::size_of::<RootExchangeOriginalsV1>().checked_mul(2)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let mut demand = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(fixed)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?);
            demand = demand.checked_add(
                aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1
                    ::fixed_framing_receiving_demand_v1().ok_or(ResourceReservationErrorV1::Conflict)?)?;
            demand = demand.checked_add(CacheCurrentnessOriginalV1::receiving_backing_demand_v1(2)?)?;
            demand = demand.checked_add(InputsReadyOriginalsV1::receiving_demand_v1(
                self.original.controller, self.original.source.journal_ref_v1())?)?;
            demand = demand.checked_add(*state.driver_geometry.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?)?;
            Ok(demand)
        })());
        state.funding = Some(match &state.geometry {
            Some(Ok(demand)) => self.original.owner.intake.reserve_create_capture_complete(
                CreateContinuationCaptureOwnerV1::RootExchange, *demand),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(state.funding, Some(Ok(()))) { return Err(CreateStorageRootExchangeClosedV1); }
        let owner = &mut *self.original.owner;
        owner.root_exchange.before_result = Some(owner.root_exchange.before.observe_operation_once(CacheControlOriginalsV1 {
            parent: &owner.parent, intake: &owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile,
        }, &(&mut self.cache).currentness_original_v1(), expected, expected_position));
        if matches!(owner.root_exchange.before_result, Some(Ok(()))) {
            owner.root_exchange.returned = Some(owner.root_exchange.inputs.produce_once(&owner.parent, &mut owner.intake,
                &owner.histories, &owner.assignment, &owner.bundle, self.original.controller, self.original.source,
                self.original.profile, bytes));
        }
        let after_position = if owner.root_exchange.inputs.started() {
            owner.root_exchange.inputs.position()
        } else {
            owner.assignment.position()
        };
        owner.root_exchange.after_result = Some(owner.root_exchange.after.observe_operation_once(CacheControlOriginalsV1 {
            parent: &owner.parent, intake: &owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile,
        }, &(&mut self.cache).currentness_original_v1(), expected, after_position));
        if owner.root_exchange.failure().is_none() && matches!(owner.root_exchange.returned, Some(Ok(())))
            && matches!(owner.root_exchange.after_result, Some(Ok(()))) {
            Ok(())
        } else {
            owner.root_exchange.closed.get_or_insert(CreateStorageRootExchangeClosedV1);
            Err(CreateStorageRootExchangeClosedV1)
        }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Sends this actual original B to its authenticated original Root stream.
    ///
    /// The same Ready stays borrowed by the installed coordinator. Its Root
    /// stream, complete Hello and every failed IO/native/peer owner stay in the
    /// original intake. This prefix issues no Use, Prepare or completion grant.
    ///
    /// # Errors
    /// Retains admission, connect/adoption, original peer, finite byte receipt,
    /// exact Hello correlation, original cutoff or independent bookend refusal.
    #[doc(hidden)]
    pub fn exchange_root_ready_once(&mut self, bytes: &[u8]) -> Result<(), CreateStorageRootExchangeClosedV1> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::transport::{OpenQueryV1, FRAME_HEADER_BYTES, INDEX_BYTES, CHUNK_HEADER_BYTES};
        use aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
        if self.failure().is_some() || self.original.owner.root_exchange.turn.entered {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.original.owner.bundle.require_completed_bytes_v1(bytes).map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let position = self.original.owner.root_exchange.inputs.position().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let expected = self.original.owner.cache_capture.currentness_association_v1().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let body = self.original.owner.root_exchange.inputs.body_data_v1().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let original_clock = self.original.owner.intake.create_storage_j_data_v1().map_err(|_| CreateStorageRootExchangeClosedV1)?.clock;
        let root_shape = CreateStorageRootPeerReceivingOriginalsV1::receiving_shape_v1(self.original.profile)
            .ok_or(CreateStorageRootExchangeClosedV1)?;
        let progress = &mut self.original.owner.root_exchange;
        progress.turn.entered = true;
        progress.turn.peer_shape = Some(root_shape);
        progress.turn.expected_controller = Some(position);
        progress.turn.expected_cache = Some(expected);
        progress.turn.geometry = Some((|| {
            let mut demand = *progress.geometry.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            demand = demand.checked_add(root_shape.checked_demand_v1().ok_or(ResourceReservationErrorV1::Conflict)?)?;
            demand = demand.checked_add(CacheCurrentnessOriginalV1::receiving_backing_demand_v1(4)?)?;
            // Each of two failed/owed Root samples has its own J before and
            // after. The existing HistoryNames peak covers two negative pairs;
            // this genuine Root purpose prepays the other two before any IO.
            // A failed J after cannot suppress the prearmed owed Root sample.
            let names_peak = crate::journal::create_storage_name_peak_demand_v1()?;
            demand = demand.checked_add(ResourceVector::ZERO.with(D::OpenFiles,
                names_peak.get(D::OpenFiles)))?;
            // Actual peer-pinned socket adoption retains one stream and one
            // peer pidfd. Its returned error owns its entire partial prefix.
            let (admission_bytes, admission_files) = RetainedUnixStream::retained_admission_obligations_v1();
            // Actual borrowed loan, fixed Hello/invitation/index return
            // models and frame headers exist outside the retained parent.
            // Their constructor/return overlap is named before the first loan.
            let construction = std::mem::size_of::<OriginalCreateStorageRootExchangeV1<'_, '_, '_>>()
                .checked_add(std::mem::size_of::<OpenQueryV1>())
                .and_then(|value| value.checked_add(std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootHelloDataV1<'_>>()))
                .and_then(|value| value.checked_add(std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::create_storage_history::current_proofs::CurrentProofsChallengeDataV1>()))
                .and_then(|value| value.checked_add(std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::create_storage_history::transport::TransferIndexV1>()))
                .and_then(|value| value.checked_add(std::mem::size_of::<aos_sandbox_model::RawPairedClockSample>()))
                .and_then(|value| value.checked_add(FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES))
                .and_then(|value| value.checked_mul(2))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let socket_bytes = admission_bytes.checked_add(8 * 256)
                .and_then(|value| value.checked_add(construction))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let receive_geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let (receive_bytes, receive_files) = receive_geometry.receive_obligations_v1();
            // The lower native receive provider retains its existing namespace
            // bound. Inline frame, IO and comparison controls add only bytes.
            let cells = receive_geometry.receiving_metadata_cells_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            // One bounded subject packet is disposed only after its actual
            // copy, Root observation and both same-J posts complete. The raw
            // exact Hello destination and poll construction remain additional.
            let receive_bytes = receive_bytes.checked_add(612 + 248)
                .and_then(|value| value.checked_add(std::mem::size_of::<subject::RootReadinessOriginalsV1>()))
                .and_then(|value| value.checked_add(std::mem::size_of::<rustix::event::PollFd<'_>>()))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let socket_bytes = socket_bytes.checked_add(receive_bytes)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let chunks = bytes.len().div_ceil(CLAIM_CHUNK_BYTES);
            let traffic = chunks.checked_mul(FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES)
                .and_then(|value| value.checked_add(bytes.len()))
                .and_then(|value| value.checked_add(FRAME_HEADER_BYTES + INDEX_BYTES + 112 + 612 + 248))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            demand = demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(socket_bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::OpenFiles, u64::try_from(receive_files.checked_add(admission_files).ok_or(ResourceReservationErrorV1::Conflict)?)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::Pids, u64::try_from(CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::NetworkBytes, u64::try_from(traffic).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                // The exact emitted Open/index/B chunks are also operation
                // result bytes. Hello/invitation are only incoming traffic.
                .with(D::OutputBytes, u64::try_from(traffic.checked_sub(612 + 248)
                    .ok_or(ResourceReservationErrorV1::Conflict)?)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?))?;
            Ok(demand)
        })());
        progress.turn.fixed = Some(match &progress.turn.geometry {
            Some(Ok(demand)) => self.original.owner.intake.reserve_create_capture_complete(CreateContinuationCaptureOwnerV1::RootExchange, *demand),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(progress.turn.fixed, Some(Ok(()))) {
            progress.turn.first = Some(RootTurnFailureV1::Fixed);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let owner = &mut *self.original.owner;
        let lane = owner.intake.create_lane().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            use_receiving: None,
            parent: &owner.parent, intake: &mut owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile, cache: &mut self.cache,
            state: &mut owner.root_exchange.turn,
        };
        let open = OpenQueryV1 { controller_nonce: body.association.controller_nonce,
            lane,
            seed: body.association.seed, ready: body.ready };
        let peer = &mut owner.root_exchange.peer;
        let primary = loan.run_ready_prefix_once(peer, open, body.association.cutoff, original_clock, bytes);
        loan.state.primary = Some(primary);
        if matches!(loan.state.primary, Some(Ok(()))) && loan.state.first.is_none()
            && loan.state.transport.ready_sent() {
            loan.state.ready_complete = true;
            Ok(())
        } else { Err(CreateStorageRootExchangeClosedV1) }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Receives the Root-first signer invitation on this same original stream.
    ///
    /// The actual completed B and live held Cache are compared before receiving.
    /// The received subject, exact transfer sequence and original Hello are
    /// checked before one independently owed Root/J post seals the challenge.
    ///
    /// # Errors
    /// Retains a different bundle or live Cache receipt, failed strict receive,
    /// changed original correlation, cutoff or independently owed peer post.
    #[doc(hidden)]
    pub fn await_root_cache_invitation_once(&mut self, bytes: &[u8])
        -> Result<(), CreateStorageRootExchangeClosedV1>
    {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            cache_held::{CacheHeldReceiptDataV1, CACHE_HELD_RECEIPT_BYTES_V1},
            current_proofs::CurrentProofsChallengeDataV1,
            ready::ReadyBundleDataV1,
            root_open::RootHelloDataV1,
        };
        if self.failure().is_some() || !self.original.owner.root_exchange.turn.ready_complete
            || self.original.owner.root_exchange.turn.held_match.is_some() {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        // B's framing/receipt models are fixed, and their complete receiving
        // geometry is part of the original pre-append/transport admission.
        let held = (|| {
            self.original.owner.bundle.require_completed_bytes_v1(bytes)?;
            let bundle = ReadyBundleDataV1::decode(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let held: &[u8; CACHE_HELD_RECEIPT_BYTES_V1] = bundle.cache_held.try_into()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let receipt = CacheHeldReceiptDataV1::decode(held, bundle.lane)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let live = self.cache.borrow_pre_root_cut_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if live.held_receipt_data_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != receipt {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(held)
        })();
        self.original.owner.root_exchange.turn.held_match = Some(held.as_ref().map(|_| ()).map_err(|_| ResourceReservationErrorV1::Conflict));
        let held = match held {
            Ok(held) => held,
            Err(_) => {
                self.original.owner.root_exchange.turn.first.get_or_insert(RootTurnFailureV1::HeldMatch);
                return Err(CreateStorageRootExchangeClosedV1);
            }
        };
        let original_cutoff = self.original.accepted().map_err(|_| CreateStorageRootExchangeClosedV1)?.original_cutoff;
        let owner = &mut *self.original.owner;
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            use_receiving: None,
            parent: &owner.parent, intake: &mut owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile, cache: &mut self.cache,
            state: &mut owner.root_exchange.turn,
        };
        let peer = &mut owner.root_exchange.peer;
        let cutoff = original_cutoff.min(loan.state.transport.hello_body()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?.cutoff);
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let received = loan.receive_root_subject_once(peer, cutoff, &geometry, RootReceivePurposeV1::Invitation);
        if received.is_err() {
            loan.state.first.get_or_insert(RootTurnFailureV1::Invitation);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        loan.state.invitation = Some((|| {
            let body = loan.state.transport.hello_body()?;
            let hello = RootHelloDataV1::decode(loan.state.transport.hello_frame(), body.open)?;
            let value = CurrentProofsChallengeDataV1::decode_frame(
                loan.state.invitation_receive.buffer.bytes(), &hello, loan.state.transport.completed_index()?)?;
            value.require_challenge_bytes(loan.state.transport.hello_frame(), held)?;
            Ok(value)
        })());
        if !matches!(loan.state.invitation, Some(Ok(_))) {
            loan.state.first.get_or_insert(RootTurnFailureV1::Invitation);
        }
        // The final strict receive prepaid this separate pure-comparison post.
        // It runs even when exact invitation decoding/digest equality refused.
        loan.state.owed_post = Some(RootPostFrontierV1::InvitationComparison);
        let post = peer.recheck_once(&mut loan);
        if post.is_err() { loan.state.first.get_or_insert(RootTurnFailureV1::Peer); }
        if matches!(loan.state.invitation, Some(Ok(_))) && post.is_ok() && loan.state.first.is_none() {
            loan.state.invitation_complete = true;
            Ok(())
        } else {
            Err(CreateStorageRootExchangeClosedV1)
        }
    }
}

impl<'turn, 'original, 'cache> OriginalCreateStorageRootExchangeV1<'turn, 'original, 'cache> {
    fn run_ready_prefix_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        open: aos_sandbox_protocol::domain_ledger::create_storage_history::transport::OpenQueryV1,
        original_cutoff: u64, original_clock: aos_sandbox_model::RawPairedClockSample, bytes: &[u8],
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        self.require_fixed_root_peer_preparation_v1(self.state.peer_shape.ok_or(CreateStorageRootExchangeClosedV1)?)?;
        // Connect, initial capture and its possible owed negative post are
        // all admitted before the first socket growth. The connect bookend is
        // conservatively included although it issues no PID1 row itself.
        self.prepay_root_peer_observations_v1(3)?;
        let connect_sample = self.enter_root_peer_sample_once_v1()?;
        let before = self.require_root_peer_sample_entry_v1(connect_sample);
        if before.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Native); }
        let connect = if before.is_ok() { self.state.transport.connect_once() }
            else { Err(aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1::Correlation) };
        if connect.is_err() && before.is_ok() { self.state.first.get_or_insert(RootTurnFailureV1::Connect); }
        let after = self.after_root_peer_sample_once_v1(connect_sample);
        if after.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Native); }
        before?;
        connect.map_err(|_| CreateStorageRootExchangeClosedV1)?;
        after?;
        // Socket creation/adoption itself is complete and both actual J posts
        // are positive. Peer identity is the immediately following new stage.
        let profile = self.profile;
        self.require_root_peer_sample_disposal_v1(connect_sample, profile)?;
        self.state.initial_peer = Some(peer.capture_once(self));
        if matches!(self.state.initial_peer, Some(Err(_))) {
            self.state.first.get_or_insert(RootTurnFailureV1::Peer);
            // This is the primary peer capture, so its actual independently
            // owed Root observation still runs once. It cannot publish a
            // positive binding or clear either failed native destination.
            self.state.owed_post = Some(RootPostFrontierV1::InitialPeer);
            let _owed = peer.recheck_once(self);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.state.subject_enabled = Some(self.state.transport.stream_mut().map_err(|_| CreateStorageRootExchangeClosedV1)?
            .enable_subject_reporting().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from));
        if !matches!(self.state.subject_enabled, Some(Ok(()))) {
            self.state.first.get_or_insert(RootTurnFailureV1::Hello);
            self.state.owed_post = Some(RootPostFrontierV1::HelloComparison);
            let _owed = peer.recheck_once(self);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.prepay_root_peer_observations_v1(2)?;
        let sent = self.state.transport.send_open_once(open, original_cutoff);
        if sent.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Open); }
        self.state.owed_post = Some(RootPostFrontierV1::Open);
        let post = peer.recheck_once(self);
        if post.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Peer); }
        sent.map_err(|_| CreateStorageRootExchangeClosedV1)?;
        post?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| CreateStorageRootExchangeClosedV1)?;
        let received = self.receive_root_subject_once(peer, original_cutoff, &geometry, RootReceivePurposeV1::Hello);
        if received.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Hello); }
        received?;
        let state = &mut self.state;
        let accepted = state.transport.accept_hello_once(state.hello_receive.buffer.bytes(), open);
        if accepted.is_err() {
            state.first.get_or_insert(RootTurnFailureV1::Hello);
            state.owed_post = Some(RootPostFrontierV1::HelloComparison);
            let _owed = peer.recheck_once(self);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let hello = *self.state.transport.hello_body().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        self.state.hello_peer = Some(peer.require_hello_v1(self, &hello));
        if !matches!(self.state.hello_peer, Some(Ok(()))) {
            self.state.first.get_or_insert(RootTurnFailureV1::HelloPeer);
            self.state.owed_post = Some(RootPostFrontierV1::HelloComparison);
            let _owed = peer.recheck_once(self);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let after_hello = self.state.last_native_clock.ok_or(CreateStorageRootExchangeClosedV1)?;
        self.state.hello_clock = Some(if hello.boot == original_clock.host_boot_id()
            && hello.boot == after_hello.host_boot_id()
            && hello.started >= original_clock.boottime_nanoseconds()
            && hello.started <= after_hello.boottime_nanoseconds()
            && after_hello.boottime_nanoseconds() < original_cutoff
            && after_hello.boottime_nanoseconds() < hello.cutoff {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) });
        if !matches!(self.state.hello_clock, Some(Ok(()))) {
            self.state.first.get_or_insert(RootTurnFailureV1::HelloClock);
            self.state.owed_post = Some(RootPostFrontierV1::HelloComparison);
            let _owed = peer.recheck_once(self);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        let cutoff = original_cutoff.min(hello.cutoff);
        self.prepay_root_peer_observations_v1(2)?;
        let sent = self.state.transport.send_index_once(bytes, cutoff);
        if sent.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Index); }
        self.state.owed_post = Some(RootPostFrontierV1::Index);
        let post = peer.recheck_once(self);
        if post.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Peer); }
        sent.map_err(|_| CreateStorageRootExchangeClosedV1)?;
        post?;
        while !self.state.transport.ready_sent() {
            self.prepay_root_peer_observations_v1(2)?;
            let sent = self.state.transport.send_next_chunk_once(bytes, cutoff);
            if sent.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Chunk); }
            self.state.owed_post = Some(RootPostFrontierV1::Chunk);
            let post = peer.recheck_once(self);
            if post.is_err() { self.state.first.get_or_insert(RootTurnFailureV1::Peer); }
            sent.map_err(|_| CreateStorageRootExchangeClosedV1)?;
            post?;
            // Copy/checksum/write and actual independent peer+same-J posts are
            // all positive. Dispose this exact IO roster before the next chunk.
            self.state.transport.dispose_positive_chunk_once().map_err(|_| CreateStorageRootExchangeClosedV1)?;
        }
        Ok(())
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
pub(in crate::controller_resource_reservation::create_intake)
fn root_layout_diagnostics_v1() -> [(&'static str, usize); 12] {
    use std::mem::size_of;
    [
        ("whole", size_of::<RootExchangeOriginalsV1>()),
        ("turn", size_of::<RootTurnStateV1>()),
        ("peer", size_of::<CreateStorageRootPeerReceivingOriginalsV1>()),
        ("cache_proof", size_of::<OriginalCreateStorageCacheCurrentProofV1>()),
        ("tail", size_of::<use_tail::RootUseTailOriginalsV1>()),
        ("transport", size_of::<ControllerRootTransportOriginalsV1>()),
        ("subject", size_of::<RootExactSubjectReceiveV1>()),
        ("cache_current", size_of::<cache_audit::CacheCurrentAdmissionOriginalsV1>()),
        ("signing", size_of::<use_signing::CreateStorageSigningOriginalsV1>()),
        ("preparation", size_of::<use_preparation::PreparationRootOriginalsV1>()),
        ("sample", size_of::<RootPeerCurrentnessSampleV1>()),
        ("control", size_of::<CacheCurrentnessOriginalV1>()),
    ]
}
