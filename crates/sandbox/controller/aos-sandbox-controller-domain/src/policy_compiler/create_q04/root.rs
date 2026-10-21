//! Same-original-flight Root custody for the generation-one Q04 continuation.
//!
//! One local owner parks its accepted socket before clock, peer, adoption or
//! native-open checks. Successful opens are parked immediately. Short floor
//! loans end before mutation; no decoded Claim, copied head or public callback
//! supplies an independent owner. Durable policy admission is a subgate only.

use aos_sandbox_policy::signed_inputs::PolicyDeploymentInputsV1;

use aos_sandbox_policy::native::{
    RootAuthorityQ04FlightOriginalV1, RootPolicyPublicationWorkV1,
    RootOriginalInputLoanV1 as RootNativeInputLoanV1,
};
use aos_sandbox_broker::receiving::{RootQ04OriginBorrowerV1, RootQ04OriginPurposeV1};
use super::{project_root_policy_error_v1,
    project_root_native_journal_error_v1, project_root_q04_origin_error_v1};

use aos_sandbox_protocol::source_genesis_wire::{
    RootCreateQ04TransferKindV1,
    RootSourceGenesisFrameKindV1,
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1,
    ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    decode_root_create_q04_transfer_v1,
    decode_root_source_genesis_frame_v2,
    encode_root_create_q04_transfer_v1,
    encode_root_source_genesis_frame_v2,
};

use crate::policy_compiler::create_q04::project_q04_wire_error_v1;

use crate::hierarchy::genesis_profile::project_source_genesis_wire_error_v1;

use aos_sandbox_protocol::source_genesis_wire as genesis_wire;

use std::cell::{Cell, RefCell};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use aos_sandbox_model::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;

use aos_sandbox_ledger_replay::replay::root_genesis_records::SourceHierarchyFloorRecordV1;

use crate::normal_root::ProductionNormalRootStartupV1;

use super::super::{
    PinnedSourceHoldReadbackSignerV1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1,
    SourceTreeGenesisChallengeV1, SourceTreeGenesisIntentContextV1,
};
use super::{CreateQ04ErrorV1, Q04CutIdentityV1};
use super::authority_error::map_root_authority_error_v1;

// Old Genesis-result frontiers preserve their original outer error lane. The
// separate native Q04 phase mapper retains direct Q04 semantic error classes.
fn project_root_authority_genesis_error_v1(
    error: aos_sandbox_policy::native::RootAuthorityErrorV1,
) -> CreateQ04ErrorV1 {
    CreateQ04ErrorV1::SourceGenesis(error.into())
}

const MAXIMUM_ROOT_FLIGHT: Duration = Duration::from_secs(65);
const MAXIMUM_SOURCE_OBSERVATIONS: usize = 16;

/// Selects the existing-only generation-one Q04 continuation on the fixed socket.
pub const ROOT_CREATE_Q04_QUERY_MAGIC_V1: &[u8; 8] =
    aos_sandbox_protocol::domain_ledger::create_q04_history::Q04_ORIGINAL_QUERY_MAGIC_V1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootQ04PreludePhaseV1 {
    Parked,
    Hello,
    PreparedSource,
    Anchored,
    CompletedSource,
    Completed,
    Preview,
    Prefunded,
    RefreshedSource,
    BindingHeld,
    PolicyCommitted,
    Decided,
    PolicyAcknowledged,
    ReleaseAuthorized,
    Settled,
    FinalClearance,
}

#[derive(Clone, Copy)]
enum RootSourceObservationPurposeV1 {
    Preparation,
    Completion,
    Refresh,
}

#[derive(Clone, Copy)]
enum RootControllerFrameSlotV1 {
    Prepare,
    Complete,
    Refresh,
    Prehold,
    Claim,
    Acknowledgement,
}

// These identities are selected by the actual privileged daemon configuration
// after its startup admission. A client Claim does not populate them.
#[derive(Clone, Copy)]
struct RootServiceIdentitiesV1 {
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    cache_uid: u32,
}

// Opaque nonzero representatives only fill fields whose future authentic
// values have fixed widths. They are not an authority/readback substitute.
pub(crate) fn capacity_shape_digest(identity: &Q04CutIdentityV1, field: u8) -> Result<ObjectDigest, CreateQ04ErrorV1> {
    aos_sandbox_policy::q04_data::capacity_shape_digest(identity, field).map_err(Into::into)
}

pub(super) fn root_decision_record(
    identity: &Q04CutIdentityV1,
    earlier_authority_transaction: [u8; 16],
    state_commit_sequence: u64,
    authority_before_sequence: u64,
    source_held: ObjectDigest,
    cache_held: ObjectDigest,
) -> Result<super::Q04RootDecisionV1, CreateQ04ErrorV1> {
    aos_sandbox_policy::q04_data::root_decision_record(identity, earlier_authority_transaction, state_commit_sequence, authority_before_sequence, source_held, cache_held).map_err(Into::into)
}

pub(crate) fn root_consumed_gate_record(
    identity: &Q04CutIdentityV1,
    decision: &super::Q04RootDecisionV1,
) -> Result<super::Q04EffectSubgateV1, CreateQ04ErrorV1> {
    aos_sandbox_protocol::domain_ledger::create_q04_history::root_consumed_gate_record_v1(identity, decision).map_err(Into::into)
}

// Native refusal diagnostics select the actual resident cause. They never
// manufacture a replacement owned error merely to cross an upper helper.
enum RootActionFailureV1 {
    Owned(CreateQ04ErrorV1),
    AuthorityHeld,
    PolicyHeld,
}

impl From<CreateQ04ErrorV1> for RootActionFailureV1 {
    fn from(error: CreateQ04ErrorV1) -> Self { Self::Owned(error) }
}

impl From<aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1> for RootActionFailureV1 {
    fn from(error: aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1) -> Self {
        Self::Owned(CreateQ04ErrorV1::from(error))
    }
}

impl From<crate::journal::JournalError> for RootActionFailureV1 {
    fn from(error: crate::journal::JournalError) -> Self {
        Self::Owned(CreateQ04ErrorV1::from(error))
    }
}

/// Retains the original accepted Q04 stream and actual fixed Root owners.
///
/// This negative-custody owner grants no publication, Create or live floor
/// authority. Its selected caller keeps it resident through final clearance;
/// abandoning an uncleared attempt terminates the process before owner drops.
/// Lower accepted-stream discrimination and opener/RPC pre-return prefixes are
/// not recovered by this owner.
pub struct OriginalRootCreateQ04AttemptV1<'target, 'authority, 'origin, 'startup> {
    origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    root: Option<RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>>,
    work: RootPolicyPublicationWorkV1<'target>,
    admission: Option<RootQ04AdmissionDataV1>,
    clock: Option<RawPairedClockSample>,
    started: Option<Instant>,
    cause: RefCell<Option<CreateQ04ErrorV1>>,
    first_owner: Cell<Option<RootQ04FirstCauseOwnerV1>>,
    debt_owner: Cell<Option<RootQ04FirstCauseOwnerV1>>,
    postcheck_debt: RefCell<Option<CreateQ04ErrorV1>>,
    received: Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    phase: RootQ04PreludePhaseV1,
    controller_frame: Vec<u8>,
    completion_frame: Vec<u8>,
    refresh_frames: Vec<Vec<u8>>,
    sent: Vec<u8>,
    sent_progress: Cell<usize>,
    send_result: RefCell<Option<Result<usize, rustix::io::Errno>>>,
    shutdown_entered: bool,
    shutdown_entry: Option<Result<(), CreateQ04ErrorV1>>,
    source_received: Option<Result<super::super::SourceTreeGenesisReadbackPacketV2, std::io::Error>>,
    source_observations: Vec<super::super::SourceTreeGenesisReadbackPacketV2>,
    source_resource_posts: Vec<RootResourceSourcePostsV2>,
    floor: Option<SourceHierarchyFloorRecordV1>,
    stage: Option<super::super::binding_v2::Q04RootStageRecipeV1>,
    preview: Vec<u8>,
    preview_chunk: Vec<u8>,
    prehold: Vec<u8>,
    prehold_frame: Vec<u8>,
    prehold_reply: Option<super::Q04PreholdPublicationDataV1>,
    controller_clock: Option<[u8; 32]>,
    claim: Vec<u8>,
    claim_frame: Vec<u8>,
    claim_source_observation: Option<usize>,
    acknowledgement_frames: Vec<Vec<u8>>,
    cache_terminal_outcomes: Vec<aos_sandbox_policy::native::RootAuthorityCacheTerminalOutcomeV1>,
    refresh_resume: Option<RootQ04PreludePhaseV1>,
    controller_complete: Vec<u8>,
    source_complete: Vec<u8>,
    cleared: bool,
}

// These are passive copies derived once from the entered native role. No
// supplied query, identity or clock can populate this admission slot.
struct RootQ04AdmissionDataV1 {
    identities: RootServiceIdentitiesV1,
    request: [u8; 32],
}

// This is a chronological diagnostic selector, never a currentness grant.
// Native marker failures keep their actual error on that same native owner.
#[derive(Clone, Copy)]
enum RootQ04FirstCauseOwnerV1 {
    UpperOwned,
    AuthorityHeld,
    PolicyHeld,
}

impl<'target, 'authority, 'origin, 'startup>
    OriginalRootCreateQ04AttemptV1<'target, 'authority, 'origin, 'startup>
{
    /// Parks the actual ordinary endpoint and its optional legacy startup.
    ///
    /// This inert transition exposes no startup field or selected lender.
    /// Native admission preserves the original request/identity checks and
    /// first clock before refusing absent or selected startup custody.
    #[must_use]
    pub fn park_ordinary_transport_v1(
        original: UnixStream,
        startup: Option<&'startup ProductionNormalRootStartupV1>,
        request: [u8; 32],
        identities: [u32; 4],
    ) -> aos_sandbox_broker::receiving::RootQ04OrdinaryTransportOriginalV1<'startup> {
        aos_sandbox_broker::receiving::RootQ04OrdinaryTransportOriginalV1::new(
            original,
            startup.map(ProductionNormalRootStartupV1::native_startup_original_v1),
            request,
            identities,
        )
    }

    /// Parks the entered Authority, actual target work and same native Origin.
    ///
    /// Construction performs no I/O. Actual request, identities and original
    /// clock are derived fallibly only after all consumed owners are resident.
    #[must_use]
    pub fn new(
        root: RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>,
        work: RootPolicyPublicationWorkV1<'target>,
        origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    ) -> Self {
        Self {
            origin,
            root: Some(root),
            work,
            admission: None,
            clock: None,
            started: None,
            cause: RefCell::new(None),
            first_owner: Cell::new(None),
            debt_owner: Cell::new(None),
            postcheck_debt: RefCell::new(None),
            received: None,
            phase: RootQ04PreludePhaseV1::Parked,
            controller_frame: Vec::new(),
            completion_frame: Vec::new(),
            refresh_frames: Vec::new(),
            sent: Vec::new(),
            sent_progress: Cell::new(0),
            send_result: RefCell::new(None),
            shutdown_entered: false,
            shutdown_entry: None,
            source_received: None,
            source_observations: Vec::new(),
            source_resource_posts: Vec::new(),
            floor: None,
            stage: None,
            preview: Vec::new(),
            preview_chunk: Vec::new(),
            prehold: Vec::new(),
            prehold_frame: Vec::new(),
            prehold_reply: None,
            controller_clock: None,
            claim: Vec::new(),
            claim_frame: Vec::new(),
            claim_source_observation: None,
            acknowledgement_frames: Vec::new(),
            cache_terminal_outcomes: Vec::new(),
            refresh_resume: None,
            controller_complete: Vec::new(),
            source_complete: Vec::new(),
            cleared: false,
        }
    }

    fn admission_data_v1(&self) -> Result<&RootQ04AdmissionDataV1, CreateQ04ErrorV1> {
        self.admission.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)
    }

    fn derive_original_admission_once_v1(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.admission.is_some() || self.clock.is_some() || self.started.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let root = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.require_same_origin_v1(&self.origin).map_err(project_root_authority_genesis_error_v1)?;
        let request = root.request_data_v1().map_err(project_root_authority_genesis_error_v1)?;
        let [controller_uid, controller_gid, source_uid, cache_uid] =
            root.identities_data_v1().map_err(project_root_authority_genesis_error_v1)?;
        let (clock, started) = root.original_clock_data_v1()
            .map_err(project_root_authority_genesis_error_v1)?;
        self.admission = Some(RootQ04AdmissionDataV1 {
            identities: RootServiceIdentitiesV1 {
                controller_uid, controller_gid, source_uid, cache_uid,
            },
            request,
        });
        self.clock = Some(clock);
        self.started = Some(started);
        Ok(())
    }

    /// Checks the existing ordinary opening at its concrete owner frontier.
    ///
    /// The daemon calls this between actual Origin admission, Authority/nonce
    /// admission and Target opening. It does not create a selected lender.
    ///
    /// # Errors
    /// Preserves the first actual startup, peer, queue, Authority, Target-name
    /// or original-clock failure; ordinary prefix refusal skips its final clock.
    pub fn recheck_ordinary_opening_v1(
        origin: RootQ04OriginBorrowerV1<'_, '_>,
        root: Option<&RootAuthorityQ04FlightOriginalV1<'_, '_, '_>>,
        work: Option<&RootPolicyPublicationWorkV1<'_>>,
    ) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        if origin.purpose_v1() != RootQ04OriginPurposeV1::Ordinary {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let mut original = origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?;
        let current = original.begin_input_current_once_v1()
            .map_err(project_root_q04_origin_error_v1)?;
        if let Some(root) = root {
            root.recheck().map_err(project_root_authority_genesis_error_v1)?;
        }
        if let Some(work) = work {
            work.require_original_target_names_v1().map_err(project_root_native_journal_error_v1)?;
        }
        current.finish_once_v1().map_err(project_root_q04_origin_error_v1)
    }

    /// Begins only an existing completed gen1 flight without issuing a new Stage.
    ///
    /// # Errors
    /// Retains the first actual startup, peer, clock, fixed-open or transport
    /// failure. The caller must not retry, release or drop the failed attempt.
    pub fn begin_existing_gen1(&mut self) -> Result<(), ()> {
        let outcome = self.begin_original_existing_gen1();
        self.retain_outcome(outcome)
    }

    fn begin_original_existing_gen1(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Parked {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.derive_original_admission_once_v1()?;
        let admission = self.admission_data_v1()?;
        if admission.request[..8] != *ROOT_CREATE_Q04_QUERY_MAGIC_V1
            || admission.request[8..24] == [0; 16]
            || admission.request[24..32] != [0; 8]
            || self.origin.purpose_v1() != RootQ04OriginPurposeV1::Ordinary
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let request = admission.request;
        let identities = admission.identities;
        let nonce = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .nonce_data_v1().map_err(project_root_authority_genesis_error_v1)?;
        self.sent.try_reserve_exact(56)?;
        self.sent.resize(56, 0);
        self.sent[..8].copy_from_slice(ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1);
        self.sent[8..10].copy_from_slice(&1_u16.to_be_bytes());
        self.sent[16..32].copy_from_slice(&request[8..24]);
        self.sent[32..48].copy_from_slice(&nonce);
        self.sent[48..52].copy_from_slice(&identities.source_uid.to_be_bytes());
        self.sent[52..56].copy_from_slice(&identities.controller_uid.to_be_bytes());
        self.write_original(&self.sent)?;
        self.phase = RootQ04PreludePhaseV1::Hello;
        Ok(())
    }

    /// Lends the exact Source request selected by the original Prepare packet.
    ///
    /// # Errors
    /// Retains a malformed/nonhistorical packet, missing existing floor or
    /// original owner/clock failure. Global Empty and new genesis are refused.
    pub fn read_existing_source_preparation(
        &mut self,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'authority, 'origin, 'startup>, ()> {
        let prepared = self.prepare_source_observation(RootSourceObservationPurposeV1::Preparation);
        let (project, challenge, context) = self.retain_outcome(prepared)?;
        self.source_observation_loan(project, challenge, context, RootSourceObservationPurposeV1::Preparation)
    }

    /// Lends the exact Source request selected by actual Controller Complete.
    ///
    /// # Errors
    /// Retains changed completion, current gen1 or original transport custody.
    /// The returned loan must park the actual RPC result before postchecks.
    pub fn read_existing_source_completion(
        &mut self,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'authority, 'origin, 'startup>, ()> {
        let prepared = self.prepare_source_observation(RootSourceObservationPurposeV1::Completion);
        let (project, challenge, context) = self.retain_outcome(prepared)?;
        self.source_observation_loan(project, challenge, context, RootSourceObservationPurposeV1::Completion)
    }

    /// Refreshes completed gen1 from a new actual packet on the same held flight.
    ///
    /// This read-only request issues no Stage, hold, publication or phase
    /// authorization. Later purpose-specific actions still compare their real
    /// native history and owner cuts. Every earlier complete packet remains
    /// resident; the actual returned Source result must be parked in the loan.
    ///
    /// # Errors
    /// Retains a wrong phase, full bounded history, changed genuine Complete,
    /// Source/floor, original peer, startup or original cutoff.
    pub fn read_current_gen1_refresh(
        &mut self,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'authority, 'origin, 'startup>, ()> {
        let prepared = self.prepare_source_observation(RootSourceObservationPurposeV1::Refresh);
        let (project, challenge, context) = self.retain_outcome(prepared)?;
        self.source_observation_loan(project, challenge, context, RootSourceObservationPurposeV1::Refresh)
    }

    fn prepare_source_observation(
        &mut self,
        purpose: RootSourceObservationPurposeV1,
    ) -> Result<
        (
            aos_sandbox_model::ProjectId,
            SourceTreeGenesisChallengeV1,
            SourceTreeGenesisIntentContextV1,
        ),
        CreateQ04ErrorV1,
    > {
        let expected = match purpose {
            RootSourceObservationPurposeV1::Preparation => RootQ04PreludePhaseV1::Hello,
            RootSourceObservationPurposeV1::Completion => RootQ04PreludePhaseV1::Anchored,
            RootSourceObservationPurposeV1::Refresh => {
                if self.refresh_resume.is_some()
                    || !matches!(
                        self.phase,
                        RootQ04PreludePhaseV1::Preview
                            | RootQ04PreludePhaseV1::Prefunded
                            | RootQ04PreludePhaseV1::Decided
                            | RootQ04PreludePhaseV1::PolicyAcknowledged
                            | RootQ04PreludePhaseV1::ReleaseAuthorized
                            | RootQ04PreludePhaseV1::Settled
                            | RootQ04PreludePhaseV1::FinalClearance
                    )
                {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.refresh_resume = Some(self.phase);
                self.phase
            }
        };
        if self.phase != expected
            || self.source_received.is_some()
            || self.source_observations.len() >= MAXIMUM_SOURCE_OBSERVATIONS
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // Reserve before the RPC: moving its returned fixed packet later is
        // infallible. This is bounded storage, not a heap/kernel funding claim.
        self.source_observations.try_reserve_exact(1)?;
        if matches!(purpose, RootSourceObservationPurposeV1::Completion) {
            if !self.controller_complete.is_empty() || !self.source_complete.is_empty() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            let bytes = if self
                .floor
                .as_ref()
                .is_some_and(|floor| floor.receipt().auth_packet().len() == 400)
            {
                super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2
            } else {
                SOURCE_TREE_GENESIS_READBACK_BYTES_V1
            };
            self.source_complete.try_reserve_exact(bytes)?;
        }
        let slot = match purpose {
            RootSourceObservationPurposeV1::Preparation => RootControllerFrameSlotV1::Prepare,
            RootSourceObservationPurposeV1::Completion => RootControllerFrameSlotV1::Complete,
            RootSourceObservationPurposeV1::Refresh => {
                if self.refresh_frames.len() >= MAXIMUM_SOURCE_OBSERVATIONS - 2
                    || super::require_genesis_observation_pair_widths(
                        &self.controller_complete,
                        &self.source_complete,
                    )
                    .is_err()
                {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.refresh_frames.try_reserve_exact(1)?;
                // The new partial buffer is owned before the first receive.
                self.refresh_frames.push(Vec::new());
                RootControllerFrameSlotV1::Refresh
            }
        };
        self.receive_original_genesis_frame(slot)?;
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let packet = match purpose {
            RootSourceObservationPurposeV1::Preparation => decode_root_source_genesis_frame_v2(
                &self.controller_frame,
                RootSourceGenesisFrameKindV1::Prepare,
                root.nonce_data_v1()
                    .map_err(project_root_authority_genesis_error_v1)?,
            )
            .map_err(project_source_genesis_wire_error_v1)?,
            RootSourceObservationPurposeV1::Completion => decode_root_source_genesis_frame_v2(
                &self.completion_frame,
                RootSourceGenesisFrameKindV1::Complete,
                root.nonce_data_v1()
                    .map_err(project_root_authority_genesis_error_v1)?,
            )
            .map_err(project_source_genesis_wire_error_v1)?,
            RootSourceObservationPurposeV1::Refresh => decode_root_create_q04_transfer_v1(
                self.refresh_frames
                    .last()
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?,
                RootCreateQ04TransferKindV1::SourceRefresh,
                root.nonce_data_v1()
                    .map_err(project_root_authority_genesis_error_v1)?,
            )
            .map_err(project_q04_wire_error_v1)?,
        };
        let (project, challenge) = root
            .accept_historical_controller_readback_v1(packet)
            .map_err(project_root_authority_genesis_error_v1)?;
        // Reuse the same original intent/floor projection. A historical
        // acceptance without an actual settled floor is not this purpose.
        let context = root
            .source_genesis_intent_context_v1()
            .map_err(project_root_authority_genesis_error_v1)?;
        root.require_existing_completed_floor_v1(project)
            .map_err(map_root_authority_error_v1)?;
        if !matches!(purpose, RootSourceObservationPurposeV1::Preparation) {
            root.require_completed_controller_packet_v1()
                .map_err(map_root_authority_error_v1)?;
            if matches!(purpose, RootSourceObservationPurposeV1::Completion) {
                self.controller_complete.try_reserve_exact(packet.len())?;
            }
            // The complete original frame is still in its own retained slot.
            // Replacing this current view cannot discard any earlier packet.
            self.controller_complete.clear();
            self.controller_complete.extend_from_slice(packet);
        }
        self.recheck_original()?;
        Ok((project, challenge, context))
    }

    fn source_observation_loan(
        &mut self,
        project: aos_sandbox_model::ProjectId,
        challenge: SourceTreeGenesisChallengeV1,
        context: SourceTreeGenesisIntentContextV1,
        purpose: RootSourceObservationPurposeV1,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'authority, 'origin, 'startup>, ()> {
        let resource_posts = if context.has_resource_authorization() {
            if self.cause.borrow().is_some() || self.postcheck_debt.borrow().is_some()
                || self.source_resource_posts.len() >= MAXIMUM_SOURCE_OBSERVATIONS {
                self.cause.borrow_mut().get_or_insert(CreateQ04ErrorV1::ChangedCut);
                return Err(());
            }
            if self.source_resource_posts.try_reserve_exact(1).map_err(|error| {
                self.cause.borrow_mut().get_or_insert(error.into());
            }).is_err() {
                return Err(());
            }
            self.source_resource_posts.push(RootResourceSourcePostsV2::default());
            self.source_resource_posts.last_mut()
        } else {
            None
        };
        let Some(root) = self.root.as_mut() else {
            self.cause.borrow_mut().get_or_insert(CreateQ04ErrorV1::ChangedCut);
            return Err(());
        };
        let original = match self.work.source_observation_input_loan_v1(&*root) {
            Ok(original) => original,
            Err(()) => {
                // The same Work parks the actual typed constructor error
                // before this marker; later independent posts remain debt.
                if self.first_owner.get().is_none() && self.cause.borrow().is_none() {
                    self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::PolicyHeld));
                } else {
                    if self.debt_owner.get().is_none() && self.postcheck_debt.borrow().is_some() {
                        self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
                    }
                    if self.debt_owner.get().is_none() {
                        self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::PolicyHeld));
                    }
                }
                return Err(());
            }
        };
        Ok(RootCreateQ04SourceObservationLoanV1 {
            root,
            original,
            origin: self.origin,
            cause: &self.cause,
            first_owner: &self.first_owner,
            debt_owner: &self.debt_owner,
            project,
            challenge,
            context,
            purpose,
            received: &mut self.source_received,
            observations: &mut self.source_observations,
            resource_posts,
            source_complete: &mut self.source_complete,
            controller_complete: &self.controller_complete,
            floor: &mut self.floor,
            phase: &mut self.phase,
            postcheck_debt: &self.postcheck_debt,
            finished: false,
        })
    }

    /// Sends the actual existing semantic floor on this same held stream.
    ///
    /// # Errors
    /// Retains missing Source observation, replaced floor or transport/cutoff.
    pub fn send_existing_anchor(&mut self) -> Result<(), ()> {
        let outcome = self.send_original_existing_anchor();
        self.retain_outcome(outcome)
    }

    fn send_original_existing_anchor(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::PreparedSource {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let source = self
            .source_observations
            .last()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let floor = root
            .recover_existing_floor_v1(source.as_ref())
            .map_err(project_root_authority_genesis_error_v1)?;
        if self.floor.as_ref() != Some(&floor) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.sent = encode_root_source_genesis_frame_v2(
            RootSourceGenesisFrameKindV1::Anchored,
            root.nonce_data_v1()
                .map_err(project_root_authority_genesis_error_v1)?,
            floor.record_bytes(),
        )
        .map_err(project_source_genesis_wire_error_v1)?;
        self.write_original(&self.sent)?;
        self.phase = RootQ04PreludePhaseV1::Anchored;
        Ok(())
    }

    /// Confirms current gen1 and returns Root's exact original Source packet.
    ///
    /// # Errors
    /// Retains changed durable Complete/Source ACK/floor or original I/O.
    /// This continuation does not accept ordinary genesis Finish or release Root.
    pub fn send_existing_completion(&mut self) -> Result<(), ()> {
        let outcome = self.send_original_existing_completion();
        self.retain_outcome(outcome)
    }

    fn send_original_existing_completion(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::CompletedSource {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = root
            .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?;
        current.recheck().map_err(map_root_authority_error_v1)?;
        if self.floor.as_ref() != Some(current.floor()) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let digest = current.floor().digest();
        drop(current);
        self.sent = encode_root_source_genesis_frame_v2(
            RootSourceGenesisFrameKindV1::Completed,
            root.nonce_data_v1()
                .map_err(project_root_authority_genesis_error_v1)?,
            digest.as_bytes(),
        )
        .map_err(project_source_genesis_wire_error_v1)?;
        self.write_original(&self.sent)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent,
            RootCreateQ04TransferKindV1::SourceObservation,
            self.root
                .as_ref()
                .ok_or(CreateQ04ErrorV1::ChangedCut)?
                .nonce_data_v1()
                .map_err(project_root_authority_genesis_error_v1)?,
            &self.source_complete,
        )
        .map_err(project_q04_wire_error_v1)?;
        self.write_original(&self.sent)?;
        self.root
            .as_mut()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?
            .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?
            .recheck()
            .map_err(map_root_authority_error_v1)?;
        self.recheck_original()?;
        self.phase = RootQ04PreludePhaseV1::Completed;
        Ok(())
    }

    /// Sends only the latest genuine Root-returned Source observation.
    ///
    /// # Errors
    /// Retains mismatched current gen1/Complete/Source, changed floor or
    /// original transport/owner/cutoff. This does not advance durable Q04 phase.
    pub fn send_current_gen1_refresh(&mut self) -> Result<(), ()> {
        let outcome = self.send_original_current_gen1_refresh();
        self.retain_outcome(outcome)
    }

    fn send_original_current_gen1_refresh(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::RefreshedSource || self.refresh_frames.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = root
            .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?;
        current.recheck().map_err(map_root_authority_error_v1)?;
        if self.floor.as_ref() != Some(current.floor()) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        drop(current);
        let nonce = root
            .nonce_data_v1()
            .map_err(project_root_authority_genesis_error_v1)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent,
            RootCreateQ04TransferKindV1::SourceObservation,
            nonce,
            &self.source_complete,
        )
        .map_err(project_q04_wire_error_v1)?;
        self.write_original(&self.sent)?;
        self.root
            .as_mut()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?
            .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?
            .recheck()
            .map_err(map_root_authority_error_v1)?;
        self.recheck_original()?;
        self.phase = self
            .refresh_resume
            .take()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        Ok(())
    }

    /// Sends authentic nonissuing input DATA under the same existing gen1 cut.
    ///
    /// The bytes and role keys come from the daemon's retained fixed input
    /// credentials. The original Root writer independently compares its own
    /// signed heads/pins and reserves its nonce/Stage recipe without appending.
    /// This does not establish a logical hold, publication or funded suffix.
    ///
    /// # Errors
    /// Retains missing/changed fixed sources, unavailable original Stage base,
    /// malformed canonical Preview, buffer failure or original transport loss.
    #[allow(clippy::too_many_arguments)]
    pub fn send_nonissuing_preview(
        &mut self,
        deployment_packet: &[u8],
        deployment_signer_generation: u64,
        deployment_key: &ed25519_dalek::VerifyingKey,
        project_source: Option<(&[u8], &[u8])>,
        project_signer_generation: u64,
        project_key: &ed25519_dalek::VerifyingKey,
        inputs: &PolicyDeploymentInputsV1<'_>,
    ) -> Result<(), ()> {
        let outcome = match project_source {
            Some((project_packet, project_input)) => self.send_original_nonissuing_preview(
                deployment_packet, deployment_signer_generation, deployment_key,
                project_packet, project_input, project_signer_generation, project_key, inputs,
            ),
            None => Err(CreateQ04ErrorV1::ChangedCut),
        };
        self.retain_outcome(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_original_nonissuing_preview(
        &mut self,
        deployment_packet: &[u8],
        deployment_signer_generation: u64,
        deployment_key: &ed25519_dalek::VerifyingKey,
        project_packet: &[u8],
        project_input: &[u8],
        project_signer_generation: u64,
        project_key: &ed25519_dalek::VerifyingKey,
        inputs: &PolicyDeploymentInputsV1<'_>,
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Completed
            || self.stage.is_some()
            || !self.preview.is_empty()
            || !self.preview_chunk.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let now = self.current_original_clock()?.wall_seconds();
        let original = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let controller_gid = self.admission_data_v1()?.identities.controller_gid;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = root
            .nonce_data_v1()
            .map_err(project_root_authority_genesis_error_v1)?;
        self.stage = Some(
            root.q04_preview_stage(
                &self.source_complete,
                deployment_packet,
                deployment_signer_generation,
                deployment_key,
                project_packet,
                project_input,
                project_signer_generation,
                project_key,
                controller_gid,
                now,
            )
            .map_err(map_root_authority_error_v1)?,
        );
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.q04_encode_preview(
            &mut self.preview,
            stage,
            inputs,
            project_input,
            original,
            now,
        )
        .map_err(map_root_authority_error_v1)?;
        self.recheck_original()?;

        let preview = super::Q04PreviewV1::decode(&self.preview, nonce)?;
        let transfer = super::Q04PreviewTransferRecipeV1::new(&preview)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent,
            RootCreateQ04TransferKindV1::PreviewIndex,
            nonce,
            transfer.index_bytes(),
        )
        .map_err(project_q04_wire_error_v1)?;
        self.write_original(&self.sent)?;
        for index in 0..transfer.chunk_count() {
            transfer.encode_chunk(index, &mut self.preview_chunk)?;
            self.sent.clear();
            encode_root_create_q04_transfer_v1(
                &mut self.sent,
                RootCreateQ04TransferKindV1::PreviewChunk,
                nonce,
                &self.preview_chunk,
            )
            .map_err(project_q04_wire_error_v1)?;
            self.write_original(&self.sent)?;
            self.preview_chunk.clear();
        }
        self.recheck_original()?;
        self.phase = RootQ04PreludePhaseV1::Preview;
        Ok(())
    }

    fn receive_original_exact(
        &mut self,
        length: usize,
        slot: RootControllerFrameSlotV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        self.receive_original_exact_with_header(length, slot, false)
    }

    fn receive_original_genesis_frame(
        &mut self, slot: RootControllerFrameSlotV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
            + super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1;
        self.receive_original_exact_with_header(length, slot, true)
    }

    fn receive_original_exact_with_header(
        &mut self,
        mut length: usize,
        slot: RootControllerFrameSlotV1,
        mut genesis_header: bool,
    ) -> Result<(), CreateQ04ErrorV1> {
        if length == 0 || length > 4096 || self.received.is_some()
            || !self.controller_frame_buffer(slot)?.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.controller_frame_buffer_mut(slot)?.try_reserve_exact(length)?;
        loop {
            let copied = self.controller_frame_buffer(slot)?.len();
            if copied == length {
                if !genesis_header { break; }
                // This is the old fixed receive's final owner/clock post.
                // Even malformed sizing DATA cannot move ahead of that post.
                self.recheck_original()?;
                // The original legacy receive/allocation schedule finishes
                // before DATA framing can select the resource-only extension.
                let header = &self.controller_frame_buffer(slot)?[..ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1];
                let resource_version = match slot {
                    RootControllerFrameSlotV1::Refresh => [0, 3],
                    _ => [0, 2],
                };
                if header[8..10] != resource_version {
                    return Ok(());
                }
                let nonce = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.nonce_data_v1().map_err(project_root_authority_genesis_error_v1)?;
                let payload_bytes = match slot {
                    RootControllerFrameSlotV1::Prepare => genesis_wire::strict_genesis_payload_bytes_from_header(
                        header, RootSourceGenesisFrameKindV1::Prepare, nonce,
                    ).map_err(project_source_genesis_wire_error_v1).map_err(CreateQ04ErrorV1::from),
                    RootControllerFrameSlotV1::Complete => genesis_wire::strict_genesis_payload_bytes_from_header(
                        header, RootSourceGenesisFrameKindV1::Complete, nonce,
                    ).map_err(project_source_genesis_wire_error_v1).map_err(CreateQ04ErrorV1::from),
                    RootControllerFrameSlotV1::Refresh => genesis_wire::q04_genesis_refresh_payload_bytes_from_header(header, nonce).map_err(project_q04_wire_error_v1),
                    _ => Err(CreateQ04ErrorV1::ChangedCut),
                }?;
                genesis_header = false;
                let complete_length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload_bytes;
                if complete_length == length { return Ok(()); }
                if complete_length != length + 176 {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.controller_frame_buffer_mut(slot)?.try_reserve_exact(176)?;
                length = complete_length;
            }
            self.recheck_original()?;
            {
                let mut original = self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?;
                let mut stream = original.borrow_native_stream_v1().map_err(project_root_q04_origin_error_v1)?;
                self.received = Some(aos_sandbox_linux::unix_stream::try_receive_subject_chunk_retaining(stream.stream_mut_v1(), length - copied));
            }
            let nonconsuming = self.received.as_ref().is_some_and(|result| result.as_ref()
                .is_err_and(|error| error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted()));
            if nonconsuming {
                self.received = None;
                self.wait_original(rustix::event::PollFlags::IN)?;
                continue;
            }
            if matches!(self.received, Some(Err(_))) {
                return match self.received.take() {
                    Some(Err(error)) => Err(error.into()),
                    returned => {
                        self.received = returned;
                        Err(CreateQ04ErrorV1::ChangedCut)
                    }
                };
            }
            let chunk = self.received.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?
                .observe_subject_once_v1(chunk).map_err(project_root_q04_origin_error_v1)?;
            if chunk.payload().is_empty() || chunk.payload().len() > length - copied {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            let output = match slot {
                RootControllerFrameSlotV1::Prepare => &mut self.controller_frame,
                RootControllerFrameSlotV1::Complete => &mut self.completion_frame,
                RootControllerFrameSlotV1::Refresh => self.refresh_frames.last_mut()
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?,
                RootControllerFrameSlotV1::Prehold => &mut self.prehold_frame,
                RootControllerFrameSlotV1::Claim => &mut self.claim_frame,
                RootControllerFrameSlotV1::Acknowledgement => self.acknowledgement_frames.last_mut()
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?,
            };
            output.extend_from_slice(chunk.payload());
            self.recheck_original()?;
            self.received = None;
        }
        self.recheck_original()
    }

    fn read_original_prehold_data(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Preview
            || !self.prehold.is_empty() || !self.prehold_frame.is_empty()
            || self.work.prehold_identity_data_v1().is_some() || self.controller_clock.is_some()
            || !self.refresh_frames.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.receive_original_exact(32 + super::PREVIEW_INDEX_BYTES, RootControllerFrameSlotV1::Prehold)?;
        let nonce = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .nonce_data_v1().map_err(map_root_authority_error_v1)?;
        let index = decode_root_create_q04_transfer_v1(
            &self.prehold_frame, RootCreateQ04TransferKindV1::PreholdIndex, nonce,
        ).map_err(project_q04_wire_error_v1)?;
        let (total, count) = super::prehold_index_shape(index)?;
        let original_index: [u8; super::PREVIEW_INDEX_BYTES] = index.try_into()
            .map_err(|_| CreateQ04ErrorV1::Bounds)?;
        self.prehold.try_reserve_exact(total)?;
        self.prehold_frame.clear();
        for number in 0..count {
            let offset = usize::from(number).checked_mul(super::CLAIM_CHUNK_BYTES)
                .ok_or(CreateQ04ErrorV1::Bounds)?;
            let payload = total.checked_sub(offset).ok_or(CreateQ04ErrorV1::Bounds)?
                .min(super::CLAIM_CHUNK_BYTES);
            self.receive_original_exact(
                32 + super::CLAIM_CHUNK_PREFIX_BYTES + payload, RootControllerFrameSlotV1::Prehold,
            )?;
            let bytes = decode_root_create_q04_transfer_v1(
                &self.prehold_frame, RootCreateQ04TransferKindV1::PreholdChunk, nonce,
            ).map_err(project_q04_wire_error_v1)?;
            super::Q04PreholdChunkV1::decode(bytes, &original_index)?.append_to(&mut self.prehold)?;
            self.recheck_original()?;
            self.prehold_frame.clear();
        }
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = root.refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete).map_err(map_root_authority_error_v1)?;
        let (request, _) = current.prehold_input(&self.prehold, stage).map_err(map_root_authority_error_v1)?;
        super::Q04PreholdTransferRecipeV1::verify_index(&original_index, &request)?;
        let origin: [u8; 32] = request.fields()[0][..32].try_into()
            .map_err(|_| CreateQ04ErrorV1::Bounds)?;
        current.recheck().map_err(map_root_authority_error_v1)?;
        drop(current);
        let clock = self.current_original_clock()?;
        let root_start = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?.boottime_nanoseconds();
        if origin[..16] != clock.host_boot_id()
            || u64::from_be_bytes(super::fixed(&origin, 16)) > root_start
            || clock.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(&origin, 24))
        {
            return Err(CreateQ04ErrorV1::Expired);
        }
        // The authenticated client origin is adopted once. Every subsequent
        // slow owner check samples both original cuts; neither is renewed.
        self.controller_clock = Some(origin);
        self.recheck_original()
    }

    /// Preflights and returns nonissuing publication DATA on the original flight.
    ///
    /// Root checks its own complete eligible authority suffix and actual
    /// four-member policy-state recipe. This grants no reservation, logical
    /// hold, publication, effect or public Create outcome.
    ///
    /// # Errors
    /// Retains actual receive/compiler/native/send failures and separate final
    /// readback debt. A partial or late response cannot authorize a retry.
    pub fn prepare_publication_data(&mut self) -> Result<(), ()> {
        let returned = self.prepare_original_publication_data();
        if returned.is_err() {
            let _ = self.retain_action_outcome_v1(returned);
            self.recheck_original_owed_and_retain_v1();
            return Err(());
        }
        self.retain_action_outcome_v1(returned)
    }

    fn prepare_original_publication_data(&mut self) -> Result<(), RootActionFailureV1> {
        if self.prehold_reply.is_some() { return Err(CreateQ04ErrorV1::ChangedCut.into()); }
        self.read_original_prehold_data()?;
        self.park_original_prehold_plan()?;
        let returned = self.work.forecast_prehold_suffix_once_v1(
            self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            &self.prehold, &self.preview, &self.source_complete,
        );
        self.require_work_history_action_v1(returned)?;
        self.require_prehold_originals()?;
        let returned = self.work.publication_data_reply_v1(
            self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.prehold,
        );
        self.prehold_reply = Some(match returned {
            Ok(reply) => reply,
            Err(()) => { self.latch_policy_refusal_v1(); return Err(RootActionFailureV1::PolicyHeld); }
        });
        self.sent.clear();
        encode_root_create_q04_transfer_v1(&mut self.sent, RootCreateQ04TransferKindV1::PreholdRecipe,
            self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.nonce_data_v1()
                .map_err(map_root_authority_error_v1)?,
            self.prehold_reply.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.bytes(),
        ).map_err(project_q04_wire_error_v1)?;
        self.require_prehold_originals()?;
        self.write_original(&self.sent)?;
        self.require_prehold_originals()?;
        self.phase = RootQ04PreludePhaseV1::Prefunded;
        Ok(())
    }

    fn require_prehold_originals(&mut self) -> Result<(), RootActionFailureV1> {
        self.recheck_original()?;
        let gen1 = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?;
        let returned = self.work.require_prehold_current_v1(&gen1,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.prehold, &self.preview);
        drop(gen1);
        self.require_work_action_v1(returned)?;
        self.recheck_original()?;
        Ok(())
    }

    // The actual plan is parked before any post-adapter named/native/clock
    // checks. There is still no DATA reply until Root's complete eligible
    // authority suffix also passes its same original Journal preflight.
    fn park_original_prehold_plan(&mut self) -> Result<(), RootActionFailureV1> {
        self.recheck_original()?;
        let returned = self.work.capture_original_target_before_once_v1(
            self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
        );
        self.require_work_action_v1(returned)?;
        {
            let gen1 = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
                .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
                .map_err(map_root_authority_error_v1)?;
            let returned = self.work.reconstruct_prehold_input_once_v1(&gen1,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.prehold, &self.preview);
            drop(gen1);
            self.require_work_action_v1(returned)?;
        }
        {
            let gen1 = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
                .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
                .map_err(map_root_authority_error_v1)?;
            let returned = self.work.prepare_prehold_publication_once_v1(&gen1,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                &self.prehold, &self.preview, &self.controller_complete, &self.source_complete);
            drop(gen1);
            self.require_work_action_v1(returned)?;
        }
        self.require_prehold_originals()
    }

    #[allow(clippy::too_many_arguments)]

    fn controller_frame_buffer(&self, slot: RootControllerFrameSlotV1) -> Result<&Vec<u8>, CreateQ04ErrorV1> {
        match slot {
            RootControllerFrameSlotV1::Prepare => Ok(&self.controller_frame),
            RootControllerFrameSlotV1::Complete => Ok(&self.completion_frame),
            RootControllerFrameSlotV1::Refresh => self.refresh_frames.last().ok_or(CreateQ04ErrorV1::ChangedCut),
            RootControllerFrameSlotV1::Prehold => Ok(&self.prehold_frame),
            RootControllerFrameSlotV1::Claim => Ok(&self.claim_frame),
            RootControllerFrameSlotV1::Acknowledgement => self.acknowledgement_frames.last()
                .ok_or(CreateQ04ErrorV1::ChangedCut),
        }
    }

    fn controller_frame_buffer_mut(&mut self, slot: RootControllerFrameSlotV1) -> Result<&mut Vec<u8>, CreateQ04ErrorV1> {
        match slot {
            RootControllerFrameSlotV1::Prepare => Ok(&mut self.controller_frame),
            RootControllerFrameSlotV1::Complete => Ok(&mut self.completion_frame),
            RootControllerFrameSlotV1::Refresh => self.refresh_frames.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut),
            RootControllerFrameSlotV1::Prehold => Ok(&mut self.prehold_frame),
            RootControllerFrameSlotV1::Claim => Ok(&mut self.claim_frame),
            RootControllerFrameSlotV1::Acknowledgement => self.acknowledgement_frames.last_mut()
                .ok_or(CreateQ04ErrorV1::ChangedCut),
        }
    }

    fn wait_original(&self, interest: rustix::event::PollFlags) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let started = self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        {
            let mut original = self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?;
            let stream = original.borrow_native_stream_v1().map_err(project_root_q04_origin_error_v1)?;
            aos_sandbox_broker::controller_receiving::profile::root_flight::wait_original_root_v1(
                stream.stream_v1().as_fd(), interest, started + MAXIMUM_ROOT_FLIGHT,
            ).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from)?;
        }
        self.recheck_original()
    }

    fn write_original(&self, bytes: &[u8]) -> Result<(), CreateQ04ErrorV1> {
        if bytes.is_empty() || bytes.len() > 4096 || self.send_result.borrow().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.sent_progress.set(0);
        while self.sent_progress.get() < bytes.len() {
            self.recheck_original()?;
            {
                let mut original = self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?;
                let stream = original.borrow_native_stream_v1().map_err(project_root_q04_origin_error_v1)?;
                *self.send_result.borrow_mut() = Some(rustix::net::send(
                    stream.stream_v1().as_fd(), &bytes[self.sent_progress.get()..],
                    rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
                ));
            }
            let returned = self.send_result.borrow().as_ref().copied()
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            match returned {
                Ok(0) => return Err(CreateQ04ErrorV1::ChangedCut),
                Ok(count) => self.sent_progress.set(self.sent_progress.get()
                    .checked_add(count).filter(|total| *total <= bytes.len())
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    *self.send_result.borrow_mut() = None;
                    self.wait_original(rustix::event::PollFlags::OUT)?;
                    continue;
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            self.recheck_original()?;
            *self.send_result.borrow_mut() = None;
        }
        self.recheck_original()
    }

    fn recheck_original(&self) -> Result<(), CreateQ04ErrorV1> {
        if self.has_first_cause_v1() || self.has_postcheck_debt_v1() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original_owned()
    }

    fn recheck_original_owned(&self) -> Result<(), CreateQ04ErrorV1> {
        let root = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = match self.work.recheck_original_owners_v1(root) {
            Ok(current) => current,
            Err(()) => {
                // The actual native cause is resident before this guard leaves
                // the positive bookend; later posts cannot become its owner.
                self.latch_policy_refusal_v1();
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        };
        if let Some(origin) = &self.controller_clock {
            if origin[..16] != current.host_boot_id()
                || current.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(origin, 24))
            {
                return Err(CreateQ04ErrorV1::Expired);
            }
        }
        Ok(())
    }

    // The final refusal path must still reach the independent Target post.
    // Positive opening/current checks keep their separate healthy operation.
    fn recheck_original_owed_and_retain_v1(&self) {
        match self.recheck_original_owed_v1() {
            Ok(()) => {}
            Err(RootActionFailureV1::Owned(error)) => {
                self.postcheck_debt.borrow_mut().get_or_insert(error);
                if self.debt_owner.get().is_none() {
                    self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
                }
            }
            Err(RootActionFailureV1::PolicyHeld) => self.latch_policy_refusal_v1(),
            Err(RootActionFailureV1::AuthorityHeld) => self.latch_authority_refusal_v1(),
        }
    }

    fn recheck_original_owed_v1(&self) -> Result<(), RootActionFailureV1> {
        if self.origin.purpose_v1() != RootQ04OriginPurposeV1::Ordinary {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        let mut original = self.origin.try_borrow_mut()
            .map_err(CreateQ04ErrorV1::OriginBorrowMut)?;
        let current = original.begin_input_current_once_v1()
            .map_err(project_root_q04_origin_error_v1)?;
        if let Some(root) = self.root.as_ref() {
            root.recheck().map_err(project_root_authority_genesis_error_v1)?;
        }
        if self.work.require_original_target_names_post_once_v1().is_err() {
            // Select this reached native site before any later diagnostic.
            self.latch_policy_refusal_v1();
            return Err(RootActionFailureV1::PolicyHeld);
        }
        let current = current.finish_once_v1().map_err(project_root_q04_origin_error_v1)?;
        if let Some(origin) = &self.controller_clock {
            if origin[..16] != current.host_boot_id()
                || current.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(origin, 24))
            {
                return Err(CreateQ04ErrorV1::Expired.into());
            }
        }
        Ok(())
    }

    // Sample after all potentially slow owner checks. Neither the monotonic
    // cut nor its paired BOOTTIME/wall/boot origin is renewed at a phase.
    fn current_original_clock(&self) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?
            .observe_original_clock_once_v1().map_err(project_root_q04_origin_error_v1)
    }

    fn require_identity_clock(&self, identity: &Q04CutIdentityV1) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let original = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if identity.bytes()[112..128] != original.host_boot_id()
            || identity.bytes()[144..152] != original.boottime_nanoseconds().to_be_bytes()
            || identity.controller_uid() != self.admission_data_v1()?.identities.controller_uid
            || identity.bytes()[84..88] != self.admission_data_v1()?.identities.source_uid.to_be_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.current_original_clock()?;
        Ok(())
    }

    /// Retains the exact authenticated held Claim on this original stream.
    ///
    /// This only reconstructs and compares input DATA under genuine current
    /// Controller/Source/Cache/Root loans. No Stage, publication or decision is
    /// committed by receiving it.
    ///
    /// # Errors
    /// Retains incomplete chunks, original subjects, canonical/signature/model
    /// failures and final readback debt. Failure never permits retry or release.
    pub fn receive_held_claim(&mut self) -> Result<(), ()> {
        let returned = self.receive_original_held_claim();
        if returned.is_err() {
            let _ = self.retain_action_outcome_v1(returned);
            self.recheck_original_owed_and_retain_v1();
            return Err(());
        }
        self.retain_action_outcome_v1(returned)
    }

    fn receive_original_held_claim(&mut self) -> Result<(), RootActionFailureV1> {
        if self.phase != RootQ04PreludePhaseV1::Prefunded || !self.claim.is_empty()
            || !self.claim_frame.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        // Keep the same original bounded identity copy across physical reads.
        // Work lends it only from its actual parked prehold publication plan.
        let identity = self.work.prehold_identity_data_v1()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?.clone();
        let claim_length = self.work.prehold_claim_length_data_v1()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.require_identity_clock(&identity)?;
        self.receive_original_exact(32 + super::CLAIM_INDEX_BYTES, RootControllerFrameSlotV1::Claim)?;
        let bytes = decode_root_create_q04_transfer_v1(
            &self.claim_frame, RootCreateQ04TransferKindV1::ClaimIndex, identity.nonce(),
        ).map_err(project_q04_wire_error_v1)?;
        let (total, count) = aos_sandbox_policy::q04_data::claim_index_shape(bytes, &identity).map_err(CreateQ04ErrorV1::from)?;
        if total != claim_length {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        let index: [u8; super::CLAIM_INDEX_BYTES] = bytes.try_into().map_err(|_| CreateQ04ErrorV1::Bounds)?;
        self.claim.try_reserve_exact(total).map_err(CreateQ04ErrorV1::from)?;
        self.claim_frame.clear();
        for chunk in 0..count {
            let offset = usize::from(chunk).checked_mul(super::CLAIM_CHUNK_BYTES)
                .ok_or(CreateQ04ErrorV1::Bounds)?;
            let length = total.checked_sub(offset).ok_or(CreateQ04ErrorV1::Bounds)?
                .min(super::CLAIM_CHUNK_BYTES);
            self.receive_original_exact(32 + super::CLAIM_CHUNK_PREFIX_BYTES + length,
                RootControllerFrameSlotV1::Claim)?;
            let bytes = decode_root_create_q04_transfer_v1(
                &self.claim_frame, RootCreateQ04TransferKindV1::ClaimChunk, identity.nonce(),
            ).map_err(project_q04_wire_error_v1)?;
            super::Q04ClaimChunkV1::decode(bytes, &index, &identity).map_err(CreateQ04ErrorV1::from)?
                .append_to(&mut self.claim).map_err(CreateQ04ErrorV1::from)?;
            self.require_identity_clock(&identity)?;
            self.claim_frame.clear();
        }
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?;
        let claim = gen1.verify_claim(&self.claim, &identity).map_err(map_root_authority_error_v1)?;
        super::Q04ClaimStorageRecipeV1::verify_index(&index, &claim, &identity).map_err(CreateQ04ErrorV1::from)?;
        let request = super::Q04PreholdInputDataV1::decode(&self.prehold).map_err(CreateQ04ErrorV1::from)?;
        let preview = super::Q04PreviewV1::decode(&self.preview, identity.nonce()).map_err(CreateQ04ErrorV1::from)?;
        let original = request.fields();
        let signed = preview.fields();
        let fields = claim.fields();
        if fields[..3] != original[1..4] || fields[3..7] != signed[3..7]
            || fields[7] != signed[8] || fields[8] != original[4]
            || fields[11] != self.source_complete.as_slice()
        {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        gen1.recheck().map_err(map_root_authority_error_v1)?;
        drop(gen1);
        self.claim_source_observation = Some(self.source_observations.len().checked_sub(1)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?);
        if self.source_observations.get(self.claim_source_observation
            .ok_or(CreateQ04ErrorV1::ChangedCut)?).map(|packet| packet.as_ref())
            != Some(self.source_complete.as_slice())
        {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }

        // Preserve the old independent second gen1 observation immediately
        // before reconstructing the complete held compiler input on real Work.
        let cache_uid = self.admission_data_v1()?.identities.cache_uid;
        let gen1 = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?;
        let returned = self.work.reconstruct_held_input_once_v1(&gen1,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &identity,
            &self.claim, &self.source_complete, cache_uid);
        drop(gen1);
        if returned.is_err() {
            self.latch_policy_refusal_v1();
            return Err(RootActionFailureV1::PolicyHeld);
        }
        self.require_identity_clock(&identity)?;
        Ok(())
    }

    /// Commits only the actual Claim, reserved Stage, and held Root binding.
    ///
    /// Every append uses this original flight and the same native journal
    /// engine. This prefix is not an executed qualification gate, a policy
    /// decision, Controller clearance, or a successful public Create.
    ///
    /// # Errors
    /// Retains the original append outcome and first typed cause before any
    /// later native, name, floor or clock check. No failed prefix is retried.
    pub fn commit_held_root_binding(&mut self) -> Result<(), ()> {
        let returned = self.commit_original_binding_prefix();
        if returned.is_err() {
            let _ = self.retain_action_outcome_v1(returned);
            self.recheck_original_owed_and_retain_v1();
            return Err(());
        }
        self.retain_action_outcome_v1(returned)
    }

    fn park_original_root_history(&mut self) -> Result<(), RootActionFailureV1> {
        if self.phase != RootQ04PreludePhaseV1::Prefunded {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        self.require_original_held_input_cut()?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let returned = self.work.admit_root_binding_history_once_v1(
            root, stage, &self.claim, &self.prehold, &self.preview,
            &self.controller_complete, &self.source_complete,
        );
        match returned {
            Ok(()) => {}
            Err(aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1::AuthorityHeld) => {
                self.latch_authority_refusal_v1();
                return Err(RootActionFailureV1::AuthorityHeld);
            }
            Err(aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1::PolicyHeld) => {
                self.latch_policy_refusal_v1();
                return Err(RootActionFailureV1::PolicyHeld);
            }
        }
        let identity = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?.identity();
        self.require_identity_clock(identity)?;
        Ok(())
    }

    fn commit_original_binding_prefix(&mut self) -> Result<(), RootActionFailureV1> {
        self.park_original_root_history()?;
        loop {
            let history = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
                .q04_history_v1().map_err(map_root_authority_error_v1)?;
            if history.committed() == history.binding_prefix_end().map_err(map_root_authority_error_v1)? {
                break;
            }
            self.append_one_original_root_prefix()?;
        }
        self.phase = RootQ04PreludePhaseV1::BindingHeld;
        self.require_original_held_input_cut()?;
        Ok(())
    }

    fn append_one_original_root_prefix(&mut self) -> Result<(), RootActionFailureV1> {
        self.require_original_held_input_cut()?;
        self.append_parked_original_root_commit()?;
        let root = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let returned = root.q04_recheck_original_binding_prefix_v1(
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete,
        ).map_err(map_root_authority_error_v1);
        if let Err(debt) = returned {
            self.postcheck_debt.get_mut().get_or_insert(debt);
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        let identity = root.q04_history_v1().map_err(map_root_authority_error_v1)?.identity();
        self.require_identity_clock(identity)?;
        Ok(())
    }

    fn append_parked_original_root_commit(&mut self) -> Result<(), RootActionFailureV1> {
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let original = match self.work.borrow_authority_input_v1(&*root) {
            Ok(original) => original,
            Err(()) => {
                self.latch_policy_refusal_v1();
                return Err(RootActionFailureV1::PolicyHeld);
            }
        };
        // This constructor copies only the already-ready same Origin. Native
        // floor/currentness observations remain at their old lower positions.
        let returned = root.append_next_q04_history_v1(
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            &self.source_complete, &original,
        );
        drop(original);
        match returned {
            Ok(()) => Ok(()),
            Err(aos_sandbox_policy::native::RootAuthorityQ04AppendFailureV1::AuthorityHeld) => {
                self.latch_authority_refusal_v1();
                Err(RootActionFailureV1::AuthorityHeld)
            }
            Err(aos_sandbox_policy::native::RootAuthorityQ04AppendFailureV1::PolicyHeld) => {
                self.latch_policy_refusal_v1();
                Err(RootActionFailureV1::PolicyHeld)
            }
        }
    }

    fn require_original_held_input_cut(&mut self) -> Result<(), RootActionFailureV1> {
        if self.has_first_cause_v1() || self.has_postcheck_debt_v1() {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        let cache_uid = self.admission_data_v1()?.identities.cache_uid;
        let returned = self.work.require_held_originals_current_v1(
            self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            &self.claim, &self.controller_complete, &self.source_complete, cache_uid,
        );
        self.require_work_action_v1(returned)
    }

    /// Publishes the exact policy recipe while this original binding stays held.
    ///
    /// The actual strict adapter outcome, native recipe, and complete replay
    /// remain resident. Success here is only policy durability; Controller's
    /// Effect and the public Create are still Applying and pending.
    ///
    /// # Errors
    /// Retains the actual prepared/applied/ambiguous outcome and first cause.
    /// A late or failed postcheck cannot issue a Decision or release owners.
    pub fn publish_held_policy(&mut self) -> Result<(), ()> {
        let returned = (|| -> Result<(), RootActionFailureV1> {
            if self.phase != RootQ04PreludePhaseV1::BindingHeld {
                return Err(CreateQ04ErrorV1::ChangedCut.into());
            }
            self.require_original_held_input_cut()?;
            let cache_uid = self.admission_data_v1()?.identities.cache_uid;
            self.recheck_original()?;
            let returned = self.work.prepare_held_policy_once_v1(
                self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                &self.claim, &self.controller_complete, &self.source_complete, cache_uid,
            );
            self.require_work_action_v1(returned)?;
            self.require_original_held_input_cut()?;
            self.require_original_held_input_cut()?;
            let returned = self.work.invoke_held_policy_once_v1(
                self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                &self.claim, &self.controller_complete, &self.source_complete, cache_uid,
            );
            self.require_work_action_v1(returned)?;
            self.recheck_original()?;
            let returned = self.work.observe_first_publication_body_once_v1();
            self.require_work_action_v1(returned)?;
            self.require_original_held_input_cut()?;
            self.phase = RootQ04PreludePhaseV1::PolicyCommitted;
            self.recheck_original()?;
            Ok(())
        })();
        if returned.is_err() {
            let _ = self.retain_action_outcome_v1(returned);
            self.recheck_original_owed_and_retain_v1();
            return Err(());
        }
        self.retain_action_outcome_v1(returned)
    }

    fn read_original_policy_publication(
        &mut self,
    ) -> Result<(u64, ObjectDigest, ObjectDigest), RootActionFailureV1> {
        self.recheck_original()?;
        self.read_original_policy_publication_body()
    }

    fn read_original_policy_publication_body(
        &mut self,
    ) -> Result<(u64, ObjectDigest, ObjectDigest), RootActionFailureV1> {
        match self.work.observe_publication_body_once_v1() {
            Ok(data) => Ok(data),
            Err(()) => {
                self.latch_policy_refusal_v1();
                Err(RootActionFailureV1::PolicyHeld)
            }
        }
    }

    /// Commits and sends the real decision on this same original Root flight.
    ///
    /// The decision names the already committed R2 binding and the actual
    /// policy-state transaction. It is neither a future native observation
    /// nor a successful Create or a permission to release the lower owners.
    ///
    /// # Errors
    /// Retains the original decision, native outcome, transport cause and
    /// later readback debt. Failure leaves the same whole attempt closed.
    pub fn publish_decision(&mut self) -> Result<(), ()> {
        let returned = self.publish_original_decision();
        self.retain_action_outcome_v1(returned)
    }

    fn publish_original_decision(&mut self) -> Result<(), RootActionFailureV1> {
        if self.phase != RootQ04PreludePhaseV1::PolicyCommitted {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        self.require_original_held_input_cut()?;
        let cache_uid = self.admission_data_v1()?.identities.cache_uid;
        let returned = self.work.admit_root_decision_once_v1(
            self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.claim,
            &self.controller_complete, &self.source_complete, cache_uid,
        );
        match returned {
            Ok(()) => {}
            Err(aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1::AuthorityHeld) => {
                self.latch_authority_refusal_v1();
                return Err(RootActionFailureV1::AuthorityHeld);
            }
            Err(aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1::PolicyHeld) => {
                self.latch_policy_refusal_v1();
                return Err(RootActionFailureV1::PolicyHeld);
            }
        }
        self.append_one_original_root_prefix()?;
        self.require_original_held_input_cut()?;
        let history = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?;
        self.require_identity_clock(history.identity())?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(&mut self.sent,
            RootCreateQ04TransferKindV1::Decision, history.identity().nonce(),
            history.decision_data_v1().ok_or(CreateQ04ErrorV1::ChangedCut)?.bytes(),
        ).map_err(project_q04_wire_error_v1)?;
        self.write_original(&self.sent)?;
        self.require_original_held_input_cut()?;
        self.phase = RootQ04PreludePhaseV1::Decided;
        Ok(())
    }

    /// Consumes the real policy ACK and returns the committed Root4 phase.
    ///
    /// The selected caller first refreshes gen1 after Controller's C2 write.
    /// Both the received packet and the native result remain in this attempt.
    ///
    /// # Errors
    /// Retains wrong phase, signature/current-cut mismatch, original I/O cause
    /// and postcheck debt without releasing or reconstructing an owner.
    pub fn consume_policy_acknowledgement(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Policy);
        self.retain_action_outcome_v1(returned)
    }

    /// Consumes the real release ACK and returns logical Root5 authorization.
    ///
    /// This authorizes only the exact lower ReleasedPending transitions. The
    /// original Root writers, stream and clock remain resident through final
    /// settlement; a logical release is not disposal, cleanup or Drain.
    ///
    /// # Errors
    /// Retains wrong phase, changed original owners, stale current ACK, native
    /// ambiguity, transport error or expired original cut.
    pub fn authorize_lower_release(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Release);
        self.retain_action_outcome_v1(returned)
    }

    /// Commits settlement after exact lower ReleasedPending observations.
    ///
    /// Root retains its original writer pair and stream. The returned Root6
    /// record permits only the same in-cut lower clearance sequence, not a
    /// generic currentness token, disposal acknowledgement or successful Create.
    ///
    /// # Errors
    /// Retains stale/mixed lower cuts, wrong signed packet, original native or
    /// transport failure, late cutoff and separate physical readback debt.
    pub fn settle_lower_release(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Settlement);
        self.retain_action_outcome_v1(returned)
    }

    /// Commits Root7 only after the genuine lower clear observations.
    ///
    /// The original Root writer remains owned after this method. Final
    /// bounded response/shutdown must complete before that owner can end.
    ///
    /// # Errors
    /// Retains incomplete/ambiguous clears, changed same-flight observations,
    /// native failure, transport failure or the expired original cutoff.
    pub fn acknowledge_lower_clearance(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Clearance);
        self.retain_action_outcome_v1(returned)
    }

    /// Ends this original stream only after the actual C8 gen1 refresh.
    ///
    /// Root7 has already been sent. The same Root writers remain held while
    /// Controller commits C8 and returns its fresh signed Complete. Shutdown
    /// is a terminal transport action, not resource retirement or Drain.
    ///
    /// # Errors
    /// Retains wrong/missing C8, changed native/publication/name/clock cuts,
    /// the actual shutdown error, and separate final-bookend debt.
    pub fn finish_original_clearance(&mut self) -> Result<(), ()> {
        let prepared = (|| -> Result<(), RootActionFailureV1> {
            if self.phase != RootQ04PreludePhaseV1::FinalClearance
                || self.refresh_frames.len() != 11 || self.shutdown_entered
            {
                return Err(CreateQ04ErrorV1::ChangedCut.into());
            }
            self.recheck_original()?;
            let history = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?;
            if history.committed() != history.transactions().len()
                || history.actual_acknowledgement_count_v1() != 4
            {
                return Err(CreateQ04ErrorV1::ChangedCut.into());
            }
            let original = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
            let metadata = original.fields()[0];
            let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let gen1 = root.refresh_completed_gen1_v1(&self.controller_complete, &self.source_complete).map_err(map_root_authority_error_v1)?;
            if gen1.controller_coordinates().map_err(map_root_authority_error_v1)? != (
                crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[176..224])
                    .map_err(crate::journal::JournalError::from)?,
                u64::from_be_bytes(super::fixed(metadata, 464)).checked_add(31).ok_or(CreateQ04ErrorV1::Bounds)?,
            ) || gen1.source_coordinates().map_err(map_root_authority_error_v1)? != (
                crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[224..272])
                    .map_err(crate::journal::JournalError::from)?,
                u64::from_be_bytes(super::fixed(metadata, 472)).checked_add(11).ok_or(CreateQ04ErrorV1::Bounds)?,
            ) {
                return Err(CreateQ04ErrorV1::ChangedCut.into());
            }
            gen1.recheck().map_err(map_root_authority_error_v1)?;
            drop(gen1);
            self.recheck_final_named_native_cut()?;
            self.recheck_original()?;
            Ok(())
        })();
        self.retain_action_outcome_v1(prepared)?;
        self.shutdown_entered = true;
        self.shutdown_entry = Some(self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)
            .and_then(|mut original| original.shutdown_ordinary_original_once_v1()
                .map_err(project_root_q04_origin_error_v1)));
        let shutdown_ready = matches!(self.shutdown_entry, Some(Ok(())));
        let final_bookend = self.recheck_final_named_native_cut();
        if let Err(debt) = final_bookend {
            let _ = self.retain_action_outcome_v1::<()>(Err(debt));
        }
        if self.has_first_cause_v1() || self.has_postcheck_debt_v1()
            || !shutdown_ready
        {
            return Err(());
        }
        self.cleared = true;
        Ok(())
    }

    /// Borrows the actual terminal shutdown result without replacing its cause.
    ///
    /// Earlier original failures and final-bookend debt stay in their distinct
    /// resident slots. A shutdown error is neither expected EOF nor retirement.
    pub fn shutdown_result(&self) -> Result<
        Option<std::cell::Ref<'_, Result<(), std::io::Error>>>, CreateQ04ErrorV1,
    > {
        self.origin.ordinary_shutdown_result_v1().map_err(project_root_q04_origin_error_v1)
    }

    fn recheck_final_named_native_cut(&mut self) -> Result<(), RootActionFailureV1> {
        {
            let mut original = self.origin.try_borrow_mut().map_err(CreateQ04ErrorV1::OriginBorrowMut)?;
            original.observe_ordinary_startup_post_once_v1().map_err(project_root_q04_origin_error_v1)?;
            {
                let stream = original.borrow_native_stream_v1().map_err(project_root_q04_origin_error_v1)?;
                stream.stream_v1().revalidate_original().map_err(CreateQ04ErrorV1::from)?;
            }
            original.observe_ordinary_peer_post_once_v1().map_err(project_root_q04_origin_error_v1)?;
        }
        self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_recheck_original_binding_prefix_v1(
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete,
            ).map_err(map_root_authority_error_v1)?;
        let expected = self.work.original_publication_data_v1().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = self.read_original_policy_publication_body()?;
        if current != expected { return Err(CreateQ04ErrorV1::ChangedCut.into()); }
        let now = self.current_original_clock()?;
        let controller = self.controller_clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if controller[..16] != now.host_boot_id()
            || now.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(&controller, 24))
        {
            return Err(CreateQ04ErrorV1::Expired.into());
        }
        Ok(())
    }

    fn consume_original_held_acknowledgement(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<(), RootActionFailureV1> {
        let (expected_phase, next_phase, request, response, packet_index) = match kind {
            super::Q04AcknowledgementKindV1::Policy => (
                RootQ04PreludePhaseV1::Decided, RootQ04PreludePhaseV1::PolicyAcknowledged,
                RootCreateQ04TransferKindV1::PolicyAcknowledgement, RootCreateQ04TransferKindV1::PolicyAccepted, 0,
            ),
            super::Q04AcknowledgementKindV1::Release => (
                RootQ04PreludePhaseV1::PolicyAcknowledged, RootQ04PreludePhaseV1::ReleaseAuthorized,
                RootCreateQ04TransferKindV1::ReleaseAcknowledgement, RootCreateQ04TransferKindV1::ReleaseAuthorized, 1,
            ),
            super::Q04AcknowledgementKindV1::Settlement => (
                RootQ04PreludePhaseV1::ReleaseAuthorized, RootQ04PreludePhaseV1::Settled,
                RootCreateQ04TransferKindV1::SettlementAcknowledgement, RootCreateQ04TransferKindV1::Settled, 2,
            ),
            super::Q04AcknowledgementKindV1::Clearance => (
                RootQ04PreludePhaseV1::Settled, RootQ04PreludePhaseV1::FinalClearance,
                RootCreateQ04TransferKindV1::ClearanceAcknowledgement, RootCreateQ04TransferKindV1::FinalClearance, 3,
            ),
        };
        if self.phase != expected_phase || self.acknowledgement_frames.len() != packet_index {
            return Err(CreateQ04ErrorV1::ChangedCut.into());
        }
        self.recheck_original()?;
        self.acknowledgement_frames.try_reserve_exact(1).map_err(CreateQ04ErrorV1::from)?;
        self.acknowledgement_frames.push(Vec::new());
        self.receive_original_exact(32 + kind.body_bytes() + 64, RootControllerFrameSlotV1::Acknowledgement)?;
        self.require_terminal_held_input_cut(kind)?;

        let frame = self.acknowledgement_frames.get(packet_index)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .admit_next_q04_acknowledgement_v1(kind, frame, &self.prehold,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                &self.controller_complete, &self.source_complete)
            .map_err(map_root_authority_error_v1)?;

        self.append_one_original_terminal_held_phase(kind)?;
        self.require_terminal_held_input_cut(kind)?;
        let history = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?;
        let phase = history.phase_record_v1(u8::try_from(packet_index + 4).map_err(|_| CreateQ04ErrorV1::Bounds)?).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(&mut self.sent, response, history.identity().nonce(), phase.bytes()).map_err(project_q04_wire_error_v1)?;
        self.write_original(&self.sent)?;
        self.require_terminal_held_input_cut(kind)?;
        self.phase = next_phase;
        Ok(())
    }

    fn append_one_original_terminal_held_phase(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<(), RootActionFailureV1> {
        self.require_terminal_held_input_cut(kind)?;
        self.append_parked_original_root_commit()?;
        if let Err(debt) = self.require_terminal_held_input_cut(kind) {
            return Err(debt);
        }
        Ok(())
    }

    fn require_terminal_held_input_cut(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<(), RootActionFailureV1> {
        self.recheck_original()?;
        let publication = self.read_original_policy_publication()?;
        let terminal_cache = if matches!(kind, super::Q04AcknowledgementKindV1::Settlement
            | super::Q04AcknowledgementKindV1::Clearance)
        {
            Some(self.park_current_terminal_cache(kind)?)
        } else { None };
        let history = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?;
        self.require_identity_clock(history.identity())?;
        let packet_index = match kind {
            super::Q04AcknowledgementKindV1::Policy => 0,
            super::Q04AcknowledgementKindV1::Release => 1,
            super::Q04AcknowledgementKindV1::Settlement => 2,
            super::Q04AcknowledgementKindV1::Clearance => 3,
        };
        let cache_uid = self.admission_data_v1()?.identities.cache_uid;
        let observed_source = self.source_observations.get(
            self.claim_source_observation.ok_or(CreateQ04ErrorV1::ChangedCut)?)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let observed_cache = terminal_cache.map(|index| self.cache_terminal_outcomes.get(index)
            .ok_or(CreateQ04ErrorV1::ChangedCut)).transpose()?;
        let returned = self.work.require_terminal_input_current_v1(
            self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, kind,
            self.acknowledgement_frames.get(packet_index).ok_or(CreateQ04ErrorV1::ChangedCut)?,
            &self.prehold, &self.claim, observed_source.as_ref(),
            &self.controller_complete, &self.source_complete, cache_uid, observed_cache,
        );
        self.require_work_action_v1(returned)?;
        let after = self.read_original_policy_publication()?;
        if publication != after { return Err(CreateQ04ErrorV1::ChangedCut.into()); }
        if let Some(before) = terminal_cache {
            let after = self.park_current_terminal_cache(kind)?;
            if self.cache_terminal_outcomes.get(before).and_then(|outcome| outcome.readback_v1())
                != self.cache_terminal_outcomes.get(after).and_then(|outcome| outcome.readback_v1())
            { return Err(CreateQ04ErrorV1::ChangedCut.into()); }
        }
        self.require_identity_clock(self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?.identity())?;
        Ok(())
    }

    fn park_current_terminal_cache(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<usize, CreateQ04ErrorV1> {
        match kind {
            super::Q04AcknowledgementKindV1::Settlement
            | super::Q04AcknowledgementKindV1::Clearance => {}
            _ => return Err(CreateQ04ErrorV1::ChangedCut),
        }
        if self.cache_terminal_outcomes.len() >= 32 {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        self.cache_terminal_outcomes.try_reserve_exact(1)?;
        let returned = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .replay_original_terminal_cache_v1(kind,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                &self.claim, &self.prehold, &self.controller_complete, &self.source_complete);
        // The real Root/Cache outcome is parked before any independent named,
        // native or final-clock check. Capacity was reserved before native IO.
        self.cache_terminal_outcomes.push(returned.map_err(map_root_authority_error_v1)?);
        let index = self.cache_terminal_outcomes.len() - 1;
        let (primary, final_mount) = {
            let outcome = self
                .cache_terminal_outcomes
                .get_mut(index)
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            (
                outcome.take_primary_error_once_v1(),
                outcome.take_final_mount_error_once_v1(),
            )
        };
        if let Some(first) = primary {
            let error = match first {
                aos_sandbox_policy::native::RootAuthorityCacheTerminalErrorV1::Authority(error) => {
                    map_root_authority_error_v1(error)
                }
                aos_sandbox_policy::native::RootAuthorityCacheTerminalErrorV1::Cache(error) => {
                    CreateQ04ErrorV1::NativeCache(Box::new(error))
                }
            };
            let _ = self.retain_outcome::<()>(Err(error));
        }
        if let Some(debt) = final_mount {
            let error = CreateQ04ErrorV1::CacheJournal(debt);
            if self.has_first_cause_v1() {
                self.postcheck_debt.get_mut().get_or_insert(error);
            } else {
                let _ = self.retain_outcome::<()>(Err(error));
            }
        }
        self.require_identity_clock(
            self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_history_v1().map_err(map_root_authority_error_v1)?
                .identity(),
        )?;
        if self.has_first_cause_v1() || self.postcheck_debt.get_mut().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(index)
    }

    // Only this same attempt's original retained fields supply the inputs.
    // The short genuine gen1 loan ends before any later Root action; returned
    // compiler DATA must be parked before the caller's final bookends.

    // Before any logical hold, only the actual pinned original Controller
    // DATA and signed Root inputs may form an inert compiler recipe. No held
    // packet, Cache authority or future native head is invented here.

    fn require_work_action_v1(&self, outcome: Result<(), ()>) -> Result<(), RootActionFailureV1> {
        match outcome {
            Ok(()) => Ok(()),
            Err(()) => { self.latch_policy_refusal_v1(); Err(RootActionFailureV1::PolicyHeld) }
        }
    }

    fn require_work_history_action_v1(&self,
        outcome: Result<(), aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1>,
    ) -> Result<(), RootActionFailureV1> {
        match outcome {
            Ok(()) => Ok(()),
            Err(aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1::PolicyHeld) => {
                self.latch_policy_refusal_v1(); Err(RootActionFailureV1::PolicyHeld)
            }
            Err(aos_sandbox_policy::native::RootPolicyHistoryAdmissionFailureV1::AuthorityHeld) => {
                self.latch_authority_refusal_v1(); Err(RootActionFailureV1::AuthorityHeld)
            }
        }
    }

    fn retain_action_outcome_v1<T>(&self, outcome: Result<T, RootActionFailureV1>) -> Result<T, ()> {
        match outcome {
            Ok(value) => self.retain_outcome(Ok(value)),
            Err(RootActionFailureV1::Owned(error)) => self.retain_outcome(Err(error)),
            Err(RootActionFailureV1::AuthorityHeld) => {
                self.latch_authority_refusal_v1();
                Err(())
            }
            Err(RootActionFailureV1::PolicyHeld) => {
                self.latch_policy_refusal_v1();
                Err(())
            }
        }
    }

    fn retain_outcome<T>(&self, outcome: Result<T, CreateQ04ErrorV1>) -> Result<T, ()> {
        match outcome {
            Ok(value) if !self.has_first_cause_v1() && !self.has_postcheck_debt_v1() => Ok(value),
            Ok(_) => Err(()),
            Err(error) => {
                if !self.has_first_cause_v1() {
                    *self.cause.borrow_mut() = Some(error);
                    self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
                }
                Err(())
            }
        }
    }

    fn has_first_cause_v1(&self) -> bool {
        if self.first_owner.get().is_none() && self.cause.borrow().is_some() {
            self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
        }
        self.first_owner.get().is_some()
    }

    fn has_postcheck_debt_v1(&self) -> bool {
        if self.debt_owner.get().is_none() && self.postcheck_debt.borrow().is_some() {
            self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
        }
        self.debt_owner.get().is_some()
    }

    // Called exactly at the returned native marker, before any owed post.
    fn latch_authority_refusal_v1(&self) {
        if !self.has_first_cause_v1() {
            self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::AuthorityHeld));
        } else if !self.has_postcheck_debt_v1() {
            self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::AuthorityHeld));
        }
    }

    // Called exactly at the returned native marker, before any owed post.
    fn latch_policy_refusal_v1(&self) {
        if !self.has_first_cause_v1() {
            self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::PolicyHeld));
        } else if !self.has_postcheck_debt_v1() {
            self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::PolicyHeld));
        }
    }

}

// The actual resource-only observation reserves all independent Result owners
// before the RPC. The paired sample remains whole and runs last even on Err.
#[derive(Default)]
struct RootResourceSourcePostsV2 {
    owners: [Option<Result<(), CreateQ04ErrorV1>>; 4],
    target: Option<Result<(), ()>>,
    clock: Option<Result<RawPairedClockSample, CreateQ04ErrorV1>>,
}

/// Lends one actual Root-selected request to the unchanged fixed Source RPC.
///
/// The loan exposes only existing request/key DATA. It retains the actual Root
/// owner and original stream/startup/state loans; it cannot clone, extract or
/// manufacture an authority. Its caller parks the actual returned `Result`
/// through [`Self::park_result`] or [`Self::park_result_v2`] before postchecks.
pub struct RootCreateQ04SourceObservationLoanV1<'attempt, 'authority, 'origin, 'startup> {
    root: &'attempt mut RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>,
    original: RootNativeInputLoanV1<'attempt, 'origin, 'startup>,
    origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    cause: &'attempt RefCell<Option<CreateQ04ErrorV1>>,
    first_owner: &'attempt Cell<Option<RootQ04FirstCauseOwnerV1>>,
    debt_owner: &'attempt Cell<Option<RootQ04FirstCauseOwnerV1>>,
    project: aos_sandbox_model::ProjectId,
    challenge: SourceTreeGenesisChallengeV1,
    context: SourceTreeGenesisIntentContextV1,
    purpose: RootSourceObservationPurposeV1,
    received: &'attempt mut Option<Result<super::super::SourceTreeGenesisReadbackPacketV2, std::io::Error>>,
    observations: &'attempt mut Vec<super::super::SourceTreeGenesisReadbackPacketV2>,
    resource_posts: Option<&'attempt mut RootResourceSourcePostsV2>,
    source_complete: &'attempt mut Vec<u8>,
    controller_complete: &'attempt [u8],
    floor: &'attempt mut Option<SourceHierarchyFloorRecordV1>,
    phase: &'attempt mut RootQ04PreludePhaseV1,
    postcheck_debt: &'attempt RefCell<Option<CreateQ04ErrorV1>>,
    finished: bool,
}

impl RootCreateQ04SourceObservationLoanV1<'_, '_, '_, '_> {
    /// Borrows the same independently pinned Root request inputs.
    ///
    /// The returned project/context are comparison DATA for the old RPC;
    /// signature verification is not currentness or permission to mutate.
    ///
    /// # Errors
    /// Parks the actual native pin-owner failure before returning its marker.
    pub fn request(&self) -> Result<(
        SourceTreeGenesisChallengeV1,
        aos_sandbox_model::ProjectId,
        &SourceTreeGenesisIntentContextV1,
        &PinnedSourceHoldReadbackSignerV1,
    ), ()> {
        match self.root.source_readback_pin_data_v1() {
            Ok(pin) => Ok((self.challenge, self.project, &self.context, pin)),
            Err(error) => {
                self.retain_error(project_root_authority_genesis_error_v1(error));
                Err(())
            }
        }
    }

    /// Parks the real returned packet or first I/O cause before postchecks.
    ///
    /// # Errors
    /// Retains the RPC's actual error and separately records a later original
    /// owner/clock check failure. The enclosing attempt remains closed; this
    /// does not repair the old RPC's callee-local pre-return custody gap.
    pub fn park_result(
        self,
        returned: Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], std::io::Error>,
    ) -> Result<(), ()> {
        self.park_result_v2(returned.map(super::super::SourceTreeGenesisReadbackPacketV2::Legacy))
    }

    /// Parks the full resource packet before all independent owner posts.
    ///
    /// # Errors
    /// Retains the actual RPC cause, Root post and original-flight post without
    /// renewing the deadline. The original clock-bearing post runs last.
    pub fn park_result_v2(
        mut self,
        returned: Result<super::super::SourceTreeGenesisReadbackPacketV2, std::io::Error>,
    ) -> Result<(), ()> {
        *self.received = Some(returned);
        if matches!(self.received, Some(Err(_))) {
            match self.received.take() {
                Some(Err(error)) => {
                    self.retain_error(error.into());
                }
                original => *self.received = original,
            }
        }
        self.complete_original_posts_v1();
        if !self.has_first_cause_v1() {
            let accepted = self.accept_original_packet();
            if let Err(error) = accepted {
                if !self.original.has_retained_failure_v1() {
                    self.retain_error(error);
                }
            }
        }
        self.finished = true;
        if self.has_first_cause_v1() || self.has_postcheck_debt_v1() {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Completes owed posts after the actual pinned request was refused.
    ///
    /// No RPC result is fabricated. The actual request failure is already
    /// retained in this same outer Attempt before independent posts run.
    ///
    /// # Errors
    /// Always returns the refusal marker after retaining all reached post debt.
    pub fn park_request_refusal_v1(mut self) -> Result<(), ()> {
        self.complete_original_posts_v1();
        self.finished = true;
        Err(())
    }

    fn complete_original_posts_v1(&mut self) {
        if let Some(posts) = self.resource_posts.take() {
            // These Results remain parked before any later independent IO.
            posts.owners[0] = Some(self.root.recheck().map_err(project_root_authority_genesis_error_v1));
            posts.owners[1] = Some(self.origin.try_borrow_mut()
                .map_err(CreateQ04ErrorV1::OriginBorrowMut)
                .and_then(|original| original.observe_ordinary_startup_post_once_v1()
                    .map_err(project_root_q04_origin_error_v1)));
            posts.owners[2] = Some(self.origin.try_borrow_mut()
                .map_err(CreateQ04ErrorV1::OriginBorrowMut)
                .and_then(|original| original.observe_ordinary_peer_post_once_v1()
                    .map_err(project_root_q04_origin_error_v1)));
            posts.owners[3] = Some(self.origin.try_borrow_mut()
                .map_err(CreateQ04ErrorV1::OriginBorrowMut)
                .and_then(|original| original.observe_ordinary_queue_post_once_v1()
                    .map_err(project_root_q04_origin_error_v1)));
            // Classification has no effects. Earlier owning errors must win
            // before Target parks a later typed refusal on its own Work.
            for result in &mut posts.owners {
                self.retain_post_result_v1(result);
            }

            posts.target = Some(self.original.require_original_target_names_post_once_v1());
            if matches!(posts.target, Some(Err(()))) {
                self.latch_policy_refusal_v1();
            }
            // The same original clock is independently owed after Target,
            // including when the Target marker selected native post debt.
            posts.clock = Some(self.origin.try_borrow_mut()
                .map_err(CreateQ04ErrorV1::OriginBorrowMut)
                .and_then(|mut original| original.observe_original_clock_once_v1()
                    .map_err(project_root_q04_origin_error_v1)));
            self.retain_post_result_v1(&mut posts.clock);
            self.resource_posts = Some(posts);
        } else {
            match self.root.recheck().map_err(project_root_authority_genesis_error_v1) {
                Err(error) => self.retain_error(error),
                Ok(()) => {
                    let checked = self.original.recheck_v1();
                    if checked.is_err() && self.original.has_retained_failure_v1() {
                        self.latch_policy_refusal_v1();
                    }
                    if let Err(error) = checked {
                        if !self.original.has_retained_failure_v1() {
                            self.retain_error(project_root_policy_error_v1(error));
                        }
                    }
                }
            }
        }
    }

    // Moving an actual Result is diagnostic custody only. A later error stays
    // in its original reservoir when an earlier native debt already won.
    fn retain_post_result_v1<T>(&self, result: &mut Option<Result<T, CreateQ04ErrorV1>>) {
        if !result.as_ref().is_some_and(Result::is_err) {
            return;
        }
        if !self.has_first_cause_v1() {
            if let Some(Err(error)) = result.take() {
                *self.cause.borrow_mut() = Some(error);
                self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
            }
        } else if !self.has_postcheck_debt_v1() {
            if let Some(Err(error)) = result.take() {
                *self.postcheck_debt.borrow_mut() = Some(error);
                self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
            }
        }
    }

    fn accept_original_packet(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.root.require_existing_completed_floor_v1(self.project)
            .map_err(map_root_authority_error_v1)?;
        let packet = self.received.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let completed = !matches!(self.purpose, RootSourceObservationPurposeV1::Preparation);
        let floor = if completed {
            let current = self.root.refresh_completed_gen1_v1(self.controller_complete, packet.as_ref())
                .map_err(map_root_authority_error_v1)?;
            current.recheck().map_err(map_root_authority_error_v1)?;
            current.floor().clone()
        } else {
            self.root.recover_existing_floor_v1(packet.as_ref())
                .map_err(project_root_authority_genesis_error_v1)?
        };
        if self.floor.as_ref().is_some_and(|prior| prior != &floor) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.root.recheck().map_err(project_root_authority_genesis_error_v1)?;
        let checked = self.original.recheck_v1();
        if checked.is_err() && self.original.has_retained_failure_v1() {
            self.latch_policy_refusal_v1();
        }
        checked.map_err(project_root_policy_error_v1)?;

        if completed {
            self.source_complete.clear();
            self.source_complete.extend_from_slice(packet.as_ref());
        }
        *self.floor = Some(floor);
        // Capacity and slot vacancy were checked before invocation. This
        // final move invokes no callback and allocates no storage.
        match self.received.take() {
            Some(Ok(packet)) => self.observations.push(packet),
            original => {
                *self.received = original;
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        *self.phase = match self.purpose {
            RootSourceObservationPurposeV1::Preparation => RootQ04PreludePhaseV1::PreparedSource,
            RootSourceObservationPurposeV1::Completion => RootQ04PreludePhaseV1::CompletedSource,
            RootSourceObservationPurposeV1::Refresh => RootQ04PreludePhaseV1::RefreshedSource,
        };
        Ok(())
    }

    fn retain_error(&self, error: CreateQ04ErrorV1) {
        if self.has_first_cause_v1() {
            if self.postcheck_debt.borrow().is_none() {
                *self.postcheck_debt.borrow_mut() = Some(error);
                // A prior native debt remains the chronological selector even
                // if this separate owning slot retains a later actual error.
                if self.debt_owner.get().is_none() {
                    self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
                }
            }
        } else {
            *self.cause.borrow_mut() = Some(error);
            self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
        }
    }

    fn has_first_cause_v1(&self) -> bool {
        if self.first_owner.get().is_none() && self.cause.borrow().is_some() {
            self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
        }
        self.first_owner.get().is_some()
    }

    fn has_postcheck_debt_v1(&self) -> bool {
        if self.debt_owner.get().is_none() && self.postcheck_debt.borrow().is_some() {
            self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::UpperOwned));
        }
        self.debt_owner.get().is_some()
    }

    fn latch_policy_refusal_v1(&self) {
        if !self.has_first_cause_v1() {
            self.first_owner.set(Some(RootQ04FirstCauseOwnerV1::PolicyHeld));
        } else if !self.has_postcheck_debt_v1() {
            self.debt_owner.set(Some(RootQ04FirstCauseOwnerV1::PolicyHeld));
        }
    }

}

impl Drop for RootCreateQ04SourceObservationLoanV1<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            // No abandonment/unwind may release the enclosing borrowed Root
            // writer or original socket while this request is unresolved.
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_policy::q04_data::{
        RootQ04RecordKeyV1, root_capacity_acknowledgement, root_phase_record,
    };

    // Canonical inert DATA only. No genuine owner, floor, native commit,
    // currentness, capacity reservation or deployment fixture is constructed.
    pub(super) fn cut() -> Q04CutIdentityV1 {
        let mut body = [0; super::super::IDENTITY_BYTES];
        body[16..80].fill(1);
        body[80..84].copy_from_slice(&1000_u32.to_be_bytes());
        body[84..88].copy_from_slice(&1001_u32.to_be_bytes());
        body[88..104].copy_from_slice(&[1_u64.to_be_bytes(), 1_u64.to_be_bytes()].concat());
        body[112..128].fill(2);
        for (offset, value) in [(128, 100_u64), (136, 60_000_000_100),
            (144, 200), (152, 65_000_000_200), (160, 7)]
        {
            body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        body[168..184].fill(3);
        body[184..200].fill(4);
        for (index, start) in (200..648).step_by(32).enumerate() {
            body[start..start + 32].fill(5 + index as u8);
        }
        Q04CutIdentityV1::from_body(body).unwrap()
    }

    #[test]
    fn root_record_keys_keep_the_funded_exact_namespace_widths() {
        let nonce = [1; 16];

        for (key, expected) in [
            (RootQ04RecordKeyV1::Cut, 37),
            (RootQ04RecordKeyV1::Phase(1), 40),
            (RootQ04RecordKeyV1::Decision, 42),
            (RootQ04RecordKeyV1::Packet(4), 41),
            (RootQ04RecordKeyV1::ClaimIndex, 45),
            (RootQ04RecordKeyV1::ClaimChunk(341), 41),
        ] {
            assert_eq!(key.encode(nonce).unwrap().len(), expected);
            assert!(key.encode([0; 16]).is_err());
        }
        assert!(RootQ04RecordKeyV1::Phase(8).encode(nonce).is_err());
        assert!(RootQ04RecordKeyV1::Packet(5).encode(nonce).is_err());
    }

    #[test]
    fn root_phase_capacity_recipe_requires_the_actual_prior_release_row_digest() {
        let cut = cut();
        let before = ObjectDigest::from_bytes([1; 32]);
        let zero = ObjectDigest::from_bytes([0; 32]);
        let pairs = [ObjectDigest::from_bytes([2; 32]); 6];
        let r5 = root_phase_record(&cut, 5, [5; 16], before, Some(before),
            [before, before, ObjectDigest::from_bytes([3; 32]), zero, zero],
            pairs, Some(before)).unwrap();
        let wrong = root_phase_record(&cut, 6, [6; 16], before, Some(r5.digest()),
            [before, before, ObjectDigest::from_bytes([4; 32]), zero, zero],
            pairs, Some(before)).unwrap();

        assert!(wrong.require_successor(&r5).is_err());

        let correct = root_phase_record(&cut, 6, [6; 16], before, Some(r5.digest()),
            [before, before, r5.digest(), zero, zero], pairs, Some(before)).unwrap();
        correct.require_successor(&r5).unwrap();
        assert_eq!(&r5.bytes()[320..352], &[0; 32]);
        assert_ne!(&correct.bytes()[320..352], &[0; 32]);
        assert_eq!(&correct.bytes()[192..288], &[0; 96]);
    }

    #[test]
    fn capacity_acknowledgement_is_not_an_authentic_controller_packet() {
        use super::super::{Q04AcknowledgementKindV1, Q04AcknowledgementV1};

        let cut = cut();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let credential =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                1,
                &key.verifying_key(),
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let pin = aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1::decode(
            &credential,
        )
        .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
        .unwrap();
        let kind = Q04AcknowledgementKindV1::Policy;
        let mut packet = Vec::new();

        root_capacity_acknowledgement(&mut packet, kind, &cut, 7,
            ObjectDigest::from_bytes([3; 32]), [ObjectDigest::from_bytes([2; 32]); 6]).unwrap();

        assert_eq!(packet.len(), 408);
        assert_eq!(&packet[76..84], &16_u64.to_be_bytes());
        assert!(matches!(Q04AcknowledgementV1::verify(kind, &packet, &pin, &cut),
            Err(aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1::AcknowledgementSignature(_))));
    }
}
