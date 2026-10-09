//! Resident Controller-side data on the same original gen1 Root flight.
//!
//! External Controller, Source and Cache owners stay in their actual caller.
//! This capsule owns only original connection descriptions, received results,
//! partial packets and the first typed cause. No reconstructed Preview or
//! copied floor can replace the short genuine completed-gen1 owner loans.

use std::os::fd::OwnedFd;

use aos_sandbox_core::ProjectId;
use aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use ed25519_dalek::SigningKey;
use sha2::Digest as _;

use crate::Journal;
use crate::hierarchy::controller_genesis::hold_existing_completed_source_genesis_v2;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::protected_journal::retained_tree_inventory_data_v1;
use crate::hierarchy::source_genesis::observe_retained_source_genesis_v1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;

use super::super::source_genesis_root::{
    ControllerGenesisReadbackPacketV2, OriginalRootGenesisFlightV1,
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, RootCreateQ04TransferKindV1,
    RootSourceGenesisFrameKindV1, decode_root_create_q04_transfer_v1,
    encode_root_source_genesis_frame_v2,
};
use super::super::{
    CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1, CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1,
    ControllerHoldReadbackChallengeV1, ControllerProjectAdmissionChallengeV1,
    StagedClosedPolicyRootBaseV2, StagedClosedPolicySignerChallengeV2,
    staged_closed_policy_signer_challenge_v2,
};
use super::{
    CLAIM_CHUNK_BYTES, CLAIM_CHUNK_PREFIX_BYTES, CreateQ04ErrorV1, PREVIEW_INDEX_BYTES,
    Q04PreviewChunkV1, Q04PreviewTransferRecipeV1, Q04PreviewV1, preview_index_shape,
    PREHOLD_METADATA_BYTES, PREHOLD_RESPONSE_BYTES, Q04PreholdInputDataV1,
    Q04PreholdPublicationDataV1, Q04PreholdTransferRecipeV1,
};

// This pre-completion borrower admits only conservative preparation payment.
// Its private constructor is below the genuine original Anchored receive;
// it is not a Completed ancestry, child-grant or detached currentness proof.
pub(crate) struct OriginalQ04ProjectPreparationLoanV1<'cut, 'controller, 'source, 'flight> {
    controller: &'cut crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1<'controller>,
    source: &'cut crate::hierarchy::source_genesis::HeldSourceTreeGenesisObservationV1<'source>,
    inventory: &'cut crate::hierarchy::protected_journal::RetainedTreeInventoryDataV1<'source>,
    root: &'cut super::super::source_genesis_root::RootSourceGenesisFloorProofV1<'flight>,
    original: aos_sandbox_core::RawPairedClockSample,
    nonce: [u8; 16],
}

impl OriginalQ04ProjectPreparationLoanV1<'_, '_, '_, '_> {
    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.controller.recheck_current_admission()?;
        self.source.require_retained_inventory_v1(self.inventory)?;
        self.controller.recheck_completed_source_ack(self.source)?;
        self.root.recheck()?;
        let floor = self.root.floor();
        if floor.semantic_revision() != 1 || floor.predecessor().is_some()
            || self.source.project() != Some(floor.project())
            || self.controller.acceptance().project() != floor.project()
            || self.source.source_uid() != self.root.source_uid()
            || self.source.receipt() != Some(floor.receipt())
            || self.source.ack_floor_digest() != Some(floor.digest())
            || self.source.ack_record_digest().is_none()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let (tree, head, lineage) = self.inventory.trees()?
            .find(|(tree, _, _)| tree.project() == floor.project())
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        if tree.tree_generation().get() != 1 || tree.records().next().is_some()
            || tree.tombstones().next().is_some()
            || head != floor.tree_head() || lineage != floor.lineage_head()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.controller.borrow_current_project_resources_v3()?.recheck()?;
        Ok(())
    }

    pub(crate) fn data(&self) -> Result<crate::controller_resource_reservation::OriginalPreparationData, SourceGenesisErrorV1> {
        self.recheck()?;
        let authorization = self.controller.borrow_current_project_resources_v3()?;
        let project = authorization.acceptance().project();
        let (tree, _, _) = self.inventory.trees()?
            .find(|(tree, _, _)| tree.project() == project)
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        let tree = crate::hierarchy::codec::tree_commitment_v1(tree)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let floor = self.root.floor();
        let deadline = self.original.boottime_nanoseconds().checked_add(60_000_000_000)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        Ok(crate::controller_resource_reservation::OriginalPreparationData {
            project: *project.as_bytes(),
            authorization: *authorization.acceptance().digest().as_bytes(),
            tree: *tree.as_bytes(), instance: floor.instance(),
            operation: [0; 16], amount: authorization.envelope(), original: self.original,
            deadline, nonce: self.nonce,
            controller_names: self.controller.names(), source_names: self.source.names(),
            source_sequence: self.source.snapshot_sequence(), floor: *floor.digest().as_bytes(),
            tree_head: *floor.tree_head().as_bytes(), lineage_head: *floor.lineage_head().as_bytes(),
        })
    }

    pub(crate) fn observe_posts(&self, posts: &mut [Option<Result<(), SourceGenesisErrorV1>>; 3]) {
        posts[0] = Some(self.controller.recheck_current_admission());
        posts[1] = Some(self.source.require_retained_inventory_v1(self.inventory));
        posts[2] = Some(self.root.recheck());
    }
}

pub(crate) struct OriginalQ04CompletedPreparationLoanV1<'cut, 'controller, 'source, 'completed, 'flight> {
    original: OriginalQ04ProjectPreparationLoanV1<'cut, 'controller, 'source, 'flight>,
    completed: &'cut super::super::source_genesis_root::CompletedRootSourceGenesisFloorV1<'completed, 'flight>,
}

impl OriginalQ04CompletedPreparationLoanV1<'_, '_, '_, '_, '_> {
    pub(crate) fn allocation_shape(
        &self,
    ) -> Result<crate::controller_resource_reservation::service_interval::JournalShape, SourceGenesisErrorV1> {
        self.original.controller.q04_preparation_allocation_shape_v1()
    }

    pub(crate) fn original_data(
        &self,
    ) -> Result<crate::controller_resource_reservation::OriginalPreparationData, SourceGenesisErrorV1> {
        self.original.data()
    }

    // The same original lenders are observed independently even if the
    // separate complete ACK conjunction or an earlier demand failed.
    pub(crate) fn observe_posts(&self, posts: &mut [Option<Result<(), SourceGenesisErrorV1>>; 3]) {
        self.original.observe_posts(posts);
    }

    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.original.recheck()?;
        super::super::public_create_source::consume_completed_gen1_ancestry_v1(
            self.original.controller, self.original.source, self.original.inventory, self.completed,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Q04ClientPhaseV1 {
    Prehold,
    Claimed,
    Decided,
    PolicyAccepted,
    ReleaseAuthorized,
    Settled,
    FinalClearance,
    FinalObservation,
}

// Owned compiler/prehold DATA is parked by the actual method-specific caller
// before its postchecks. It borrows no Journal and cannot prolong a live cut.
pub(crate) struct Q04ControllerPreparationV1 {
    source: super::super::CurrentCreateProjectPolicySourceV1,
    staged: StagedClosedPolicyRootBaseV2,
    proposed: Vec<u8>,
    metadata: [u8; PREHOLD_METADATA_BYTES],
    controller_uid: u32,
    source_uid: u32,
    floor: aos_sandbox_core::ObjectDigest,
    ancestry: aos_sandbox_core::ObjectDigest,
    candidate: aos_sandbox_policy::CompiledPolicyCandidateV1,
    input_origin: super::Q04PreparedInputOriginV1,
    publication_recipe: super::super::protected_journal::Q04IndependentPublicationRecipeV1,
}

impl Q04ControllerPreparationV1 {
    pub(crate) fn staged(&self) -> StagedClosedPolicyRootBaseV2 { self.staged }

    pub(crate) fn proposed(&self) -> &[u8] { &self.proposed }

    pub(crate) fn metadata(&self) -> &[u8; PREHOLD_METADATA_BYTES] { &self.metadata }

    pub(crate) fn candidate(&self) -> &aos_sandbox_policy::CompiledPolicyCandidateV1 {
        &self.candidate
    }

    pub(crate) fn input_origin(&self) -> &super::Q04PreparedInputOriginV1 {
        &self.input_origin
    }
}

pub(crate) struct OriginalCreateQ04InvocationV1<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    resource_bank: Option<std::sync::Arc<std::sync::Mutex<crate::controller_resource_reservation::ControllerResourceBankOpeningV1>>>,
    preparation_operation: Option<aos_sandbox_core::OperationId>,
    resource_preparation: Option<crate::controller_resource_reservation::ProjectPreparationReservationAttemptV1>,
    component_admission: Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
    raw: Option<OwnedFd>,
    adopted: Option<RetainedUnixStream>,
    flight: Option<OriginalRootGenesisFlightV1<'profile>>,
    received: Option<Result<UnixStreamSubjectChunk, RetainedSeqpacketReceiveErrorV1>>,
    hello: Vec<u8>,
    sent: Vec<u8>,
    floor_frame: Vec<u8>,
    completed_frame: Vec<u8>,
    source_frame: Vec<u8>,
    preview_index_frame: Vec<u8>,
    preview_chunk_frame: Vec<u8>,
    preview: Vec<u8>,
    prehold: Vec<u8>,
    prehold_chunk: Vec<u8>,
    prehold_response: Vec<u8>,
    prepare: Option<ControllerGenesisReadbackPacketV2>,
    complete: Option<ControllerGenesisReadbackPacketV2>,
    refresh_complete: Vec<ControllerGenesisReadbackPacketV2>,
    refresh_source_frames: Vec<Vec<u8>>,
    refresh_sign_result: Option<Result<ControllerGenesisReadbackPacketV2, SourceGenesisErrorV1>>,
    controller_current: Option<[u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1]>,
    controller_hold: Option<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]>,
    claim: Vec<u8>,
    claim_chunk: Vec<u8>,
    decision_frame: Vec<u8>,
    acknowledgements: Vec<Vec<u8>>,
    root_phase_frames: Vec<Vec<u8>>,
    shutdown_observation: Option<Result<usize, rustix::io::Errno>>,
    shutdown_byte: [u8; 1],
    phase: Q04ClientPhaseV1,
    first: Option<CreateQ04ErrorV1>,
    postcheck_debt: Option<CreateQ04ErrorV1>,
    cleared: bool,
}

// This short loan comes only from the same successful prehold exchange. It
// keeps the real original Root flight borrowed; neither a decoded Cut nor a
// signed packet can construct it. It grants terminal observation, not release.
pub(crate) struct OriginalQ04RootCacheLoanV1<'invocation, 'profile, 'cut> {
    invocation: &'invocation OriginalCreateQ04InvocationV1<'profile>,
    identity: &'cut super::Q04CutIdentityV1,
}

// This is only a short terminal observation on the actual original invocation.
// Neither Root7 DATA nor a supplied EOF can construct it. It supplies no floor,
// mutation permission, new currentness, physical retirement or Drain.
pub(crate) struct OriginalQ04FinalRootObservationV1<'invocation, 'profile, 'cut> {
    invocation: &'invocation OriginalCreateQ04InvocationV1<'profile>,
    identity: &'cut super::Q04CutIdentityV1,
}

impl OriginalQ04FinalRootObservationV1<'_, '_, '_> {
    pub(crate) fn identity(&self) -> &super::Q04CutIdentityV1 {
        self.identity
    }

    // This borrows the genuine returned phase under the final original loan.
    // Its digest is terminal history DATA, never new Root/current authority.
    pub(crate) fn terminal_digest(&self) -> Result<aos_sandbox_core::ObjectDigest, CreateQ04ErrorV1> {
        self.recheck()?;
        self.invocation.root_phase(self.identity, 3).map(|phase| phase.digest())
    }

    pub(crate) fn recheck(&self) -> Result<(), CreateQ04ErrorV1> {
        if self.invocation.phase != Q04ClientPhaseV1::FinalObservation
            || !matches!(self.invocation.shutdown_observation, Some(Ok(0)))
            || self.invocation.first.is_some() || self.invocation.postcheck_debt.is_some()
            || self.invocation.refresh_complete.len() != 11
            || self.invocation.refresh_source_frames.len() != 11
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let flight = self.invocation.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let clock = flight.q04_terminal_original_clock()?;
        let nonce = flight.q04_terminal_nonce()?;
        let preview = Q04PreviewV1::decode(&self.invocation.preview, nonce)?;
        let response = decode_root_create_q04_transfer_v1(
            &self.invocation.prehold_response, RootCreateQ04TransferKindV1::PreholdRecipe, nonce,
        )?;
        let response = Q04PreholdPublicationDataV1::decode(response, nonce)?;
        require_original_identity_data(self.identity, clock, nonce, &preview, &response)?;
        if self.invocation.root_phase(self.identity, 3)?.phase() != 7 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        flight.q04_terminal_clock()?;
        Ok(())
    }
}

fn require_original_identity_data(
    identity: &super::Q04CutIdentityV1,
    original: aos_sandbox_core::RawPairedClockSample,
    nonce: [u8; 16],
    preview: &Q04PreviewV1<'_>,
    response: &Q04PreholdPublicationDataV1,
) -> Result<(), CreateQ04ErrorV1> {
    let metadata = preview.fields()[0];
    let cut = identity.bytes();
    let reply = response.bytes();
    if identity.nonce() != nonce
        || cut[112..128] != original.host_boot_id()
        || cut[128..136] != original.boottime_nanoseconds().to_be_bytes()
        || cut[112..128] != metadata[..16]
        || cut[144..160] != metadata[16..32]
        || cut[168..200] != reply[128..160]
        || cut[296..328] != reply[288..320]
        || cut[328..392] != reply[320..384]
        || cut[392..424] != reply[64..96]
        || cut[520..584] != reply[160..224]
        || cut[616..648] != reply[256..288]
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(())
}

impl OriginalQ04RootCacheLoanV1<'_, '_, '_> {
    pub(crate) fn identity(&self) -> &super::Q04CutIdentityV1 {
        self.identity
    }

    pub(crate) fn recheck(&self) -> Result<(), CreateQ04ErrorV1> {
        self.invocation.require_cache_terminal_original(self.identity)
    }

    pub(crate) fn require_signing_boundary(&self) -> Result<(), CreateQ04ErrorV1> {
        self.recheck()?;
        let flight = self.invocation.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        flight.require_q04_signing_boundary()?;
        Ok(())
    }

    pub(crate) fn cache_signing_challenge(
        &self,
        staged: StagedClosedPolicyRootBaseV2,
        proposed: &[u8],
    ) -> Result<crate::cache_residency::CacheOwnerReadbackChallengeV1, CreateQ04ErrorV1> {
        self.recheck()?;
        if super::super::closed_policy_binding_digest_v2(proposed)? != self.identity.binding() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let challenge = self.invocation.signing_challenge(staged, proposed)?;
        let challenge = crate::cache_residency::CacheOwnerReadbackChallengeV1::new(
            challenge.nonce(), challenge.cut(),
        )?;
        self.recheck()?;
        Ok(challenge)
    }

    pub(crate) fn require_controller_transition(
        &self,
        transition: &crate::journal::ControllerQ04TransitionV1<'_>,
    ) -> Result<(), CreateQ04ErrorV1> {
        self.recheck()?;
        if !std::ptr::eq(transition.identity(), self.identity) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let index = usize::from(transition.phase_number()).checked_sub(1)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let expected = match index {
            0 => Q04ClientPhaseV1::Prehold,
            1 => Q04ClientPhaseV1::Decided,
            2 | 3 => Q04ClientPhaseV1::PolicyAccepted,
            4 => Q04ClientPhaseV1::ReleaseAuthorized,
            5 | 6 => Q04ClientPhaseV1::Settled,
            7 => Q04ClientPhaseV1::FinalClearance,
            _ => return Err(CreateQ04ErrorV1::ChangedCut),
        };
        if self.invocation.phase != expected {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let phase = transition.phase_record();
        if index >= 1 {
            let actual = self.invocation.decision(self.identity)?;
            let gate = super::root::root_consumed_gate_record(self.identity, &actual)?;
            if phase.bytes()[96..128] != *actual.digest().as_bytes()
                || phase.bytes()[128..160] != *gate.digest().as_bytes()
                || phase.bytes()[352..384] != actual.bytes()[216..248]
                || phase.bytes()[416..448] != actual.bytes()[248..280]
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        let acknowledgement_index = match index {
            2 | 3 => Some(0),
            4 => Some(1),
            5 | 6 => Some(2),
            7 => Some(3),
            _ => None,
        };
        if let Some(index) = acknowledgement_index {
            let actual = self.invocation.acknowledgements.get(index)
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            if phase.acknowledgement().as_bytes()
                != sha2::Sha256::digest(actual).as_slice()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        if index >= 4 && phase.bytes()[160..192] != *self.release_phase()?.digest().as_bytes() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if index >= 5 && phase.bytes()[192..224] != *self.settlement_phase()?.digest().as_bytes() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if index == 7 && phase.bytes()[256..288]
            != *self.invocation.root_phase(self.identity, 3)?.digest().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()
    }

    // Only actual responses parked on this same original flight select a
    // lower mutation. The returned phase is comparison DATA; the loan itself
    // remains borrowed through the real Cache/Source action and bookends.
    pub(crate) fn require_lower_transition(
        &self,
        index: usize,
        release_authorization: Option<aos_sandbox_core::ObjectDigest>,
    ) -> Result<(), CreateQ04ErrorV1> {
        self.recheck()?;
        match index {
            0 if self.invocation.phase == Q04ClientPhaseV1::Prehold => {
                if release_authorization.is_some() {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            }
            1 if self.invocation.phase == Q04ClientPhaseV1::ReleaseAuthorized => {
                if release_authorization != Some(self.release_phase()?.digest()) {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            }
            2 if self.invocation.phase == Q04ClientPhaseV1::Settled => {
                if release_authorization != Some(self.release_phase()?.digest()) {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.settlement_phase()?;
            }
            _ => return Err(CreateQ04ErrorV1::ChangedCut),
        }
        self.recheck()
    }

    pub(crate) fn release_phase(&self) -> Result<super::Q04PhaseRecordV1, CreateQ04ErrorV1> {
        self.recheck()?;
        if !matches!(self.invocation.phase, Q04ClientPhaseV1::ReleaseAuthorized | Q04ClientPhaseV1::Settled
            | Q04ClientPhaseV1::FinalClearance) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let phase = self.invocation.root_phase(self.identity, 1)?;
        if phase.phase() != 5 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        Ok(phase)
    }

    pub(crate) fn settlement_phase(&self) -> Result<super::Q04PhaseRecordV1, CreateQ04ErrorV1> {
        self.recheck()?;
        if !matches!(self.invocation.phase, Q04ClientPhaseV1::Settled | Q04ClientPhaseV1::FinalClearance) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let phase = self.invocation.root_phase(self.identity, 2)?;
        let release = self.release_phase()?;
        if phase.phase() != 6 || phase.bytes()[160..192] != *release.digest().as_bytes() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        Ok(phase)
    }
}

impl<'profile> OriginalCreateQ04InvocationV1<'profile> {
    // The actual worker creates this in its Cache guard scope, before opening
    // Root. There is no supplied descriptor, authority callback or second graph.
    pub(crate) fn park(profile: &'profile ProductionControllerNormalRootProfileV1) -> Self {
        Self {
            profile,
            resource_bank: None,
            preparation_operation: None,
            resource_preparation: None,
            component_admission: None,
            raw: None,
            adopted: None,
            flight: None,
            received: None,
            hello: Vec::new(),
            sent: Vec::new(),
            floor_frame: Vec::new(),
            completed_frame: Vec::new(),
            source_frame: Vec::new(),
            preview_index_frame: Vec::new(),
            preview_chunk_frame: Vec::new(),
            preview: Vec::new(),
            prehold: Vec::new(),
            prehold_chunk: Vec::new(),
            prehold_response: Vec::new(),
            prepare: None,
            complete: None,
            refresh_complete: Vec::new(),
            refresh_source_frames: Vec::new(),
            refresh_sign_result: None,
            controller_current: None,
            controller_hold: None,
            claim: Vec::new(),
            claim_chunk: Vec::new(),
            decision_frame: Vec::new(),
            acknowledgements: Vec::new(),
            root_phase_frames: Vec::new(),
            shutdown_observation: None,
            shutdown_byte: [0; 1],
            phase: Q04ClientPhaseV1::Prehold,
            first: None,
            postcheck_debt: None,
            cleared: false,
        }
    }

    pub(crate) fn connect_existing_gen1(
        &mut self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        project: ProjectId,
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), ()> {
        let result = self.connect_original_gen1(journal, source, project, signer_generation, signer);
        self.retain_result(result)
    }

    pub(crate) fn arm_resource_preparation(
        &mut self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        bank: &std::sync::Arc<std::sync::Mutex<crate::controller_resource_reservation::ControllerResourceBankOpeningV1>>,
        operation: aos_sandbox_core::OperationId,
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.flight.is_some() || self.resource_preparation.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.resource_bank = Some(std::sync::Arc::clone(bank));
        self.preparation_operation = Some(operation);
        self.resource_preparation = Some(crate::controller_resource_reservation::ProjectPreparationReservationAttemptV1::new());
        self.component_admission = Some(self.resource_preparation.as_mut()
            .ok_or(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict)
            .and_then(|preparation| preparation.prepare_original_intake_once(journal, source, bank, self.profile))
            .and_then(|()| crate::controller_resource_reservation::require_controller_interval(
                bank, journal, self.profile,
            )));
        if matches!(self.component_admission, Some(Ok(()))) { Ok(()) }
        else { Err(CreateQ04ErrorV1::ChangedCut) }
    }

    pub(crate) fn require_resource_preparation(&self) -> Result<(), CreateQ04ErrorV1> {
        self.resource_preparation.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .require_preparation()
            .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))
    }

    pub(crate) fn resource_preparation(&self) -> Result<&crate::ProjectPreparationReservationAttemptV1, CreateQ04ErrorV1> {
        self.require_resource_preparation()?;
        self.resource_preparation.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn original_input_demand(
        &self,
        inclusive: aos_sandbox_core::ResourceVector,
    ) -> Result<&super::Q04OriginalInputDemandV1, CreateQ04ErrorV1> {
        let owner = self.resource_preparation()?;
        owner.require_original_input_subdivision(self.profile, inclusive)
            .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))?;
        owner.original_input_demand(self.profile)
            .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))
    }

    pub(crate) fn original_intake_association(&self) -> Result<([u8; 16], u64), CreateQ04ErrorV1> {
        self.resource_preparation()?.original_intake_association(self.profile)
            .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))
    }

    pub(crate) fn recheck_resource_bank(&self, journal: &Journal) -> Result<(), CreateQ04ErrorV1> {
        let bank = self.resource_bank.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        crate::controller_resource_reservation::require_controller_interval(bank, journal, self.profile)
            .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))
    }

    pub(crate) fn take_resource_preparation(
        &mut self,
    ) -> Result<crate::controller_resource_reservation::ProjectPreparationReservationAttemptV1, CreateQ04ErrorV1> {
        if !self.cleared { return Err(CreateQ04ErrorV1::ChangedCut); }
        self.resource_preparation.take().ok_or(CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn resource_terminal_observation<'invocation, 'cut>(
        &'invocation self,
        identity: &'cut super::Q04CutIdentityV1,
    ) -> Result<OriginalQ04FinalRootObservationV1<'invocation, 'profile, 'cut>, CreateQ04ErrorV1> {
        if !self.cleared { return Err(CreateQ04ErrorV1::ChangedCut); }
        let original = OriginalQ04FinalRootObservationV1 { invocation: self, identity };
        original.recheck()?;
        Ok(original)
    }

    fn connect_original_gen1(
        &mut self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        project: ProjectId,
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.first.is_some() || self.flight.is_some() || self.prepare.is_some() || self.complete.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        let controller = hold_existing_completed_source_genesis_v2(journal, project)?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(&inventory, controller.uid(), project)?;
        controller.recheck_completed_source_ack(&acknowledged)?;

        OriginalRootGenesisFlightV1::connect_q04_parked(
            self.profile, &mut self.raw, &mut self.adopted, &mut self.flight,
            &mut self.hello, &mut self.received,
        )?;
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_nonce()?;
        flight.capture_q04_prepare_readback(
            &controller, &acknowledged, signer_generation, signer,
            &mut self.refresh_sign_result, &mut self.first, &mut self.postcheck_debt,
        ).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;
        match self.refresh_sign_result.take() {
            Some(Ok(packet)) => self.prepare = Some(packet),
            returned => {
                self.refresh_sign_result = returned;
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        let prepare = self.prepare.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent = encode_root_source_genesis_frame_v2(RootSourceGenesisFrameKindV1::Prepare, nonce, prepare.as_ref())?;
        flight.q04_send_original(&self.sent)?;
        flight.receive_q04_exact(
            ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
                + RootSourceGenesisFrameKindV1::Anchored.payload_bytes_for_resource(controller.acceptance().resource_envelope().is_some()),
            &mut self.floor_frame, &mut self.received,
        )?;
        // Prepared is never accepted by this existing-only route. The same
        // sole original-floor constructor checks the actual acceptance/receipt.
        let floor = flight.q04_floor_from_frame(&controller, &self.floor_frame)?;
        // Payment precedes Complete signing, so that authentic packet contains
        // the new native sequence. No signed bytes are patched after a CAS.
        let controller = if let Some(reservation) = self.resource_preparation.as_mut() {
            let operation = self.preparation_operation.ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let bank = self.resource_bank.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let original = flight.q04_original_clock()?;
            let loan = OriginalQ04ProjectPreparationLoanV1 {
                controller: &controller, source: &acknowledged, inventory: &inventory,
                root: &floor, original, nonce,
            };
            reservation.prepare(&loan, operation).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;
            drop(loan);
            drop(controller);
            reservation.append(journal, bank, self.profile);

            // Reacquisition failure cannot suppress the available Source,
            // original Root or final raw-clock observations after native Err.
            let controller = match hold_existing_completed_source_genesis_v2(journal, project) {
                Ok(controller) => controller,
                Err(error) => {
                    let _ = reservation.post_unavailable_controller(
                        error, acknowledged.require_retained_inventory_v1(&inventory),
                        floor.recheck(), self.profile,
                    );
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            };
            let loan = OriginalQ04ProjectPreparationLoanV1 {
                controller: &controller, source: &acknowledged, inventory: &inventory,
                root: &floor, original, nonce,
            };
            reservation.post(&loan, self.profile).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;
            controller
        } else {
            controller
        };
        flight.capture_q04_complete_readback(
            &controller, &acknowledged, signer_generation, signer,
            &mut self.refresh_sign_result, &mut self.first, &mut self.postcheck_debt,
        ).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;
        match self.refresh_sign_result.take() {
            Some(Ok(packet)) => self.complete = Some(packet),
            returned => {
                self.refresh_sign_result = returned;
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        let complete = self.complete.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent = encode_root_source_genesis_frame_v2(RootSourceGenesisFrameKindV1::Complete, nonce, complete.as_ref())?;
        flight.q04_send_original(&self.sent)?;
        flight.receive_q04_exact(
            ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + RootSourceGenesisFrameKindV1::Completed.payload_bytes(),
            &mut self.completed_frame, &mut self.received,
        )?;
        let completed = flight.q04_completed_from_frame(&floor, &self.completed_frame)?;
        super::super::public_create_source::consume_completed_gen1_ancestry_v1(
            &controller, &acknowledged, &inventory, &completed,
        )?;
        if let Some(reservation) = self.resource_preparation.as_mut() {
            let loan = OriginalQ04CompletedPreparationLoanV1 {
                original: OriginalQ04ProjectPreparationLoanV1 {
                    controller: &controller, source: &acknowledged, inventory: &inventory,
                    root: &floor, original: flight.q04_original_clock()?, nonce,
                },
                completed: &completed,
            };
            reservation.confirm_completed(&loan).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;
            reservation.admit_original_input_once(&loan, self.profile)
                .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))?;
        }

        // Only Root can perform the selected root-UID Source signer request.
        // This exact original returned packet is retained as Claim field11;
        // it is not a Controller-produced signature or a stand-alone floor.
        flight.receive_q04_exact(
            ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
                + if complete.as_ref().len() == super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2 {
                    super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2
                } else {
                    super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1
                },
            &mut self.source_frame, &mut self.received,
        )?;
        decode_root_create_q04_transfer_v1(&self.source_frame, RootCreateQ04TransferKindV1::SourceObservation, nonce)?;
        completed.recheck()?;
        controller.recheck()?;
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        flight.q04_original_clock()?;
        Ok(())
    }

    // Only a permitted same-owner selfwrite calls this closed continuation.
    // Complete864/1040 uses the genuine Controller/gen1 engine; only Root
    // obtains the corresponding full Source928/1104 observation. Original
    // packets and partials stay resident, and no sequence is edited in DATA.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn refresh_after_selfwrite(
        &mut self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        project: ProjectId,
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), ()> {
        let result = self.refresh_original_after_selfwrite(
            journal, source, ledger, transitions, project, signer_generation, signer,
        );
        self.retain_result(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_original_after_selfwrite(
        &mut self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        project: ProjectId,
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), CreateQ04ErrorV1> {
        const MAXIMUM_SELFWRITE_OBSERVATIONS: usize = 11;
        if self.first.is_some() || self.postcheck_debt.is_some()
            || self.complete.is_none() || self.preview.is_empty()
            || self.refresh_sign_result.is_some()
            || self.refresh_complete.len() >= MAXIMUM_SELFWRITE_OBSERVATIONS
            || self.refresh_source_frames.len() != self.refresh_complete.len()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let before = journal.q04_controller_refresh_bookend_v1(ledger, transitions)?;
        let final_source_observation = self.phase == Q04ClientPhaseV1::FinalClearance;
        if final_source_observation {
            let identity = transitions.first().ok_or(CreateQ04ErrorV1::ChangedCut)?.identity();
            self.require_final_original_readbacks(journal, source, ledger, transitions, identity)?;
            if self.refresh_complete.len() != 10 {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        source.journal().require_q04_native_recipes_v1(&[])?;
        let source_before = (source.journal().snapshot_sequence(), source.fixed_physical_names_v1()?);
        self.refresh_complete.try_reserve_exact(1)?;
        self.refresh_source_frames.try_reserve_exact(1)?;
        // The future receive buffer is owned before signing or transport. Its
        // partial contents survive any later original check/error/unwind.
        self.refresh_source_frames.push(Vec::new());

        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_nonce()?;
        let controller = hold_existing_completed_source_genesis_v2(journal, project)?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(&inventory, controller.uid(), project)?;
        controller.recheck_completed_source_ack(&acknowledged)?;
        let signed = flight.capture_q04_complete_readback(
            &controller, &acknowledged, signer_generation, signer,
            &mut self.refresh_sign_result, &mut self.first, &mut self.postcheck_debt,
        );
        // These short loans end before mutably auditing the same Controller
        // and Source writers. The original external owners never move/drop.
        drop(acknowledged);
        drop(inventory);
        drop(controller);
        let checked = (|| {
            if journal.q04_controller_refresh_bookend_v1(ledger, transitions)? != before {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
            source.journal().require_q04_native_recipes_v1(&[])?;
            if (source.journal().snapshot_sequence(), source.fixed_physical_names_v1()?) != source_before {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            flight.q04_original_clock()?;
            Ok(())
        })();
        if super::finish_controller_q04_signing_v1(
            checked, &mut self.first, &mut self.postcheck_debt,
        ).is_err() || signed.is_err() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // Capacity was reserved before invocation. Moving the successful
        // packet into its original history requires no allocation or callback.
        match self.refresh_sign_result.take() {
            Some(Ok(packet)) => self.refresh_complete.push(packet),
            returned => {
                self.refresh_sign_result = returned;
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        let complete = self.refresh_complete.last().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent.clear();
        super::super::source_genesis_root::encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::SourceRefresh, nonce, complete.as_ref(),
        )?;
        flight.q04_send_original(&self.sent)?;
        let response = self.refresh_source_frames.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if final_source_observation {
            flight.receive_q04_final_source_observation(
                complete.as_ref().len() == super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2,
                response, &mut self.received,
            )?;
        } else {
            flight.receive_q04_exact(
                ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
                + if complete.as_ref().len() == super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2 {
                    super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2
                } else {
                    super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1
                },
                response, &mut self.received,
            )?;
        }
        decode_root_create_q04_transfer_v1(response, RootCreateQ04TransferKindV1::SourceObservation, nonce)?;
        if journal.q04_controller_refresh_bookend_v1(ledger, transitions)? != before {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        source.journal().require_q04_native_recipes_v1(&[])?;
        if (source.journal().snapshot_sequence(), source.fixed_physical_names_v1()?) != source_before {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if final_source_observation {
            flight.q04_terminal_clock()?;
        } else {
            flight.q04_original_clock()?;
        }
        Ok(())
    }

    pub(crate) fn receive_preview(&mut self) -> Result<(), ()> {
        let result = self.receive_original_preview();
        self.retain_result(result)
    }

    fn receive_original_preview(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.first.is_some() || self.complete.is_none() || !self.preview.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_nonce()?;
        flight.receive_q04_exact(
            ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + PREVIEW_INDEX_BYTES,
            &mut self.preview_index_frame, &mut self.received,
        )?;
        let original_index = decode_root_create_q04_transfer_v1(
            &self.preview_index_frame, RootCreateQ04TransferKindV1::PreviewIndex, nonce,
        )?;
        let (total, count) = preview_index_shape(original_index)?;
        for index in 0..count {
            let offset = usize::from(index).checked_mul(CLAIM_CHUNK_BYTES)
                .ok_or(CreateQ04ErrorV1::Bounds)?;
            let remaining = total.checked_sub(offset).ok_or(CreateQ04ErrorV1::Bounds)?;
            let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
                + CLAIM_CHUNK_PREFIX_BYTES + remaining.min(CLAIM_CHUNK_BYTES);
            flight.receive_q04_exact(length, &mut self.preview_chunk_frame, &mut self.received)?;
            let payload = decode_root_create_q04_transfer_v1(
                &self.preview_chunk_frame, RootCreateQ04TransferKindV1::PreviewChunk, nonce,
            )?;
            Q04PreviewChunkV1::decode(payload, original_index)?.append_to(&mut self.preview)?;
            flight.q04_original_clock()?;
            self.preview_chunk_frame.clear();
        }
        let preview = Q04PreviewV1::decode(&self.preview, nonce)?;
        Q04PreviewTransferRecipeV1::verify_index(original_index, &preview)?;
        flight.q04_original_clock()?;
        Ok(())
    }

    pub(crate) fn preview(&self) -> Result<Q04PreviewV1<'_>, CreateQ04ErrorV1> {
        if self.first.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        Q04PreviewV1::decode(&self.preview, flight.q04_nonce()?)
    }

    // This is the pre-C1 compiler action, not a new Stage or a held-current
    // constructor. The real caller owns and parks its Result before asking
    // for another original-source/credential/Cache/clock bookend.
    pub(crate) fn form_controller_preparation(
        &self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        cache: &mut crate::cache_residency::OriginalQ04CacheOwnerCutV1<'_>,
        credentials: &crate::public_api_session::ControllerQ04CredentialCustodyV1,
    ) -> Result<Q04ControllerPreparationV1, CreateQ04ErrorV1> {
        self.resource_preparation()?.original_input_demand(self.profile)
            .map_err(|error| CreateQ04ErrorV1::ResourceReservation(Box::new(error)))?;
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let original = flight.q04_original_clock()?;
        let preview = self.preview()?;
        let staged = preview.staged()?;
        let current = ledger.signing_current_source(journal)?;
        let mut metadata = [0; PREHOLD_METADATA_BYTES];
        let (signer_generation, _) = credentials.signer().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        metadata[..16].copy_from_slice(&original.host_boot_id());
        metadata[16..24].copy_from_slice(&original.boottime_nanoseconds().to_be_bytes());
        metadata[24..32].copy_from_slice(&original.boottime_nanoseconds()
            .checked_add(60_000_000_000).ok_or(CreateQ04ErrorV1::Bounds)?.to_be_bytes());
        metadata[32..40].copy_from_slice(&signer_generation.to_be_bytes());
        metadata[40..48].copy_from_slice(&1_u64.to_be_bytes());
        metadata[48..80].copy_from_slice(current.commitment().as_bytes());
        ledger.write_original_metadata(journal, &mut metadata)?;
        source.require_fixed_named_writer_v1()?;
        metadata[224..272].copy_from_slice(&source.fixed_physical_names_v1()?.to_bytes());
        metadata[472..480].copy_from_slice(&source.journal().snapshot_sequence().to_be_bytes());
        cache.write_prepare_metadata(&mut metadata).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;

        // End each real Controller/Source/gen1 loan before borrowing the
        // mutable Controller compiler engine. No scalar edits substitute for
        // the separate fresh rejoin performed after this Result is parked.
        let (heads, floor, controller_uid, source_uid) = {
            let controller = hold_existing_completed_source_genesis_v2(journal, current.project())?;
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let acknowledged = observe_retained_source_genesis_v1(&inventory, controller.uid(), current.project())?;
            let anchored = flight.q04_floor_from_frame(&controller, &self.floor_frame)?;
            let completed = flight.q04_completed_from_frame(&anchored, &self.completed_frame)?;
            let heads = super::super::CurrentCreatePolicyBarrierHeadsV2::from_original_q04_prepare(
                &controller, &acknowledged, &inventory, &completed, cache.prepare_readback()?,
            )?;
            (heads, completed.floor().digest(), controller.uid(), acknowledged.source_uid())
        };
        let selected = cache.prepare_readback()?.selected();
        if selected.partition().disclosure() != current.cache_domain() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        metadata[80..112].copy_from_slice(heads.ancestry().as_bytes());
        metadata[112..144].copy_from_slice(heads.physical_cache().as_bytes());
        metadata[144..176].copy_from_slice(cache.prepare_readback()?.quota_digest().as_bytes());

        let ((deployment_generation, deployment_pin), (project_generation, project_pin)) =
            credentials.policy_pins().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if deployment_generation != staged.base().deployment_signer_generation()
            || project_generation != staged.base().project_signer_generation()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let fields = preview.fields();
        let inputs = super::super::PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let now = flight.q04_current_clock()?.wall_seconds();
        let deployment_head = super::super::verify_policy_deployment_head_v1(
            fields[2], &inputs, deployment_pin, now,
        )?;
        let deployment = super::super::decode_policy_deployment_sources_v1(&inputs, deployment_head)?;
        let project = super::super::verify_signed_project_policy_source_v2(
            fields[7], fields[8], project_pin, now,
        )?;
        if project.head().deployment_signer_generation() != staged.base().deployment_signer_generation()
            || project.head().project_signer_generation() != staged.base().project_signer_generation()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let input = super::super::current_parentless_create_compiler_input_v1(
            journal, current.operation(), current.sandbox(), deployment_head, &deployment, &project,
        )?;
        let prerequisites = super::super::PolicyPublicationPrerequisitesV1::new(
            heads.ancestry(), deployment_head.packet_digest(), current.cache_domain_head(),
            current.revocation_head(), staged.base().next_generation(),
        )?;
        let checked_draft = super::super::checked_parentless_create_verified_policy_draft_v2(
            &current, &project, &deployment, &input, &prerequisites, now,
        )?;
        let normalized = super::super::normalized_policy_input_digest_v1(&input)?;
        let candidate = aos_sandbox_policy::PolicyCompilerV1::compile_retained(&input)?;
        let inclusive = super::input_origin::candidate_capacity(&candidate)?;
        self.original_input_demand(inclusive)?;
        // Subdivision is checked under the actual once-admitted Project owner
        // before the full input serializer creates its independently owned copy.
        let input_origin = super::Q04PreparedInputOriginV1::retain(&input, &candidate)?;
        let proposed = super::super::binding_v2::encode_closed_proposal_fields(
            &current.q04_proposal_fields(&heads), project.head().packet_digest(),
            project.head().input_digest(), deployment_head, normalized,
            candidate.commitment().digest(), staged.base(), checked_draft,
        )?;
        if super::super::binding_v2::ClosedPolicyRootBindingV2::q04_decode(&proposed)?
            .q04_compilation_commitments() != (normalized, candidate.commitment().digest())
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let publication_recipe = super::super::protected_journal::q04_independent_publication_data_v1(
            &input, &candidate, &prerequisites,
        )?;
        Ok(Q04ControllerPreparationV1 {
            source: current, staged, proposed, metadata, controller_uid, source_uid,
            floor, ancestry: heads.ancestry(), candidate, input_origin, publication_recipe,
        })
    }

    pub(crate) fn recheck_controller_preparation(
        &self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        cache: &mut crate::cache_residency::OriginalQ04CacheOwnerCutV1<'_>,
        prepared: &Q04ControllerPreparationV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        flight.q04_original_clock()?;
        let mut original_metadata = [0; PREHOLD_METADATA_BYTES];
        ledger.write_original_metadata(journal, &mut original_metadata)?;
        cache.write_prepare_metadata(&mut original_metadata).map_err(|()| CreateQ04ErrorV1::ChangedCut)?;
        if self.preview()?.staged()? != prepared.staged
            || ledger.signing_current_source(journal)?.commitment() != prepared.source.commitment()
            || original_metadata[176..224] != prepared.metadata[176..224]
            || original_metadata[272..472] != prepared.metadata[272..472]
            || original_metadata[480..512] != prepared.metadata[480..512]
            || source.fixed_physical_names_v1()?.to_bytes() != prepared.metadata[224..272]
            || source.journal().snapshot_sequence().to_be_bytes() != prepared.metadata[472..480]
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let controller = hold_existing_completed_source_genesis_v2(journal, prepared.source.project())?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(&inventory, controller.uid(), prepared.source.project())?;
        let anchored = flight.q04_floor_from_frame(&controller, &self.floor_frame)?;
        let completed = flight.q04_completed_from_frame(&anchored, &self.completed_frame)?;
        let heads = super::super::CurrentCreatePolicyBarrierHeadsV2::from_original_q04_prepare(
            &controller, &acknowledged, &inventory, &completed, cache.prepare_readback()?,
        )?;
        if completed.floor().digest() != prepared.floor
            || heads.ancestry() != prepared.ancestry
            || heads.physical_cache().as_bytes() != &prepared.metadata[112..144]
            || cache.prepare_readback()?.quota_digest().as_bytes() != &prepared.metadata[144..176]
            || controller.uid() != prepared.controller_uid || acknowledged.source_uid() != prepared.source_uid
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        completed.recheck()?;
        flight.q04_original_clock()?;
        Ok(())
    }

    pub(crate) fn sign_prehold_current(
        &mut self,
        journal: &mut Journal,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        staged: StagedClosedPolicyRootBaseV2,
        proposed: &[u8],
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), ()> {
        let challenge = match self.signing_challenge(staged, proposed)
            .and_then(|challenge| {
                ControllerProjectAdmissionChallengeV1::new(challenge.nonce(), challenge.cut())
                    .map_err(CreateQ04ErrorV1::from)
            })
        {
            Ok(challenge) => challenge,
            Err(error) => return self.retain_result(Err(error)),
        };
        let Some(flight) = self.flight.as_ref() else {
            return self.retain_result(Err(CreateQ04ErrorV1::ChangedCut));
        };
        let signed = super::super::sign_q04_current_controller_project_v1(
            journal, ledger, challenge, signer_generation, signer, flight,
            &mut self.controller_current, &mut self.first, &mut self.postcheck_debt,
        );
        self.signing_postflight(signed)
    }

    pub(crate) fn sign_prehold_data(
        &mut self,
        journal: &mut Journal,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        metadata: &[u8; PREHOLD_METADATA_BYTES],
        proposed: &[u8],
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), ()> {
        let checked = (|| {
            self.signing_challenge(self.preview()?.staged()?, proposed)?;
            let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let original = flight.q04_original_clock()?;
            let deadline = original.boottime_nanoseconds().checked_add(60_000_000_000)
                .ok_or(CreateQ04ErrorV1::Bounds)?;
            if metadata[..16] != original.host_boot_id()
                || metadata[16..24] != original.boottime_nanoseconds().to_be_bytes()
                || metadata[24..32] != deadline.to_be_bytes()
                || self.controller_current.is_none()
                || !self.prehold.is_empty()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            Ok(())
        })();
        if self.retain_result(checked).is_err() {
            return Err(());
        }
        let Some(current) = self.controller_current.as_ref() else {
            return self.retain_result(Err(CreateQ04ErrorV1::ChangedCut));
        };
        let Some(flight) = self.flight.as_ref() else {
            return self.retain_result(Err(CreateQ04ErrorV1::ChangedCut));
        };
        let signed = super::super::sign_q04_prehold_input_v1(
            journal, ledger, metadata, proposed, current, signer_generation, signer, flight,
            &mut self.prehold, &mut self.first, &mut self.postcheck_debt,
        );
        self.signing_postflight(signed)
    }

    // A response is only original-stream DATA. The actual caller independently
    // compares its full captures and preflights its C/Source/Cache journals;
    // this transport helper neither adopts Root's capacity nor creates C1.
    pub(crate) fn exchange_prehold_data(&mut self) -> Result<(), ()> {
        let result = self.exchange_original_prehold_data();
        self.retain_result(result)
    }

    fn exchange_original_prehold_data(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.first.is_some() || self.postcheck_debt.is_some()
            || !self.prehold_chunk.is_empty() || !self.prehold_response.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let request = Q04PreholdInputDataV1::decode(&self.prehold)?;
        let transfer = Q04PreholdTransferRecipeV1::new(&request)?;
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_nonce()?;
        self.sent.clear();
        super::super::source_genesis_root::encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::PreholdIndex, nonce, transfer.index_bytes(),
        )?;
        flight.q04_send_original(&self.sent)?;
        for index in 0..transfer.chunk_count() {
            transfer.encode_chunk(index, &mut self.prehold_chunk)?;
            self.sent.clear();
            super::super::source_genesis_root::encode_root_create_q04_transfer_v1(
                &mut self.sent, RootCreateQ04TransferKindV1::PreholdChunk, nonce, &self.prehold_chunk,
            )?;
            flight.q04_send_original(&self.sent)?;
            self.prehold_chunk.clear();
        }
        flight.receive_q04_exact(
            ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + PREHOLD_RESPONSE_BYTES,
            &mut self.prehold_response, &mut self.received,
        )?;
        let payload = decode_root_create_q04_transfer_v1(
            &self.prehold_response, RootCreateQ04TransferKindV1::PreholdRecipe, nonce,
        )?;
        let response = Q04PreholdPublicationDataV1::decode(payload, nonce)?;
        if response.request_digest() != request.digest() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        flight.q04_original_clock()?;
        Ok(())
    }

    pub(crate) fn prehold_data(&self) -> Result<Q04PreholdPublicationDataV1, CreateQ04ErrorV1> {
        if self.first.is_some() || self.postcheck_debt.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_nonce()?;
        let payload = decode_root_create_q04_transfer_v1(
            &self.prehold_response, RootCreateQ04TransferKindV1::PreholdRecipe, nonce,
        )?;
        Q04PreholdPublicationDataV1::decode(payload, nonce)
    }

    pub(crate) fn form_finalized_identity(
        &self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        prepared: &Q04ControllerPreparationV1,
    ) -> Result<super::Q04CutIdentityV1, CreateQ04ErrorV1> {
        use aos_sandbox_core::ObjectDigest;

        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        flight.q04_original_clock()?;
        let nonce = flight.q04_nonce()?;
        let preview = self.preview()?;
        let request = Q04PreholdInputDataV1::decode(&self.prehold)?;
        let response = self.prehold_data()?;
        let reply = response.bytes();
        let root_metadata = preview.fields()[0];
        let complete = self.complete.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let source = decode_root_create_q04_transfer_v1(
            &self.source_frame, RootCreateQ04TransferKindV1::SourceObservation, nonce,
        )?;
        let precut = super::q04_original_precut_digest_v1(
            &request, &preview, complete.as_ref(), source,
            crate::journal::ProtectedJournalNamesV1::from_bytes(&reply[400..448]).map_err(crate::journal::JournalError::from)?,
            u64::from_be_bytes(super::fixed(reply, 392)),
        )?;
        let policy_before = prepared.publication_recipe.before_digest();
        let root_before = ObjectDigest::from_bytes(super::fixed(root_metadata, 88));
        let seed = super::q04_publication_precut_seed_v1(
            precut, root_before, ledger.before_rows(), prepared.floor, prepared.ancestry, policy_before,
        )?;
        let publication = prepared.publication_recipe.initial_transaction_id(seed, nonce)?;
        let expected_claim_length = request.fields()[1..4].iter()
            .chain(preview.fields()[3..7].iter())
            .chain(std::iter::once(&preview.fields()[8]))
            .try_fold(2504_usize + source.len(), |sum, field| sum.checked_add(field.len()).ok_or(CreateQ04ErrorV1::Bounds))?;
        if request.fields()[0] != prepared.metadata.as_slice()
            || request.fields()[4] != prepared.proposed.as_slice()
            || preview.staged()? != prepared.staged
            || reply[64..96] != *precut.as_bytes()
            || reply[96..128] != *policy_before.as_bytes()
            || reply[144..160] != publication
            || reply[224..256] != *prepared.publication_recipe.recipe_digest().as_bytes()
            || reply[256..288] != *root_before.as_bytes()
            || reply[288..320] != *ledger.before_rows().as_bytes()
            || reply[320..352] != *prepared.floor.as_bytes()
            || reply[352..384] != *prepared.ancestry.as_bytes()
            || reply[384..392] != root_metadata[32..40]
            || usize::try_from(u32::from_be_bytes(super::fixed(reply, 448)))
                .map_err(|_| CreateQ04ErrorV1::Bounds)? != expected_claim_length
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let (normalized, candidate) = super::super::binding_v2::ClosedPolicyRootBindingV2::q04_decode(
            &prepared.proposed,
        )?.q04_compilation_commitments();
        let identity = super::encode_q04_cut_recipe_v1(super::Q04CutRecipeV1 {
            nonce,
            project: prepared.source.project(),
            operation: prepared.source.operation(),
            sandbox: prepared.source.sandbox(),
            controller_uid: prepared.controller_uid,
            source_uid: prepared.source_uid,
            controller_metadata: &prepared.metadata,
            root_boot: super::fixed(root_metadata, 0),
            root_started: u64::from_be_bytes(super::fixed(root_metadata, 16)),
            handoff_epoch: prepared.staged.base().next_generation(),
            stage: super::fixed(reply, 128),
            publication,
            digests: [
                prepared.source.operation_revision(), prepared.source.projection_revision(),
                ledger.effect_plan_digest()?, ledger.before_rows(), prepared.floor, prepared.ancestry,
                precut, super::super::closed_policy_binding_digest_v2(&prepared.proposed)?, normalized,
                candidate, ObjectDigest::from_bytes(super::fixed(reply, 160)),
                ObjectDigest::from_bytes(super::fixed(reply, 192)),
                ObjectDigest::from_bytes(super::fixed(&prepared.metadata, 144)), root_before,
            ],
        })?;
        ledger.require_identity(&identity)?;
        self.require_cache_terminal_original(&identity)?;
        Ok(identity)
    }

    pub(crate) fn cache_terminal_loan<'invocation, 'cut>(
        &'invocation self,
        identity: &'cut super::Q04CutIdentityV1,
    ) -> Result<OriginalQ04RootCacheLoanV1<'invocation, 'profile, 'cut>, CreateQ04ErrorV1> {
        self.require_cache_terminal_original(identity)?;
        Ok(OriginalQ04RootCacheLoanV1 { invocation: self, identity })
    }

    fn require_cache_terminal_original(
        &self,
        identity: &super::Q04CutIdentityV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let original = flight.q04_original_clock()?;
        let response = self.prehold_data()?;
        let preview = self.preview()?;
        require_original_identity_data(identity, original, flight.q04_nonce()?, &preview, &response)?;
        // The peer/profile/name work above may be slow. This final paired
        // sample still uses the original 60-second flight, without renewal.
        flight.q04_original_clock()?;
        Ok(())
    }

    pub(crate) fn sign_actual_held_controller(
        &mut self,
        journal: &mut Journal,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        staged: StagedClosedPolicyRootBaseV2,
        proposed: &[u8],
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<(), ()> {
        let checked = (|| {
            let first = transitions.first().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            first.require_signing_binding(proposed)?;
            let challenge = self.signing_challenge(staged, proposed)?;
            Ok(ControllerHoldReadbackChallengeV1::new(challenge.nonce(), challenge.cut())?)
        })();
        let challenge = match checked {
            Ok(challenge) => challenge,
            Err(error) => return self.retain_result(Err(error)),
        };
        let Some(flight) = self.flight.as_ref() else {
            return self.retain_result(Err(CreateQ04ErrorV1::ChangedCut));
        };
        let signed = super::super::sign_q04_held_controller_v1(
            journal, transitions, challenge, signer_generation, signer, flight,
            &mut self.controller_hold, &mut self.first, &mut self.postcheck_debt,
        );
        self.signing_postflight(signed)
    }

    fn signing_challenge(
        &self,
        staged: StagedClosedPolicyRootBaseV2,
        proposed: &[u8],
    ) -> Result<StagedClosedPolicySignerChallengeV2, CreateQ04ErrorV1> {
        if self.first.is_some() || self.preview()?.staged()? != staged {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if flight.q04_nonce()? != staged.challenge() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(staged_closed_policy_signer_challenge_v2(staged, proposed)?)
    }

    // A failed signer cannot suppress a later original-clock debt, and that
    // debt cannot replace its original typed first cause or parked packet.
    fn signing_postflight(&mut self, signed: Result<(), ()>) -> Result<(), ()> {
        let result = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)
            .and_then(|flight| flight.q04_original_clock().map(|_| ()).map_err(Into::into));
        let postflight = super::finish_controller_q04_signing_v1(
            result, &mut self.first, &mut self.postcheck_debt,
        );
        signed.and(postflight)
    }

    pub(crate) fn claim_owner_packets(
        &self,
    ) -> Result<(&[u8], &[u8], &[u8]), CreateQ04ErrorV1> {
        if self.first.is_some() || self.postcheck_debt.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let frame = self.refresh_source_frames.last().unwrap_or(&self.source_frame);
        let source = decode_root_create_q04_transfer_v1(
            frame, RootCreateQ04TransferKindV1::SourceObservation, flight.q04_nonce()?,
        )?;
        let current = self.controller_current.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let held = self.controller_hold.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        Ok((current.as_slice(), held.as_slice(), source))
    }

    // The actual caller retains Controller/Source/Cache originals around this
    // action. The fields below are borrowed from those real captures and this
    // invocation's original returned packets, not a synthesized owner graph.
    pub(crate) fn send_held_claim(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &super::Q04CutIdentityV1,
        proposed: &[u8],
        cache_packet: &[u8],
        signer: &SigningKey,
    ) -> Result<(), ()> {
        let result = self.send_original_held_claim(ledger, identity, proposed, cache_packet, signer);
        self.retain_result(result)
    }

    fn send_original_held_claim(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &super::Q04CutIdentityV1,
        proposed: &[u8],
        cache_packet: &[u8],
        signer: &SigningKey,
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != Q04ClientPhaseV1::Prehold || !self.claim.is_empty() || !self.claim_chunk.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        ledger.require_identity(identity)?;
        self.require_cache_terminal_original(identity)?;
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_nonce()?;
        let preview = Q04PreviewV1::decode(&self.preview, nonce)?;
        let inputs = preview.fields();
        let rows = ledger.original_rows();
        let source_frame = self.refresh_source_frames.last().unwrap_or(&self.source_frame);
        let source = decode_root_create_q04_transfer_v1(source_frame, RootCreateQ04TransferKindV1::SourceObservation, nonce)?;
        let controller = self.controller_current.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let held = self.controller_hold.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        super::encode_q04_claim_body_v1(&mut self.claim, [
            rows[0], rows[1], rows[2], inputs[3], inputs[4], inputs[5], inputs[6], inputs[8], proposed,
            controller.as_slice(), held.as_slice(), source, cache_packet, identity.bytes(),
        ], identity)?;
        super::sign_original_q04_claim_v1(&mut self.claim, signer, identity, flight)?;
        flight.q04_original_clock()?;
        let claim = super::Q04ClaimV1::decode(&self.claim, identity)?;
        let storage = super::Q04ClaimStorageRecipeV1::new(&claim, identity)?;
        self.sent.clear();
        super::super::source_genesis_root::encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::ClaimIndex, nonce, storage.index_bytes(),
        )?;
        flight.q04_send_original(&self.sent)?;
        for index in 0..storage.chunk_count() {
            storage.encode_chunk(index, &mut self.claim_chunk)?;
            self.sent.clear();
            super::super::source_genesis_root::encode_root_create_q04_transfer_v1(
                &mut self.sent, RootCreateQ04TransferKindV1::ClaimChunk, nonce, &self.claim_chunk,
            )?;
            flight.q04_send_original(&self.sent)?;
            self.claim_chunk.clear();
        }
        flight.q04_original_clock()?;
        self.phase = Q04ClientPhaseV1::Claimed;
        Ok(())
    }

    pub(crate) fn receive_decision(&mut self, identity: &super::Q04CutIdentityV1) -> Result<(), ()> {
        let result = self.receive_original_decision(identity);
        self.retain_result(result)
    }

    fn receive_original_decision(&mut self, identity: &super::Q04CutIdentityV1) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != Q04ClientPhaseV1::Claimed || !self.decision_frame.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_cache_terminal_original(identity)?;
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        flight.receive_q04_exact(32 + super::DECISION_BYTES, &mut self.decision_frame, &mut self.received)?;
        let bytes = decode_root_create_q04_transfer_v1(&self.decision_frame,
            RootCreateQ04TransferKindV1::Decision, flight.q04_nonce()?)?;
        let decision = super::Q04RootDecisionV1::decode(bytes, identity)?;
        let response = self.prehold_data()?;
        if decision.state_sequence() != u64::from_be_bytes(super::fixed(response.bytes(), 392))
            .checked_add(5).ok_or(CreateQ04ErrorV1::Bounds)?
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_cache_terminal_original(identity)?;
        self.phase = Q04ClientPhaseV1::Decided;
        Ok(())
    }

    pub(crate) fn decision(&self, identity: &super::Q04CutIdentityV1) -> Result<super::Q04RootDecisionV1, CreateQ04ErrorV1> {
        self.require_cache_terminal_original(identity)?;
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let bytes = decode_root_create_q04_transfer_v1(&self.decision_frame,
            RootCreateQ04TransferKindV1::Decision, flight.q04_nonce()?)?;
        super::Q04RootDecisionV1::decode(bytes, identity).map_err(Into::into)
    }

    pub(crate) fn consumed_gate(
        &self,
        identity: &super::Q04CutIdentityV1,
    ) -> Result<super::Q04EffectSubgateV1, CreateQ04ErrorV1> {
        super::root::root_consumed_gate_record(identity, &self.decision(identity)?)
    }

    pub(crate) fn observed_root_phase(
        &self,
        identity: &super::Q04CutIdentityV1,
        index: usize,
    ) -> Result<super::Q04PhaseRecordV1, CreateQ04ErrorV1> {
        self.require_cache_terminal_original(identity)?;
        let observed = self.root_phase(identity, index)?;
        self.require_cache_terminal_original(identity)?;
        Ok(observed)
    }

    // The full signed packet stays owned by the actual ledger/source/Cache
    // caller after its native transition and gen1 refresh. This transport copy
    // is bounded DATA, parked before growth or I/O, never an ACK capability.
    pub(crate) fn exchange_acknowledgement(
        &mut self,
        identity: &super::Q04CutIdentityV1,
        kind: super::Q04AcknowledgementKindV1,
        packet: &[u8],
    ) -> Result<(), ()> {
        let result = self.exchange_original_acknowledgement(identity, kind, packet);
        self.retain_result(result)
    }

    fn exchange_original_acknowledgement(
        &mut self,
        identity: &super::Q04CutIdentityV1,
        kind: super::Q04AcknowledgementKindV1,
        packet: &[u8],
    ) -> Result<(), CreateQ04ErrorV1> {
        let (index, before, after, request, response) = match kind {
            super::Q04AcknowledgementKindV1::Policy => (0, Q04ClientPhaseV1::Decided,
                Q04ClientPhaseV1::PolicyAccepted, RootCreateQ04TransferKindV1::PolicyAcknowledgement, RootCreateQ04TransferKindV1::PolicyAccepted),
            super::Q04AcknowledgementKindV1::Release => (1, Q04ClientPhaseV1::PolicyAccepted,
                Q04ClientPhaseV1::ReleaseAuthorized, RootCreateQ04TransferKindV1::ReleaseAcknowledgement, RootCreateQ04TransferKindV1::ReleaseAuthorized),
            super::Q04AcknowledgementKindV1::Settlement => (2, Q04ClientPhaseV1::ReleaseAuthorized,
                Q04ClientPhaseV1::Settled, RootCreateQ04TransferKindV1::SettlementAcknowledgement, RootCreateQ04TransferKindV1::Settled),
            super::Q04AcknowledgementKindV1::Clearance => (3, Q04ClientPhaseV1::Settled,
                Q04ClientPhaseV1::FinalClearance, RootCreateQ04TransferKindV1::ClearanceAcknowledgement, RootCreateQ04TransferKindV1::FinalClearance),
        };
        if self.first.is_some() || self.postcheck_debt.is_some() || self.phase != before
            || self.acknowledgements.len() != index || self.root_phase_frames.len() != index
            || packet.len() != kind.body_bytes() + 64
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.acknowledgements.try_reserve_exact(1)?;
        self.acknowledgements.push(Vec::new());
        let stored = self.acknowledgements.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        stored.try_reserve_exact(packet.len())?;
        stored.extend_from_slice(packet);
        self.require_cache_terminal_original(identity)?;
        self.root_phase_frames.try_reserve_exact(1)?;
        self.root_phase_frames.push(Vec::new());
        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent.clear();
        super::super::source_genesis_root::encode_root_create_q04_transfer_v1(
            &mut self.sent, request, flight.q04_nonce()?, &self.acknowledgements[index],
        )?;
        flight.q04_send_original(&self.sent)?;
        flight.receive_q04_exact(32 + super::PHASE_BYTES,
            self.root_phase_frames.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?, &mut self.received)?;
        let bytes = decode_root_create_q04_transfer_v1(
            self.root_phase_frames.get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?, response, identity.nonce(),
        )?;
        let phase = super::Q04PhaseRecordV1::decode(super::Q04PhaseOwnerV1::Root, bytes, identity)?;
        let decision = self.decision(identity)?;
        let gate = super::root::root_consumed_gate_record(identity, &decision)?;
        if phase.phase() != kind.phase() + 3 || phase.bytes()[96..128] != *decision.digest().as_bytes()
            || phase.bytes()[128..160] != *gate.digest().as_bytes()
            || phase.acknowledgement().as_bytes() != sha2::Sha256::digest(&self.acknowledgements[index]).as_slice()
            || phase.native_transaction_id() != super::Q04TransactionOwnerV1::Root.transaction_id(
                identity, phase.phase(), aos_sandbox_core::ObjectDigest::from_bytes(super::fixed(phase.bytes(), 64)),
            )?
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if index > 0 {
            phase.require_successor(&self.root_phase(identity, index - 1)?)?;
        }
        self.require_cache_terminal_original(identity)?;
        self.phase = after;
        Ok(())
    }

    fn require_final_original_readbacks(
        &self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        identity: &super::Q04CutIdentityV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.first.is_some() || self.postcheck_debt.is_some()
            || !matches!(self.phase, Q04ClientPhaseV1::FinalClearance | Q04ClientPhaseV1::FinalObservation)
            || transitions.len() != 8 || self.root_phase_frames.len() != 4
            || transitions.iter().any(|transition| !std::ptr::eq(transition.ledger(), ledger)
                || transition.identity() != identity)
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        ledger.require_identity(identity)?;
        let controller_before = journal.q04_controller_refresh_bookend_v1(ledger, transitions)?;
        let request = Q04PreholdInputDataV1::decode(&self.prehold)?;
        let metadata = request.fields()[0];
        let original_controller = crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[176..224]).map_err(crate::journal::JournalError::from)?;
        let original_source = crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[224..272]).map_err(crate::journal::JournalError::from)?;
        let root_final = self.root_phase(identity, 3)?;
        // Count the same eight native recipes, including each original
        // begin/commit pair. The compound resource hold has six extra members;
        // legacy recipes retain their original total of thirty-one frames.
        let controller_frames = transitions.iter().try_fold(0_u64, |total, transition| {
            let members = u64::try_from(transition.transaction().records().len())
                .map_err(|_| CreateQ04ErrorV1::Bounds)?;
            let frames = members.checked_add(2).ok_or(CreateQ04ErrorV1::Bounds)?;
            total.checked_add(frames).ok_or(CreateQ04ErrorV1::Bounds)
        })?;
        if controller_before.0 != ledger.original_next().checked_add(controller_frames).ok_or(CreateQ04ErrorV1::Bounds)?
            || ledger.original_next() != u64::from_be_bytes(super::fixed(metadata, 464))
            || controller_before.1 != original_controller
            || root_final.phase() != 7
            || transitions[7].phase_record().bytes()[256..288] != *root_final.digest().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        source.journal().require_q04_native_recipes_v1(&[])?;
        let source_next = source.journal().snapshot_sequence();
        let source_names = source.fixed_physical_names_v1()?;
        let released = source.journal().source_domain_policy_hold_v1()?
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if source_names != original_source
            || source_next != u64::from_be_bytes(super::fixed(metadata, 472))
                .checked_add(11).ok_or(CreateQ04ErrorV1::Bounds)?
            || released.is_held() || released.operation() != identity.operation()
            || released.sandbox() != identity.sandbox()
            || released.controller_source() != ledger.source_commitment()
            || released.binding() != identity.binding() || released.epoch() != identity.epoch()
            || source.journal().get(crate::journal::RecordNamespace::SourceDomainPolicyHold,
                super::SOURCE_PENDING_KEY).is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = flight.q04_terminal_nonce()?;
        let floor_payload = super::super::source_genesis_root::decode_root_source_genesis_frame_v2(
            &self.floor_frame, RootSourceGenesisFrameKindV1::Anchored, nonce,
        )?;
        let floor = super::super::SourceHierarchyFloorRecordV1::from_record_bytes(floor_payload)?;
        let controller = hold_existing_completed_source_genesis_v2(journal, identity.project())?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(&inventory, controller.uid(), identity.project())?;
        controller.recheck_completed_source_ack(&acknowledged)?;
        if floor.digest() != identity.gen1_floor()
            || controller.accepted_floor_digest()? != identity.gen1_floor()
            || acknowledged.ack_floor_digest() != Some(identity.gen1_floor())
            || acknowledged.receipt() != Some(floor.receipt())
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        acknowledged.recheck()?;
        inventory.recheck().map_err(SourceGenesisErrorV1::from)?;
        controller.recheck()?;
        drop(acknowledged);
        drop(inventory);
        drop(controller);

        if journal.q04_controller_refresh_bookend_v1(ledger, transitions)? != controller_before
            || source.journal().snapshot_sequence() != source_next
            || source.fixed_physical_names_v1()? != source_names
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        flight.q04_terminal_clock()?;
        Ok(())
    }

    // Root independently verifies its real Source-role pin before returning
    // each full Source packet. This consumer trusts that authenticated original
    // producer boundary; it does not invent a separate Controller Source pin.
    // Its own exact current Controller/Source native and gen1 checks remain.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_original_clearance(
        &mut self,
        journal: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        source_recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        cache: &mut crate::cache_residency::OriginalQ04CacheOwnerCutV1<'_>,
        cache_recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
        identity: &super::Q04CutIdentityV1,
    ) -> Result<(), ()> {
        let prepared = (|| {
            if self.phase != Q04ClientPhaseV1::FinalClearance
                || self.refresh_complete.len() != 11 || self.refresh_source_frames.len() != 11
                || self.shutdown_observation.is_some()
                || !std::ptr::eq(source_recipes.identity(), identity)
                || !std::ptr::eq(cache_recipes.identity(), identity)
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.require_final_original_readbacks(journal, source, ledger, transitions, identity)?;
            source.journal().readback_source_q04_original_v1(source_recipes, 3)?;
            let flight = self.flight.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let returned = self.refresh_source_frames.last().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            decode_root_create_q04_transfer_v1(
                returned, RootCreateQ04TransferKindV1::SourceObservation, flight.q04_terminal_nonce()?,
            )?;
            flight.q04_terminal_clock()?;
            Ok(())
        })();
        self.retain_result(prepared)?;

        let received = match self.flight.as_ref() {
            Some(flight) => flight.q04_expect_original_shutdown(
                &mut self.shutdown_observation, &mut self.shutdown_byte,
            ),
            None => Err(CreateQ04ErrorV1::ChangedCut),
        };
        self.retain_result(received)?;
        let checked = self.require_final_original_readbacks(journal, source, ledger, transitions, identity);
        self.retain_result(checked)?;
        self.phase = Q04ClientPhaseV1::FinalObservation;

        let original = OriginalQ04FinalRootObservationV1 { invocation: self, identity };
        cache.finish_original_clearance(cache_recipes, &original)?;
        let checked = (|| {
            source.journal().readback_source_q04_original_v1(source_recipes, 3)?;
            self.require_final_original_readbacks(journal, source, ledger, transitions, identity)?;
            original.recheck()
        })();
        drop(original);
        self.retain_result(checked)?;
        self.cleared = true;
        Ok(())
    }

    fn root_phase(&self, identity: &super::Q04CutIdentityV1, index: usize) -> Result<super::Q04PhaseRecordV1, CreateQ04ErrorV1> {
        let response = match index {
            0 => RootCreateQ04TransferKindV1::PolicyAccepted,
            1 => RootCreateQ04TransferKindV1::ReleaseAuthorized,
            2 => RootCreateQ04TransferKindV1::Settled,
            3 => RootCreateQ04TransferKindV1::FinalClearance,
            _ => return Err(CreateQ04ErrorV1::ChangedCut),
        };
        let bytes = decode_root_create_q04_transfer_v1(
            self.root_phase_frames.get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?, response, identity.nonce(),
        )?;
        super::Q04PhaseRecordV1::decode(super::Q04PhaseOwnerV1::Root, bytes, identity).map_err(Into::into)
    }

    pub(crate) fn first_cause(&self) -> Option<&CreateQ04ErrorV1> {
        self.first.as_ref()
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&CreateQ04ErrorV1> {
        self.postcheck_debt.as_ref()
    }

    fn retain_result(&mut self, result: Result<(), CreateQ04ErrorV1>) -> Result<(), ()> {
        match result {
            Ok(()) if self.first.is_none() && self.postcheck_debt.is_none() => Ok(()),
            Ok(()) => Err(()),
            Err(first) => {
                // A retained postcheck cause is already the real failure; do
                // not replace it with a synthetic forwarding ChangedCut.
                if self.first.is_none() && self.postcheck_debt.is_none() {
                    self.first = Some(first);
                }
                Err(())
            }
        }
    }
}

impl Drop for OriginalCreateQ04InvocationV1<'_> {
    fn drop(&mut self) {
        if !self.cleared {
            // In particular this runs before OriginalRootGenesisFlight's
            // legacy shutdown Drop or the enclosing Cache clock guard can run.
            if self.first.is_none() {
                self.first = Some(CreateQ04ErrorV1::Unwind);
            }
            std::process::exit(1);
        }
    }
}
