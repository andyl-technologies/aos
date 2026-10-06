//! Resident consumers of genuinely retained first-successor approvals.
//!
//! Controller phase ownership retains its mutable Journal loan. Inventory is
//! only a short authentic comparison loan and ends before Source mutation.
//! Returned failure keeps the original writers, selected profile and all action
//! Results resident until deliberate termination. No approval DATA opens Delete.
//! Global strict, global mixed comparison and project-scoped recipes share one
//! ordered flight and mutation loop. Key selection stays independent of wire
//! comparison purpose. Six mixed evidence slots own complete decoded maps after
//! each short Source loan ends; none can reconstruct a live observation.

use std::cell::RefCell;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_core::{DesiredGeneration, ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1;

use crate::hierarchy::codec::tree_commitment_v1;
use crate::hierarchy::controller_genesis::{hold_existing_completed_source_genesis_v2, require_controller};
use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, digest_at, take};
use crate::hierarchy::model::SandboxTreeRecordV1;
use crate::hierarchy::protected_journal::RetainedTreeInventoryDataV1;
use crate::hierarchy::protected_journal::retained_tree_inventory_data_v1;
use crate::hierarchy::source_successor::SourceSuccessorApprovalDataV2;
use crate::hierarchy::{
    HeldSourceFirstSuccessorObservationV2, SourceFirstSuccessorStateV2,
    first_source_successor_inventory_uid_v2, observe_source_first_successor_v2,
    SourceFirstSuccessorMutationResultsV2, SourceFirstSuccessorMutationFailureV2,
    append_source_first_successor_v2, acknowledge_source_first_successor_v2,
};
use crate::journal::controller_source_successor_issuance::{self as issuance, controller_capacity_request};
use crate::journal::source_tree_successor::{FirstSourceSuccessorNativePhaseV2 as NativePhase, transaction_id};
use crate::journal::{CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalNamesV1, RecordNamespace};
use crate::public_api_session::{PinnedSystemdCredential, PublicApiSessionError};
use crate::publisher_policy::{PinnedPublisherProjectAuthorizationIssuerV2, verify_signed_project_authorization_claims_v2};
use crate::hierarchy::source_seed::PinnedControllerSourceTreeSeedIssuerV1;
use crate::hierarchy::{
    SourceSuccessorObservationViewV3, observe_source_project_continuation_v3,
};
use issuance::IssuanceKeyRecipeV3;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;

use super::records::SourceHierarchyFloorRecordV1;
use super::successor_records::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorAnchoredV2,
    ControllerFirstSourceSuccessorBeginFieldsV2, ControllerFirstSourceSuccessorBeginV2,
    ControllerFirstSourceSuccessorCompleteFieldsV2, ControllerFirstSourceSuccessorCompleteV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckFieldsV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorReceiptV2,
};

const CONTROLLER_OBSERVATION_BYTES: usize = 2560;
const CONTROLLER_OBSERVATION_BODY: usize = CONTROLLER_OBSERVATION_BYTES - 64;
const OBSERVATION_MAGIC: &[u8; 8] = b"AOSCSO02";
const OBSERVATION_DOMAIN: &[u8] =
    b"aos.sandbox.source-first-successor.controller-held-observation.signature.v2\0";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ControllerSuccessorSignatureRecipeV3 { StrictV2, MixedV3 }

impl ControllerSuccessorSignatureRecipeV3 {
    const fn magic(self) -> &'static [u8; 8] {
        match self { Self::StrictV2 => OBSERVATION_MAGIC, Self::MixedV3 => b"AOSCSO03" }
    }

    const fn version(self) -> u8 {
        match self { Self::StrictV2 => 2, Self::MixedV3 => 3 }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::StrictV2 => OBSERVATION_DOMAIN,
            Self::MixedV3 => b"aos.sandbox.source-first-successor.controller-held-observation.signature.v3\0",
        }
    }
}

/// Identifies the original first-successor boundary without granting progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstSourceSuccessorConsumerPhaseV2 {
    /// Selects actual retained issuance and independently held predecessors.
    Admission,
    /// Retains the exact native Controller Begin and reserved whole suffix.
    Begin,
    /// Connects the original Root peer and receives durable Prepared.
    Prepare,
    /// Appends the sole canonical Source successor atomically.
    Source,
    /// Receives the exact Root floor/archive join on the original flight.
    Anchor,
    /// Retains Controller Anchored and settles the exact Source ACK.
    Acknowledge,
    /// Retains Controller Complete and receives actual Root Completed.
    Complete,
    /// Consumes populated current ancestry and finishes the same original stream.
    Finish,
}

/// Reports only the actual parked singleton selector, never mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstSourceSuccessorSelectionV2 {
    /// No retained slot exists; no signer or Root work is required.
    Absent,
    /// Actual retained work requires genuine owner admission and coordination.
    Selected,
    /// The retained selection failed and its original Result remains parked.
    Failed,
}

// A sticky diagnostic locator, not admission authority. Indices refer to
// append-only resident Results; later independent debt cannot replace them.
#[derive(Clone, Copy)]
enum ResidentFailureSiteV2 {
    SourceObservation(usize),
    ConfiguredInput,
    Selection,
    SeedPin,
    AuthorizationPin,
    HelloReceived,
    Connection,
    Begin,
    Anchored,
    Complete,
    SourceAppend,
    SourceAck,
    Phase(FirstSourceSuccessorConsumerPhaseV2, PhaseFailureSiteV2),
    OwnerPost(usize),
    ClockPost(usize),
    ReturnedCause,
}

#[derive(Clone, Copy)]
enum PhaseFailureSiteV2 {
    Signature,
    Sent,
    Received,
    Reception,
    OwnerPost(usize),
    ClockPost(usize),
}

fn park_owner_post(
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
    first: &mut Option<ResidentFailureSiteV2>,
    phase: Option<FirstSourceSuccessorConsumerPhaseV2>,
    returned: Result<(), SourceGenesisErrorV1>,
) {
    let index = posts.len();
    posts.push(returned);
    if posts[index].is_err() {
        first.get_or_insert(match phase {
            Some(phase) => ResidentFailureSiteV2::Phase(phase, PhaseFailureSiteV2::OwnerPost(index)),
            None => ResidentFailureSiteV2::OwnerPost(index),
        });
    }
}

fn park_clock_post(
    posts: &mut Vec<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    first: &mut Option<ResidentFailureSiteV2>,
    phase: Option<FirstSourceSuccessorConsumerPhaseV2>,
    returned: Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>,
) {
    let index = posts.len();
    posts.push(returned);
    if posts[index].is_err() {
        first.get_or_insert(match phase {
            Some(phase) => ResidentFailureSiteV2::Phase(phase, PhaseFailureSiteV2::ClockPost(index)),
            None => ResidentFailureSiteV2::ClockPost(index),
        });
    }
}

#[derive(Default)]
struct OriginalPhaseResultsV2 {
    signature: Option<Result<[u8; CONTROLLER_OBSERVATION_BYTES], SourceGenesisErrorV1>>,
    frame: Vec<u8>,
    sent: Option<Result<(), SourceGenesisErrorV1>>,
    reply: Vec<u8>,
    received: Option<Result<UnixStreamSubjectChunk, RetainedSeqpacketReceiveErrorV1>>,
    reception: Option<Result<(), SourceGenesisErrorV1>>,
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
}

impl OriginalPhaseResultsV2 {
    fn resident_error(&self, site: PhaseFailureSiteV2) -> Option<&(dyn std::error::Error + 'static)> {
        match site {
            PhaseFailureSiteV2::Signature => self.signature.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            PhaseFailureSiteV2::Sent => self.sent.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            PhaseFailureSiteV2::Received => self.received.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            PhaseFailureSiteV2::Reception => self.reception.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            PhaseFailureSiteV2::OwnerPost(index) => self.posts.get(index)?.as_ref().err().map(|error| error as &dyn std::error::Error),
            PhaseFailureSiteV2::ClockPost(index) => self.clock_posts.get(index)?.as_ref().err().map(|error| error as &dyn std::error::Error),
        }
    }

    fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.signature { return Some(error); }
        if let Some(Err(error)) = &self.sent { return Some(error); }
        if let Some(Err(error)) = &self.received { return Some(error); }
        if let Some(Err(error)) = &self.reception { return Some(error); }
        for post in &self.posts {
            if let Err(error) = post { return Some(error); }
        }
        for post in &self.clock_posts {
            if let Err(error) = post { return Some(error); }
        }
        None
    }
}

/// Parks original writers and profile before every fallible selected crossing.
#[must_use = "retain the original attempt until exact Finish or deliberate termination"]
pub struct OriginalFirstSourceSuccessorInvocationV2<'writers, 'profile> {
    journal: &'writers mut Journal,
    source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    selection: Option<Result<Option<issuance::RetainedIssuanceDataV2>, JournalError>>,
    seed_pin: Option<Result<PinnedSystemdCredential, PublicApiSessionError>>,
    authorization_pin: Option<Result<PinnedSystemdCredential, PublicApiSessionError>>,
    raw: Option<OwnedFd>,
    adopted: Option<RetainedUnixStream>,
    flight: Option<super::flight::OriginalRootGenesisFlightV1<'profile>>,
    hello: Vec<u8>,
    hello_received: Option<Result<UnixStreamSubjectChunk, RetainedSeqpacketReceiveErrorV1>>,
    connection: Option<Result<(), SourceGenesisErrorV1>>,
    begin: ControllerFirstSuccessorMutationResultsV2,
    anchored: ControllerFirstSuccessorMutationResultsV2,
    complete: ControllerFirstSuccessorMutationResultsV2,
    append: SourceFirstSuccessorMutationResultsV2,
    ack: SourceFirstSuccessorMutationResultsV2,
    prepare_io: OriginalPhaseResultsV2,
    anchor_io: OriginalPhaseResultsV2,
    complete_io: OriginalPhaseResultsV2,
    finish_io: OriginalPhaseResultsV2,
    owner_posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    phase: FirstSourceSuccessorConsumerPhaseV2,
    first_site: Option<ResidentFailureSiteV2>,
    first_owner: Option<SourceGenesisErrorV1>,
    cleanup: Option<Result<(), SourceGenesisErrorV1>>,
    outcome: Option<Option<ObjectDigest>>,
    started: bool,
    armed: bool,
    recipe: StartupSuccessorRecipeV3,
    configured: Option<&'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1>,
    configured_result: Option<Result<(), crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1>>,
    source_evidence: [Option<crate::hierarchy::SourceProjectContinuationEvidenceV3>; 6],
}

#[derive(Clone, Copy)]
enum StartupSuccessorRecipeV3 { GlobalStrictV2, GlobalMixedV3, ProjectMixedV3(ProjectId) }

impl StartupSuccessorRecipeV3 {
    fn keys(self) -> IssuanceKeyRecipeV3 {
        match self { Self::GlobalStrictV2 | Self::GlobalMixedV3 => IssuanceKeyRecipeV3::GlobalV2, Self::ProjectMixedV3(project) => IssuanceKeyRecipeV3::ProjectV3(project) }
    }

    fn comparison(self) -> ControllerSuccessorSignatureRecipeV3 {
        match self { Self::GlobalStrictV2 => ControllerSuccessorSignatureRecipeV3::StrictV2, Self::GlobalMixedV3 | Self::ProjectMixedV3(_) => ControllerSuccessorSignatureRecipeV3::MixedV3 }
    }
}

/// Parks the genuine selected writer pair for the project-scoped consumer.
#[must_use = "retain the whole selected invocation through Finish or termination"]
pub struct OriginalProjectSuccessorInvocationV3<'writers, 'profile> {
    common: OriginalFirstSourceSuccessorInvocationV2<'writers, 'profile>,
}

/// Retains the selected original writers and chronological failed Results.
#[must_use = "retain the failed selected owner until deliberate termination"]
pub struct FailedProjectSuccessorInvocationV3<'writers, 'profile> {
    common: FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>,
}

impl<'writers, 'profile> OriginalProjectSuccessorInvocationV3<'writers, 'profile> {
    /// Parks actual owners before the unchanged fixed signer callback.
    pub fn park(
        journal: &'writers mut Journal, source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile ProductionControllerNormalRootProfileV1, project: ProjectId,
    ) -> Self {
        let mut common = OriginalFirstSourceSuccessorInvocationV2::park_inner(journal, Some(source), profile);
        common.recipe = StartupSuccessorRecipeV3::ProjectMixedV3(project);
        Self { common }
    }

    /// Parks the actual global predecessor before a genuinely configured B pair.
    pub fn park_predecessor(
        journal: &'writers mut Journal, source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        configured: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Self {
        let mut common = OriginalFirstSourceSuccessorInvocationV2::park_inner(journal, Some(source), profile);
        common.recipe = StartupSuccessorRecipeV3::GlobalMixedV3;
        common.configured = Some(configured);
        Self { common }
    }

    /// Selects actual complete retained histories without minting admission.
    pub fn select_retained_before_signer(&mut self) -> FirstSourceSuccessorSelectionV2 { self.common.select_retained_before_signer() }
    /// Runs the same ordered producer under the existing signer loan.
    pub fn run_with_controller_signer(&mut self, generation: u64, signer: &SigningKey) { self.common.run_with_controller_signer(generation, signer); }
    /// Parks actual fixed signer admission failure on the prearmed owner.
    pub fn fail_controller_signer_admission(&mut self, error: std::io::Error) { self.common.fail_controller_signer_admission(error); }
    /// Returns comparison completion DATA or the whole failed selected owner.
    ///
    /// # Errors
    /// Refuses incomplete work while retaining original resources and debt.
    pub fn into_outcome(self) -> Result<Option<ObjectDigest>, FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        self.common.into_outcome().map_err(|common| FailedProjectSuccessorInvocationV3 { common })
    }
}

impl FailedProjectSuccessorInvocationV3<'_, '_> {
    /// Borrows the actual chronological resident cause without observation.
    pub fn first_cause(&self) -> (FirstSourceSuccessorConsumerPhaseV2, Option<&(dyn std::error::Error + 'static)>) { self.common.first_cause() }
    /// Borrows all independent original owner failures.
    pub fn post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> { self.common.post_failures() }
    /// Borrows independent original-clock debt without renewing admission.
    pub fn clock_post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> { self.common.clock_post_failures() }
    /// Terminates without releasing the resident original resources.
    pub fn terminate_failed(self) -> ! { std::process::exit(1) }
}

/// Retains failed original custody until deliberate termination.
#[must_use = "keep the whole failed owner resident through termination"]
pub struct FailedOriginalFirstSourceSuccessorV2<'writers, 'profile> {
    original: OriginalFirstSourceSuccessorInvocationV2<'writers, 'profile>,
}

impl<'writers, 'profile> OriginalFirstSourceSuccessorInvocationV2<'writers, 'profile> {
    /// Parks genuine production owners without inspecting or mutating state.
    pub fn park(
        journal: &'writers mut Journal, source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Self { Self::park_inner(journal, Some(source), profile) }

    /// Inspects the actual singleton before admitting the existing signer loan.
    pub fn select_retained_before_signer(&mut self) -> FirstSourceSuccessorSelectionV2 {
        if self.selection.is_some() || self.started {
            self.first_owner.get_or_insert(SourceGenesisErrorV1::Conflict);
            self.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
            return FirstSourceSuccessorSelectionV2::Failed;
        }
        self.selection = Some(match self.recipe.keys() {
            IssuanceKeyRecipeV3::GlobalV2 => issuance::retained(self.journal),
            IssuanceKeyRecipeV3::ProjectV3(project) => issuance::retained_project_v3(self.journal, project),
        });
        if matches!(self.selection, Some(Err(_))) {
            self.first_site.get_or_insert(ResidentFailureSiteV2::Selection);
        }
        match self.selection.as_ref() {
            Some(Ok(None)) => { self.outcome = Some(None); FirstSourceSuccessorSelectionV2::Absent }
            Some(Ok(Some(_))) => FirstSourceSuccessorSelectionV2::Selected,
            _ => { self.first_owner = Some(SourceGenesisErrorV1::AdmissionClosed); FirstSourceSuccessorSelectionV2::Failed }
        }
    }

    fn park_inner(journal: &'writers mut Journal, source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>, profile: &'profile ProductionControllerNormalRootProfileV1) -> Self {
        Self {
            journal, source, profile, selection: None, seed_pin: None, authorization_pin: None,
            raw: None, adopted: None, flight: None,
            hello: Vec::new(), hello_received: None, connection: None,
            begin: Default::default(), anchored: Default::default(), complete: Default::default(),
            append: SourceFirstSuccessorMutationResultsV2::new(), ack: SourceFirstSuccessorMutationResultsV2::new(),
            prepare_io: Default::default(), anchor_io: Default::default(), complete_io: Default::default(), finish_io: Default::default(),
            owner_posts: Vec::new(), clock_posts: Vec::new(), phase: FirstSourceSuccessorConsumerPhaseV2::Admission,
            first_site: None, first_owner: None, cleanup: None, outcome: None, started: false, armed: true,
            recipe: StartupSuccessorRecipeV3::GlobalStrictV2, configured: None, configured_result: None,
            source_evidence: std::array::from_fn(|_| None),
        }
    }

    /// Runs once inside the existing actual Controller-purpose signer loan.
    ///
    /// Native and RPC Results are parked before independent postchecks. An
    /// ambiguous append is never redispatched by this invocation.
    pub fn run_with_controller_signer(&mut self, generation: u64, signer: &SigningKey) {
        if self.started || self.first_owner.is_some() {
            self.first_owner.get_or_insert(SourceGenesisErrorV1::Conflict);
            self.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
            return;
        }
        self.started = true;
        match coordinate_retained_successor(self, generation, signer) {
            Ok(outcome) => self.outcome = Some(outcome),
            Err(cause) => {
                self.first_owner.get_or_insert(cause);
                self.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
            }
        }
    }

    /// Latches admission failure of the unchanged fixed Controller signer.
    pub fn fail_controller_signer_admission(&mut self, error: std::io::Error) {
        self.first_owner.get_or_insert(SourceGenesisErrorV1::Transport(error));
        self.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
    }

    /// Returns historical completion DATA or the whole retaining failed owner.
    ///
    /// # Errors
    /// Every selected incomplete/failed invocation requires deliberate termination.
    pub fn into_outcome(mut self) -> Result<Option<ObjectDigest>, FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
        if self.first_owner.is_none() && self.first_site.is_none() {
            if let Some(outcome) = self.outcome.take() {
                self.armed = false;
                return Ok(outcome);
            }
            self.first_owner = Some(SourceGenesisErrorV1::AdmissionClosed);
        }
        self.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
        self.cleanup = Some(if let Some(flight) = &self.flight {
            flight.end_failed()
        } else if let Some(raw) = &self.raw {
            rustix::net::shutdown(raw, rustix::net::Shutdown::Both)
                .map_err(|error| SourceGenesisErrorV1::Transport(std::io::Error::from(error)))
        } else { Ok(()) });
        Err(FailedOriginalFirstSourceSuccessorV2 { original: self })
    }
}

impl FailedOriginalFirstSourceSuccessorV2<'_, '_> {
    /// Borrows the chronologically latched resident cause without observation.
    pub fn first_cause(&self) -> (FirstSourceSuccessorConsumerPhaseV2, Option<&(dyn std::error::Error + 'static)>) {
        let original = &self.original;
        let cause = match original.first_site {
            Some(ResidentFailureSiteV2::SourceObservation(index)) => original.source_evidence.get(index).and_then(Option::as_ref).and_then(|evidence| evidence.error()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::ConfiguredInput) => original.configured_result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::Selection) => original.selection.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::SeedPin) => original.seed_pin.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::AuthorizationPin) => original.authorization_pin.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::HelloReceived) => original.hello_received.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::Connection) => original.connection.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::Begin) => original.begin.error(),
            Some(ResidentFailureSiteV2::Anchored) => original.anchored.error(),
            Some(ResidentFailureSiteV2::Complete) => original.complete.error(),
            Some(ResidentFailureSiteV2::SourceAppend) => source_mutation_error(&original.append),
            Some(ResidentFailureSiteV2::SourceAck) => source_mutation_error(&original.ack),
            Some(ResidentFailureSiteV2::Phase(phase, site)) => match phase {
                FirstSourceSuccessorConsumerPhaseV2::Prepare => original.prepare_io.resident_error(site),
                FirstSourceSuccessorConsumerPhaseV2::Anchor => original.anchor_io.resident_error(site),
                FirstSourceSuccessorConsumerPhaseV2::Complete => original.complete_io.resident_error(site),
                FirstSourceSuccessorConsumerPhaseV2::Finish => original.finish_io.resident_error(site),
                _ => None,
            },
            Some(ResidentFailureSiteV2::OwnerPost(index)) => original.owner_posts.get(index).and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::ClockPost(index)) => original.clock_posts.get(index).and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error),
            Some(ResidentFailureSiteV2::ReturnedCause) => original.first_owner.as_ref().map(|error| error as &dyn std::error::Error),
            None => None,
        };
        (original.phase, cause)
    }

    /// Borrows independent writer/profile/stream debt without replacing cause.
    pub fn post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> {
        self.original.owner_posts.iter().filter_map(|result| result.as_ref().err())
            .chain(self.original.source_evidence.iter().filter_map(Option::as_ref)
                .flat_map(|evidence| evidence.post_failures()))
    }

    /// Borrows independent actual original-clock debt without clearing poison.
    pub fn clock_post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> {
        let original = &self.original;
        original.clock_posts.iter()
            .chain(original.prepare_io.clock_posts.iter())
            .chain(original.anchor_io.clock_posts.iter())
            .chain(original.complete_io.clock_posts.iter())
            .chain(original.finish_io.clock_posts.iter())
            .chain(original.begin.clock_post.iter())
            .chain(original.anchored.clock_post.iter())
            .chain(original.complete.clock_post.iter())
            .chain(original.append.clock_post_result())
            .chain(original.ack.clock_post_result())
            .filter_map(|result| result.as_ref().err())
    }

    /// Borrows every selected poll's resident actual original-clock Result.
    ///
    /// # Errors
    /// Rejects a conflicting live observation borrow without moving any Result.
    pub fn wait_clock_results(&self) -> Result<
        Option<std::cell::Ref<'_, Vec<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>>,
        SourceGenesisErrorV1,
    > {
        self.original.flight.as_ref()
            .map(super::flight::OriginalRootGenesisFlightV1::first_successor_wait_clock_results)
            .transpose()
    }

    /// Borrows independent original-owner poll debt without admitting transport.
    ///
    /// # Errors
    /// Rejects a conflicting live observation borrow without releasing custody.
    pub fn wait_owner_results(&self) -> Result<
        Option<std::cell::Ref<'_, Vec<Result<(), SourceGenesisErrorV1>>>>,
        SourceGenesisErrorV1,
    > {
        self.original.flight.as_ref()
            .map(super::flight::OriginalRootGenesisFlightV1::first_successor_wait_owner_results)
            .transpose()
    }

    /// Borrows the independently retained original-stream shutdown Result.
    pub fn cleanup_result(&self) -> Option<&Result<(), SourceGenesisErrorV1>> { self.original.cleanup.as_ref() }

    /// Deliberately terminates without releasing the borrowed original writers.
    pub fn terminate_failed(self) -> ! { std::process::exit(1) }
}

impl Drop for OriginalFirstSourceSuccessorInvocationV2<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            if let Some(flight) = &self.flight { let _ = flight.end_failed(); }
            else if let Some(raw) = &self.raw { let _ = rustix::net::shutdown(raw, rustix::net::Shutdown::Both); }
            std::process::abort();
        }
    }
}

fn source_mutation_error(results: &SourceFirstSuccessorMutationResultsV2) -> Option<&(dyn std::error::Error + 'static)> {
    results.error().map(|error| match error {
        SourceFirstSuccessorMutationFailureV2::Admission(error) => error as &dyn std::error::Error,
        SourceFirstSuccessorMutationFailureV2::Native(error) => error as &dyn std::error::Error,
    })
}

pub(crate) fn unavailable_first_source_successor_v2<'writers, 'profile>(
    journal: &'writers mut Journal, profile: &'profile ProductionControllerNormalRootProfileV1,
) -> Result<Option<ObjectDigest>, FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
    let mut original = OriginalFirstSourceSuccessorInvocationV2::park_inner(journal, None, profile);
    original.selection = Some(issuance::retained(original.journal));
    if matches!(original.selection, Some(Err(_))) {
        original.first_site.get_or_insert(ResidentFailureSiteV2::Selection);
    }
    match original.selection.as_ref() {
        Some(Ok(None)) => { original.outcome = Some(None); }
        _ => { original.first_owner = Some(SourceGenesisErrorV1::AdmissionClosed); }
    }
    original.into_outcome()
}

pub(crate) fn unavailable_project_successor_v3<'writers, 'profile>(
    journal: &'writers mut Journal, profile: &'profile ProductionControllerNormalRootProfileV1,
    project: ProjectId,
) -> Result<Option<ObjectDigest>, FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
    let mut common = OriginalFirstSourceSuccessorInvocationV2::park_inner(journal, None, profile);
    common.recipe = StartupSuccessorRecipeV3::ProjectMixedV3(project);
    common.select_retained_before_signer();
    if matches!(common.selection, Some(Ok(Some(_)))) {
        common.first_owner = Some(SourceGenesisErrorV1::AdmissionClosed);
        common.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
    }
    common.into_outcome().map_err(|common| FailedProjectSuccessorInvocationV3 { common })
}

pub(crate) fn unavailable_predecessor_successor_v3<'writers, 'profile>(
    journal: &'writers mut Journal, profile: &'profile ProductionControllerNormalRootProfileV1,
    configured: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
) -> Result<Option<ObjectDigest>, FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
    let mut common = OriginalFirstSourceSuccessorInvocationV2::park_inner(journal, None, profile);
    common.recipe = StartupSuccessorRecipeV3::GlobalMixedV3;
    common.configured = Some(configured);
    common.select_retained_before_signer();
    if matches!(common.selection, Some(Ok(Some(_)))) {
        common.first_owner = Some(SourceGenesisErrorV1::AdmissionClosed);
        common.first_site.get_or_insert(ResidentFailureSiteV2::ReturnedCause);
    }
    common.into_outcome().map_err(|common| FailedProjectSuccessorInvocationV3 { common })
}

enum SelectedControllerV3<'controller> {
    Strict(HeldControllerFirstSourceSuccessorV2<'controller>),
    Mixed(HeldControllerProjectSuccessorV3<'controller>),
}

impl<'controller> SelectedControllerV3<'controller> {
    fn view(&self) -> ControllerSuccessorOwnerViewV3<'_, 'controller> {
        match self { Self::Strict(owner) => ControllerSuccessorOwnerViewV3::Strict(owner), Self::Mixed(owner) => ControllerSuccessorOwnerViewV3::Mixed(owner) }
    }

    fn uid(&self) -> u32 { self.view().data().uid() }
    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.view().recheck() }

    fn packet(&self) -> &SourceSuccessorApprovalDataV2 {
        match self { Self::Strict(owner) => owner.packet(), Self::Mixed(owner) => owner.packet() }
    }

    fn append_begin(&mut self, results: &mut ControllerFirstSuccessorMutationResultsV2) -> Result<(), ()> {
        match self { Self::Strict(owner) => owner.append_begin(results), Self::Mixed(owner) => owner.append_begin(results) }
    }

    fn append_anchored(&mut self, source: &SelectedSourceV3<'_>, root: &SelectedFloorV3<'_>, results: &mut ControllerFirstSuccessorMutationResultsV2) -> Result<(), ()> {
        match (self, source, root) {
            (Self::Strict(owner), SelectedSourceV3::Strict(source), SelectedFloorV3::Strict(root)) => owner.append_anchored(source, root, results),
            (Self::Mixed(owner), SelectedSourceV3::Mixed(source), SelectedFloorV3::Mixed(root)) => owner.append_anchored(source, root, results),
            _ => Err(()),
        }
    }

    fn append_complete(&mut self, source: &SelectedSourceV3<'_>, root: &SelectedFloorV3<'_>, results: &mut ControllerFirstSuccessorMutationResultsV2) -> Result<(), ()> {
        match (self, source, root) {
            (Self::Strict(owner), SelectedSourceV3::Strict(source), SelectedFloorV3::Strict(root)) => owner.append_complete(source, root, results),
            (Self::Mixed(owner), SelectedSourceV3::Mixed(source), SelectedFloorV3::Mixed(root)) => owner.append_complete(source, root, results),
            _ => Err(()),
        }
    }
}

enum SelectedSourceV3<'source> {
    Strict(HeldSourceFirstSuccessorObservationV2<'source>),
    Mixed(crate::hierarchy::SourceProjectContinuationObservationV3<'source>),
}

impl<'source> SelectedSourceV3<'source> {
    fn observe(inventory: &'source RetainedTreeInventoryDataV1<'_>, uid: u32, project: ProjectId, recipe: StartupSuccessorRecipeV3) -> Result<Self, SourceGenesisErrorV1> {
        match recipe {
            StartupSuccessorRecipeV3::GlobalStrictV2 => observe_source_first_successor_v2(inventory, uid, project).map(Self::Strict),
            StartupSuccessorRecipeV3::GlobalMixedV3 | StartupSuccessorRecipeV3::ProjectMixedV3(_) => {
                if matches!(recipe, StartupSuccessorRecipeV3::ProjectMixedV3(selected) if selected != project) { return Err(SourceGenesisErrorV1::Conflict); }
                let observed = observe_source_project_continuation_v3(inventory, uid, project);
                // Keep the whole returned mixed observation, including failure,
                // resident through every independent original postcheck.
                Ok(Self::Mixed(observed))
            }
        }
    }

    fn view(&self) -> SourceSuccessorObservationViewV3<'_, 'source> {
        match self { Self::Strict(source) => SourceSuccessorObservationViewV3::Strict(source), Self::Mixed(source) => SourceSuccessorObservationViewV3::Mixed(source) }
    }

    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.view().recheck() }

    fn latch_observation(&self, index: usize, first: &mut Option<ResidentFailureSiteV2>) {
        if matches!(self, Self::Mixed(observed) if observed.error().is_some()) {
            first.get_or_insert(ResidentFailureSiteV2::SourceObservation(index));
        }
    }

    fn retain_evidence(self, slot: &mut Option<crate::hierarchy::SourceProjectContinuationEvidenceV3>) {
        if let Self::Mixed(observed) = self { *slot = Some(observed.into_evidence_v3()); }
    }
}

enum SelectedPurposeV3<'flight> {
    Strict(super::successor_flight::OriginalRootFirstSourceSuccessorFlightV2<'flight>),
    Mixed(super::successor_flight::OriginalRootProjectSuccessorFlightV3<'flight>),
}

impl<'flight> SelectedPurposeV3<'flight> {
    fn from_original(core: &'flight super::flight::OriginalRootGenesisFlightV1<'flight>, recipe: StartupSuccessorRecipeV3) -> Result<Self, SourceGenesisErrorV1> {
        match recipe {
            StartupSuccessorRecipeV3::GlobalStrictV2 => super::successor_flight::OriginalRootFirstSourceSuccessorFlightV2::from_original(core).map(Self::Strict),
            StartupSuccessorRecipeV3::GlobalMixedV3 | StartupSuccessorRecipeV3::ProjectMixedV3(_) => super::successor_flight::OriginalRootProjectSuccessorFlightV3::from_original(core).map(Self::Mixed),
        }
    }

    fn view(&self) -> super::successor_flight::RootSuccessorFlightViewV3<'_, '_> {
        match self { Self::Strict(flight) => super::successor_flight::RootSuccessorFlightViewV3::Strict(flight), Self::Mixed(flight) => super::successor_flight::RootSuccessorFlightViewV3::Mixed(flight) }
    }

    fn source_uid(&self) -> Result<u32, SourceGenesisErrorV1> { self.view().source_uid() }
    fn nonce(&self) -> [u8; 16] { self.view().nonce() }
    fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.view().observe_original_clock() }

    fn encode(&self, output: &mut Vec<u8>, phase: super::wire::RootFirstSourceSuccessorFrameKindV2, payload: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        match self {
            Self::Strict(_) => super::wire::encode_root_first_source_successor_frame_v2(output, phase, self.nonce(), payload),
            Self::Mixed(_) => super::wire::encode_root_project_source_successor_frame_v3(output, phase, self.nonce(), payload),
        }
    }

    fn decode<'frame>(&self, frame: &'frame [u8], phase: super::wire::RootFirstSourceSuccessorFrameKindV2) -> Result<&'frame [u8], SourceGenesisErrorV1> {
        match self {
            Self::Strict(_) => super::wire::decode_root_first_source_successor_frame_v2(frame, phase, self.nonce()),
            Self::Mixed(_) => super::wire::decode_root_project_source_successor_frame_v3(frame, phase, self.nonce()),
        }
    }

    fn prepared(&'flight self, frame: &[u8], controller: &SelectedControllerV3<'_>) -> Result<SelectedIntentV3<'flight>, SourceGenesisErrorV1> {
        match (self, controller) {
            (Self::Strict(flight), SelectedControllerV3::Strict(controller)) => flight.prepared(frame, controller).map(SelectedIntentV3::Strict),
            (Self::Mixed(flight), SelectedControllerV3::Mixed(controller)) => flight.prepared(frame, controller).map(SelectedIntentV3::Mixed),
            _ => Err(SourceGenesisErrorV1::Conflict),
        }
    }

    fn anchored(&'flight self, frame: &[u8], prepared: &SelectedIntentV3<'_>) -> Result<SelectedFloorV3<'flight>, SourceGenesisErrorV1> {
        match (self, prepared) {
            (Self::Strict(flight), SelectedIntentV3::Strict(intent)) => flight.anchored(frame, intent).map(SelectedFloorV3::Strict),
            (Self::Mixed(flight), SelectedIntentV3::Mixed(intent)) => flight.anchored(frame, intent).map(SelectedFloorV3::Mixed),
            _ => Err(SourceGenesisErrorV1::Conflict),
        }
    }

    fn completed<'completed>(&self, frame: &[u8], floor: &'completed SelectedFloorV3<'flight>, controller: &SelectedControllerV3<'_>) -> Result<SelectedCompletedV3<'completed, 'flight>, SourceGenesisErrorV1> {
        match (self, floor, controller) {
            (Self::Strict(flight), SelectedFloorV3::Strict(floor), SelectedControllerV3::Strict(controller)) => flight.completed(frame, floor, controller).map(SelectedCompletedV3::Strict),
            (Self::Mixed(flight), SelectedFloorV3::Mixed(floor), SelectedControllerV3::Mixed(controller)) => flight.completed(frame, floor, controller).map(SelectedCompletedV3::Mixed),
            _ => Err(SourceGenesisErrorV1::Conflict),
        }
    }
}

enum SelectedIntentV3<'flight> {
    Strict(super::successor_flight::HeldRootFirstSourceSuccessorIntentV2<'flight>),
    Mixed(super::successor_flight::HeldRootProjectSuccessorIntentV3<'flight>),
}

impl SelectedIntentV3<'_> {
    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        match self { Self::Strict(intent) => intent.recheck(), Self::Mixed(intent) => intent.recheck() }
    }

    fn append(&self, source: &mut ProtectedSourceDomainJournalOwnerV1, controller: &SelectedControllerV3<'_>, results: &mut SourceFirstSuccessorMutationResultsV2) -> Result<SourceFirstSuccessorReceiptV2, ()> {
        match (self, controller) {
            (Self::Strict(root), SelectedControllerV3::Strict(controller)) => append_source_first_successor_v2(source, controller, root, results),
            (Self::Mixed(root), SelectedControllerV3::Mixed(controller)) => crate::hierarchy::append_source_project_continuation_v3(source, controller, root, results),
            _ => Err(()),
        }
    }
}

enum SelectedFloorV3<'flight> {
    Strict(super::successor_flight::RootFirstSourceSuccessorFloorProofV2<'flight>),
    Mixed(super::successor_flight::RootProjectSuccessorFloorProofV3<'flight>),
}

impl SelectedFloorV3<'_> {
    fn floor(&self) -> &super::successor_records::RootFirstSourceSuccessorFloorV2 {
        match self { Self::Strict(floor) => floor.floor(), Self::Mixed(floor) => floor.floor() }
    }

    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        match self { Self::Strict(floor) => floor.recheck(), Self::Mixed(floor) => floor.recheck() }
    }

    fn acknowledge(&self, source: &mut ProtectedSourceDomainJournalOwnerV1, controller: &SelectedControllerV3<'_>, results: &mut SourceFirstSuccessorMutationResultsV2) -> Result<SourceFirstSuccessorAckV2, ()> {
        match (self, controller) {
            (Self::Strict(root), SelectedControllerV3::Strict(controller)) => acknowledge_source_first_successor_v2(source, controller, root, results),
            (Self::Mixed(root), SelectedControllerV3::Mixed(controller)) => crate::hierarchy::acknowledge_source_project_continuation_v3(source, controller, root, results),
            _ => Err(()),
        }
    }
}

enum SelectedCompletedV3<'completed, 'flight> {
    Strict(super::successor_flight::CompletedRootFirstSourceSuccessorFloorV2<'completed, 'flight>),
    Mixed(super::successor_flight::CompletedRootProjectSuccessorFloorV3<'completed, 'flight>),
}

impl SelectedCompletedV3<'_, '_> {
    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        match self { Self::Strict(completed) => completed.recheck(), Self::Mixed(completed) => completed.recheck() }
    }

    fn finish_payload(&self) -> [u8; 96] {
        match self { Self::Strict(completed) => completed.finish_payload(), Self::Mixed(completed) => completed.finish_payload() }
    }

    fn consume(&self, controller: &SelectedControllerV3<'_>, source: &SelectedSourceV3<'_>, inventory: &RetainedTreeInventoryDataV1<'_>) -> Result<(), SourceGenesisErrorV1> {
        match (self, controller, source) {
            (Self::Strict(root), SelectedControllerV3::Strict(controller), SelectedSourceV3::Strict(source)) => super::super::public_create_source::consume_completed_first_successor_ancestry_v2(controller, source, inventory, root),
            (Self::Mixed(root), SelectedControllerV3::Mixed(controller), SelectedSourceV3::Mixed(source)) => super::super::public_create_source::consume_completed_project_successor_ancestry_v3(controller, source, inventory, root),
            _ => Err(SourceGenesisErrorV1::Conflict),
        }
    }
}

fn coordinate_retained_successor(
    original: &mut OriginalFirstSourceSuccessorInvocationV2<'_, '_>,
    generation: u64, signer: &SigningKey,
) -> Result<Option<ObjectDigest>, SourceGenesisErrorV1> {
    use FirstSourceSuccessorConsumerPhaseV2 as Step;
    use super::wire::RootFirstSourceSuccessorFrameKindV2 as Wire;
    let OriginalFirstSourceSuccessorInvocationV2 {
        journal, source, profile, selection, seed_pin, authorization_pin,
        raw, adopted, flight, hello, hello_received, connection,
        begin, anchored, complete, append, ack, prepare_io, anchor_io, complete_io, finish_io,
        owner_posts, clock_posts, phase, first_site, recipe, configured, configured_result, source_evidence, ..
    } = original;
    if selection.is_none() {
        *selection = Some(match recipe.keys() {
            IssuanceKeyRecipeV3::GlobalV2 => issuance::retained(journal),
            IssuanceKeyRecipeV3::ProjectV3(project) => issuance::retained_project_v3(journal, project),
        });
    }
    if matches!(selection, Some(Err(_))) { first_site.get_or_insert(ResidentFailureSiteV2::Selection); }
    let selected = selection.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    let Some(selected) = selected else { return Ok(None); };
    if !selected.delivered { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    if matches!(recipe, StartupSuccessorRecipeV3::GlobalMixedV3) {
        let input = configured.ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
        *configured_result = Some((|| {
            if input.has_retained_attempt(journal)? {
                // Existing B is compared with its actual retained acceptance.
                // Historical pair custody does not renew fresh B admission.
                input.recheck()
            } else {
                input.inspect_current(journal)
            }
        })());
        if matches!(configured_result, Some(Err(_))) { first_site.get_or_insert(ResidentFailureSiteV2::ConfiguredInput); }
        park_owner_post(owner_posts, first_site, None, input.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
        let uid = journal.protected_owner_uid()?;
        park_owner_post(owner_posts, first_site, None, require_controller(journal, uid));
        park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
        if !matches!(configured_result, Some(Ok(()))) || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
        if input.project() == selected.packet.intent()?.project() { return Err(SourceGenesisErrorV1::Conflict); }
    }
    let source = source.as_deref_mut().ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    source.require_fixed_named_writer_v1()?;
    profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
    // Park both genuine returned credential Results before building a phase
    // owner. A failed second load cannot release a returned first reader.
    *seed_pin = Some(PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1());
    if matches!(seed_pin, Some(Err(_))) { first_site.get_or_insert(ResidentFailureSiteV2::SeedPin); }
    *authorization_pin = Some(PinnedSystemdCredential::load_project_authorization_issuer_v2());
    if matches!(authorization_pin, Some(Err(_))) { first_site.get_or_insert(ResidentFailureSiteV2::AuthorizationPin); }
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    let uid = journal.protected_owner_uid()?;
    park_owner_post(owner_posts, first_site, None, require_controller(journal, uid));
    if owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    let seed_pin = seed_pin.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    let authorization_pin = authorization_pin.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    let mut controller = {
        let inventory = retained_tree_inventory_data_v1(source)?;
        match recipe {
            StartupSuccessorRecipeV3::GlobalStrictV2 => SelectedControllerV3::Strict(hold_retained_first_source_successor_v2(journal, seed_pin, authorization_pin, &inventory)?),
            StartupSuccessorRecipeV3::GlobalMixedV3 | StartupSuccessorRecipeV3::ProjectMixedV3(_) => {
                let validation = match recipe {
                    StartupSuccessorRecipeV3::GlobalMixedV3 => hold_retained_global_predecessor_v3(journal, seed_pin, authorization_pin, &inventory, &mut source_evidence[0]),
                    StartupSuccessorRecipeV3::ProjectMixedV3(project) => hold_retained_project_successor_v3(journal, seed_pin, authorization_pin, &inventory, *project, &mut source_evidence[0]),
                    StartupSuccessorRecipeV3::GlobalStrictV2 => return Err(SourceGenesisErrorV1::Conflict),
                };
                if source_evidence[0].as_ref().is_some_and(|evidence| evidence.error().is_some()) {
                    first_site.get_or_insert(ResidentFailureSiteV2::SourceObservation(0));
                }
                SelectedControllerV3::Mixed(validation?)
            }
        }
    };
    let project = controller.packet().intent()?.project();

    *phase = Step::Begin;
    let returned = controller.append_begin(begin);
    if returned.is_err() { first_site.get_or_insert(ResidentFailureSiteV2::Begin); }
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    if returned.is_err() || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::AdmissionClosed); }

    *phase = Step::Prepare;
    *connection = Some(match recipe {
        StartupSuccessorRecipeV3::GlobalStrictV2 => super::flight::OriginalRootGenesisFlightV1::connect_first_successor_parked(
            profile, raw, adopted, flight, hello, hello_received, controller.uid(),
        ),
        StartupSuccessorRecipeV3::GlobalMixedV3 | StartupSuccessorRecipeV3::ProjectMixedV3(_) => super::flight::OriginalRootGenesisFlightV1::connect_project_successor_parked_v3(
            profile, raw, adopted, flight, hello, hello_received, controller.uid(),
        ),
    });
    if !matches!(connection, Some(Ok(()))) {
        first_site.get_or_insert(if matches!(hello_received, Some(Err(_))) {
            ResidentFailureSiteV2::HelloReceived
        } else { ResidentFailureSiteV2::Connection });
    }
    park_owner_post(owner_posts, first_site, None, controller.recheck());
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    if let Some(core) = flight.as_ref() { park_clock_post(clock_posts, first_site, None, core.observe_first_successor_clock()); }
    if !matches!(connection, Some(Ok(()))) || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    if clock_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    let core = flight.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
    let purpose = SelectedPurposeV3::from_original(core, *recipe)?;
    {
        let inventory = retained_tree_inventory_data_v1(source)?;
        let observed = SelectedSourceV3::observe(&inventory, purpose.source_uid()?, project, *recipe)?;
        observed.latch_observation(1, first_site);
        let returned = exchange_phase(&controller, &observed, &purpose, core, generation, signer, Wire::Prepare, Wire::Prepared, prepare_io, Step::Prepare, first_site);
        observed.retain_evidence(&mut source_evidence[1]);
        returned?;
    }
    let prepared = purpose.prepared(&prepare_io.reply, &controller)?;

    *phase = Step::Source;
    let returned = prepared.append(source, &controller, append);
    if returned.is_err() { first_site.get_or_insert(ResidentFailureSiteV2::SourceAppend); }
    park_owner_post(owner_posts, first_site, None, controller.recheck());
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, prepared.recheck());
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    park_clock_post(clock_posts, first_site, None, purpose.observe_original_clock());
    if returned.is_err() || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    if clock_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }

    *phase = Step::Anchor;
    {
        let inventory = retained_tree_inventory_data_v1(source)?;
        let observed = SelectedSourceV3::observe(&inventory, purpose.source_uid()?, project, *recipe)?;
        observed.latch_observation(2, first_site);
        let returned = exchange_phase(&controller, &observed, &purpose, core, generation, signer, Wire::Anchor, Wire::Anchored, anchor_io, Step::Anchor, first_site);
        observed.retain_evidence(&mut source_evidence[2]);
        returned?;
    }
    let floor = purpose.anchored(&anchor_io.reply, &prepared)?;

    *phase = Step::Acknowledge;
    {
        let inventory = retained_tree_inventory_data_v1(source)?;
        let observed = SelectedSourceV3::observe(&inventory, purpose.source_uid()?, project, *recipe)?;
        observed.latch_observation(3, first_site);
        let returned = controller.append_anchored(&observed, &floor, anchored);
        if returned.is_err() { first_site.get_or_insert(ResidentFailureSiteV2::Anchored); }
        park_owner_post(owner_posts, first_site, None, observed.recheck());
        park_owner_post(owner_posts, first_site, None, floor.recheck());
        park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
        park_clock_post(clock_posts, first_site, None, purpose.observe_original_clock());
        observed.retain_evidence(&mut source_evidence[3]);
        if returned.is_err() || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::AdmissionClosed); }
        if clock_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    }
    let returned = floor.acknowledge(source, &controller, ack);
    if returned.is_err() { first_site.get_or_insert(ResidentFailureSiteV2::SourceAck); }
    park_owner_post(owner_posts, first_site, None, controller.recheck());
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, floor.recheck());
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    park_clock_post(clock_posts, first_site, None, purpose.observe_original_clock());
    if returned.is_err() || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    if clock_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }

    *phase = Step::Complete;
    {
        let inventory = retained_tree_inventory_data_v1(source)?;
        let observed = SelectedSourceV3::observe(&inventory, purpose.source_uid()?, project, *recipe)?;
        observed.latch_observation(4, first_site);
        let returned = controller.append_complete(&observed, &floor, complete);
        if returned.is_err() { first_site.get_or_insert(ResidentFailureSiteV2::Complete); }
        park_owner_post(owner_posts, first_site, None, observed.recheck());
        park_owner_post(owner_posts, first_site, None, floor.recheck());
        park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
        park_clock_post(clock_posts, first_site, None, purpose.observe_original_clock());
        let phase_result = if returned.is_err() || owner_posts.iter().any(Result::is_err) {
            Err(SourceGenesisErrorV1::AdmissionClosed)
        } else if clock_posts.iter().any(Result::is_err) {
            Err(SourceGenesisErrorV1::Stale)
        } else {
            exchange_phase(&controller, &observed, &purpose, core, generation, signer, Wire::Complete, Wire::Completed, complete_io, Step::Complete, first_site)
        };
        observed.retain_evidence(&mut source_evidence[4]);
        phase_result?;
    }
    let completed = purpose.completed(&complete_io.reply, &floor, &controller)?;

    *phase = Step::Finish;
    {
        let inventory = retained_tree_inventory_data_v1(source)?;
        let observed = SelectedSourceV3::observe(&inventory, purpose.source_uid()?, project, *recipe)?;
        observed.latch_observation(5, first_site);
        let returned = completed.consume(&controller, &observed, &inventory);
        observed.retain_evidence(&mut source_evidence[5]);
        returned?;
    }
    let payload = completed.finish_payload();
    controller.recheck()?;
    source.require_fixed_named_writer_v1()?;
    profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
    completed.recheck()?;
    finish_io.sent = Some((|| {
        purpose.encode(&mut finish_io.frame, Wire::Finish, &payload)?;
        core.write_first_successor(&finish_io.frame)
    })());
    if matches!(finish_io.sent, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(Step::Finish, PhaseFailureSiteV2::Sent));
    }
    park_owner_post(owner_posts, first_site, None, controller.recheck());
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    park_clock_post(clock_posts, first_site, None, purpose.observe_original_clock());
    if !matches!(finish_io.sent, Some(Ok(()))) || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    if clock_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    finish_io.reception = Some(core.receive_first_successor_finish(128, &mut finish_io.reply, &mut finish_io.received));
    if matches!(finish_io.received, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(Step::Finish, PhaseFailureSiteV2::Received));
    } else if matches!(finish_io.reception, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(Step::Finish, PhaseFailureSiteV2::Reception));
    }
    park_owner_post(owner_posts, first_site, None, controller.recheck());
    park_owner_post(owner_posts, first_site, None, source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
    park_owner_post(owner_posts, first_site, None, profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
    park_owner_post(owner_posts, first_site, None, core.first_successor_terminal_recheck());
    park_clock_post(clock_posts, first_site, None, purpose.observe_original_clock());
    if !matches!(finish_io.reception, Some(Ok(()))) || owner_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    if clock_posts.iter().any(Result::is_err) { return Err(SourceGenesisErrorV1::Stale); }
    if purpose.decode(&finish_io.reply, Wire::Finish)? != payload {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(Some(floor.floor().digest()))
}

#[allow(clippy::too_many_arguments)]
fn exchange_phase(
    controller: &SelectedControllerV3<'_>, source: &SelectedSourceV3<'_>,
    purpose: &SelectedPurposeV3<'_>,
    core: &super::flight::OriginalRootGenesisFlightV1<'_>, generation: u64, signer: &SigningKey,
    send: super::wire::RootFirstSourceSuccessorFrameKindV2,
    receive: super::wire::RootFirstSourceSuccessorFrameKindV2,
    results: &mut OriginalPhaseResultsV2,
    phase: FirstSourceSuccessorConsumerPhaseV2, first_site: &mut Option<ResidentFailureSiteV2>,
) -> Result<(), SourceGenesisErrorV1> {
    results.signature = Some(match (controller, source, purpose) {
        (SelectedControllerV3::Strict(controller), SelectedSourceV3::Strict(source), SelectedPurposeV3::Strict(purpose)) => sign_controller_first_successor_readback_v2(controller, source, purpose, generation, signer),
        (SelectedControllerV3::Mixed(controller), SelectedSourceV3::Mixed(source), SelectedPurposeV3::Mixed(purpose)) => sign_controller_project_successor_readback_v3(controller, source, purpose, generation, signer),
        _ => Err(SourceGenesisErrorV1::Conflict),
    });
    if matches!(results.signature, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(phase, PhaseFailureSiteV2::Signature));
    }
    park_owner_post(&mut results.posts, first_site, Some(phase), controller.recheck());
    park_owner_post(&mut results.posts, first_site, Some(phase), source.recheck());
    park_owner_post(&mut results.posts, first_site, Some(phase), purpose.view().recheck());
    park_clock_post(&mut results.clock_posts, first_site, Some(phase), purpose.observe_original_clock());
    if results.error().is_some() { return Err(SourceGenesisErrorV1::Stale); }
    let packet = results.signature.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    results.sent = Some((|| {
        purpose.encode(&mut results.frame, send, packet)?;
        core.write_first_successor(&results.frame)
    })());
    if matches!(results.sent, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(phase, PhaseFailureSiteV2::Sent));
    }
    park_owner_post(&mut results.posts, first_site, Some(phase), controller.recheck());
    park_owner_post(&mut results.posts, first_site, Some(phase), source.recheck());
    park_owner_post(&mut results.posts, first_site, Some(phase), purpose.view().recheck());
    park_clock_post(&mut results.clock_posts, first_site, Some(phase), purpose.observe_original_clock());
    if results.error().is_some() { return Err(SourceGenesisErrorV1::Stale); }
    results.reception = Some(core.receive_first_successor_exact(32 + receive.payload_bytes(), &mut results.reply, &mut results.received));
    if matches!(results.received, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(phase, PhaseFailureSiteV2::Received));
    } else if matches!(results.reception, Some(Err(_))) {
        first_site.get_or_insert(ResidentFailureSiteV2::Phase(phase, PhaseFailureSiteV2::Reception));
    }
    park_owner_post(&mut results.posts, first_site, Some(phase), controller.recheck());
    park_owner_post(&mut results.posts, first_site, Some(phase), source.recheck());
    park_owner_post(&mut results.posts, first_site, Some(phase), purpose.view().recheck());
    park_clock_post(&mut results.clock_posts, first_site, Some(phase), purpose.observe_original_clock());
    if results.error().is_some() { Err(SourceGenesisErrorV1::Stale) } else { Ok(()) }
}

/// Retains the actual mutable Controller writer and exact native phase.
///
/// Its approval and phase getters are DATA. Only its typed native methods,
/// joined to the original Source and Root loans, can mutate this Journal.
pub struct HeldControllerFirstSourceSuccessorV2<'controller> {
    journal: RefCell<&'controller mut Journal>,
    packet: SourceSuccessorApprovalDataV2,
    begin: ControllerFirstSourceSuccessorBeginV2,
    begin_durable: bool,
    anchored: Option<ControllerFirstSourceSuccessorAnchoredV2>,
    complete: Option<ControllerFirstSourceSuccessorCompleteV2>,
    uid: u32,
    names: ProtectedJournalNamesV1,
    seed_file: &'controller PinnedSystemdCredential,
    authorization_file: &'controller PinnedSystemdCredential,
    recipe: IssuanceKeyRecipeV3,
    comparison: ControllerSuccessorSignatureRecipeV3,
}

/// Holds the actual project-scoped writer without a strict-v2 conversion.
pub struct HeldControllerProjectSuccessorV3<'controller> {
    common: HeldControllerFirstSourceSuccessorV2<'controller>,
}

#[derive(Clone, Copy)]
pub(crate) enum ControllerSuccessorOwnerViewV3<'loan, 'controller> {
    Strict(&'loan HeldControllerFirstSourceSuccessorV2<'controller>),
    Mixed(&'loan HeldControllerProjectSuccessorV3<'controller>),
}

impl<'loan, 'controller> ControllerSuccessorOwnerViewV3<'loan, 'controller> {
    fn data(&self) -> &HeldControllerFirstSourceSuccessorV2<'controller> {
        match self { Self::Strict(owner) => owner, Self::Mixed(owner) => &owner.common }
    }

    pub(crate) fn packet(&self) -> &SourceSuccessorApprovalDataV2 { self.data().packet() }
    pub(crate) fn begin(&self) -> &ControllerFirstSourceSuccessorBeginV2 { self.data().begin() }
    pub(crate) fn anchored(&self) -> Option<&ControllerFirstSourceSuccessorAnchoredV2> { self.data().anchored() }
    pub(crate) fn complete(&self) -> Option<&ControllerFirstSourceSuccessorCompleteV2> { self.data().complete() }
    pub(crate) fn source_uid(&self) -> u32 { self.data().source_uid() }
    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.data().recheck() }
    pub(crate) fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> { self.data().recheck_current_admission() }
}

impl HeldControllerProjectSuccessorV3<'_> {
    /// Borrows the genuine independently issued selected approval DATA.
    pub fn packet(&self) -> &SourceSuccessorApprovalDataV2 { self.common.packet() }
    /// Borrows the exact selected native Begin DATA.
    pub fn begin(&self) -> &ControllerFirstSourceSuccessorBeginV2 { self.common.begin() }
    /// Borrows the settled selected Controller Anchored DATA.
    pub fn anchored(&self) -> Option<&ControllerFirstSourceSuccessorAnchoredV2> { self.common.anchored() }
    /// Borrows the settled selected Controller Complete DATA.
    pub fn complete(&self) -> Option<&ControllerFirstSourceSuccessorCompleteV2> { self.common.complete() }
    /// Returns the UID compared with the actual Source writer and Root peer.
    pub fn source_uid(&self) -> u32 { self.common.source_uid() }
    /// Rechecks the genuine writer, credentials and every retained history.
    ///
    /// # Errors
    /// Rejects stale names, phase, credentials or selected predecessor joins.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck() }
    /// Rechecks current policy and the original signed admission bounds.
    ///
    /// # Errors
    /// Rejects changed current policy, boot or original expiry; never renews D.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck_current_admission() }

    pub(super) fn uid(&self) -> u32 { self.common.uid() }
    pub(super) fn append_begin(&mut self, results: &mut ControllerFirstSuccessorMutationResultsV2) -> Result<(), ()> { self.common.append_begin(results) }

    pub(super) fn append_anchored(
        &mut self, source: &crate::hierarchy::SourceProjectContinuationObservationV3<'_>,
        root: &super::successor_flight::RootProjectSuccessorFloorProofV3<'_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        self.common.append_anchored_with_recipe_v3(SourceSuccessorObservationViewV3::Mixed(source),
            super::successor_flight::RootSuccessorFloorViewV3::Mixed(root), results)
    }

    pub(super) fn append_complete(
        &mut self, source: &crate::hierarchy::SourceProjectContinuationObservationV3<'_>,
        root: &super::successor_flight::RootProjectSuccessorFloorProofV3<'_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        self.common.append_complete_with_recipe_v3(SourceSuccessorObservationViewV3::Mixed(source),
            super::successor_flight::RootSuccessorFloorViewV3::Mixed(root), results)
    }
}

pub(crate) fn hold_retained_first_source_successor_v2<'controller>(
    journal: &'controller mut Journal,
    seed_file: &'controller PinnedSystemdCredential,
    authorization_file: &'controller PinnedSystemdCredential,
    inventory: &RetainedTreeInventoryDataV1<'_>,
) -> Result<HeldControllerFirstSourceSuccessorV2<'controller>, SourceGenesisErrorV1> {
    hold_successor_with_recipe_v3(journal, seed_file, authorization_file, inventory, IssuanceKeyRecipeV3::GlobalV2, ControllerSuccessorSignatureRecipeV3::StrictV2, None)
}

fn hold_retained_global_predecessor_v3<'controller>(
    journal: &'controller mut Journal, seed_file: &'controller PinnedSystemdCredential,
    authorization_file: &'controller PinnedSystemdCredential, inventory: &RetainedTreeInventoryDataV1<'_>,
    evidence: &mut Option<crate::hierarchy::SourceProjectContinuationEvidenceV3>,
) -> Result<HeldControllerProjectSuccessorV3<'controller>, SourceGenesisErrorV1> {
    hold_successor_with_recipe_v3(journal, seed_file, authorization_file, inventory, IssuanceKeyRecipeV3::GlobalV2, ControllerSuccessorSignatureRecipeV3::MixedV3, Some(evidence))
        .map(|common| HeldControllerProjectSuccessorV3 { common })
}

pub(crate) fn hold_retained_project_successor_v3<'controller>(
    journal: &'controller mut Journal,
    seed_file: &'controller PinnedSystemdCredential,
    authorization_file: &'controller PinnedSystemdCredential,
    inventory: &RetainedTreeInventoryDataV1<'_>, project: ProjectId,
    evidence: &mut Option<crate::hierarchy::SourceProjectContinuationEvidenceV3>,
) -> Result<HeldControllerProjectSuccessorV3<'controller>, SourceGenesisErrorV1> {
    hold_successor_with_recipe_v3(journal, seed_file, authorization_file, inventory, IssuanceKeyRecipeV3::ProjectV3(project), ControllerSuccessorSignatureRecipeV3::MixedV3, Some(evidence))
        .map(|common| HeldControllerProjectSuccessorV3 { common })
}

fn hold_successor_with_recipe_v3<'controller>(
    journal: &'controller mut Journal,
    seed_file: &'controller PinnedSystemdCredential,
    authorization_file: &'controller PinnedSystemdCredential,
    inventory: &RetainedTreeInventoryDataV1<'_>, recipe: IssuanceKeyRecipeV3,
    comparison: ControllerSuccessorSignatureRecipeV3,
    evidence: Option<&mut Option<crate::hierarchy::SourceProjectContinuationEvidenceV3>>,
) -> Result<HeldControllerFirstSourceSuccessorV2<'controller>, SourceGenesisErrorV1> {
    let mut mixed = None;
    let validation = (|| {
    let uid = journal.protected_owner_uid()?;
    require_controller(journal, uid)?;
    let saved = match recipe {
        IssuanceKeyRecipeV3::GlobalV2 => issuance::retained(journal)?,
        IssuanceKeyRecipeV3::ProjectV3(project) => issuance::retained_project_v3(journal, project)?,
    }.ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    if !saved.delivered {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    let packet = saved.packet;
    let body = packet.body();
    let intent = packet.intent()?;
    let source_uid = first_source_successor_inventory_uid_v2(inventory)?;
    let strict;
    let source = match comparison {
        ControllerSuccessorSignatureRecipeV3::StrictV2 => {
            strict = observe_source_first_successor_v2(inventory, source_uid, intent.project())?;
            SourceSuccessorObservationViewV3::Strict(&strict)
        }
        ControllerSuccessorSignatureRecipeV3::MixedV3 => {
            if matches!(recipe, IssuanceKeyRecipeV3::ProjectV3(project) if project != intent.project()) { return Err(SourceGenesisErrorV1::Conflict); }
            mixed = Some(observe_source_project_continuation_v3(inventory, source_uid, intent.project()));
            let observed = mixed.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
            observed.recheck()?;
            SourceSuccessorObservationViewV3::Mixed(observed)
        }
    };
    let original = source.genesis_receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
    let predecessor = SourceHierarchyFloorRecordV1::new(original.clone(), digest_at(body, 112))?;
    if source.genesis_root_floor() != Some(predecessor.digest())
        || predecessor.digest() != digest_at(body, 144)
        || predecessor.instance() != take::<32>(body, 32)?
        || original.tree_head() != digest_at(body, 536)
        || original.lineage_head() != digest_at(body, 568)
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let genesis_complete = {
        let original_controller = hold_existing_completed_source_genesis_v2(journal, intent.project())?;
        if original_controller.acceptance().seed_packet() != &original.seed_packet()
            || original_controller.acceptance().auth_packet() != &original.auth_packet()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let complete = original_controller.completed_record_commitment_v2()?;
        if complete != digest_at(body, 176) {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        complete
    };
    let begin_durable = saved.begin.is_some();
    let begin = match saved.begin {
        Some(begin) => begin,
        None => ControllerFirstSourceSuccessorBeginV2::new(ControllerFirstSourceSuccessorBeginFieldsV2 {
            approval: packet.digest(), predecessor_floor: predecessor.digest(), genesis_complete,
            old_tree_head: original.tree_head(), old_lineage_head: original.lineage_head(),
            next_tree_commit: digest_at(body, 680), source_uid, source_names: source.names()?,
        })?,
    };
    if begin.source_uid() != source_uid || begin.approval() != packet.digest()
        || (source.state()? != SourceFirstSuccessorStateV2::Anchored && begin.source_names() != source.names()?)
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    if source.state()? == SourceFirstSuccessorStateV2::Before {
        let (tree, tree_head, lineage_head) = inventory.trees()?
            .find(|(tree, _, _)| tree.project() == intent.project())
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        let next = tree.insert(SandboxTreeRecordV1::new(
            intent.project(), intent.sandbox(), None, DesiredGeneration::new(1), None,
        ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?, tree.tree_generation(), None)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        if tree_head != begin.old_tree_head() || lineage_head != begin.old_lineage_head()
            || tree_commitment_v1(tree).map_err(|_| SourceGenesisErrorV1::NonCanonical)? != digest_at(body, 600)
            || tree_commitment_v1(&next).map_err(|_| SourceGenesisErrorV1::NonCanonical)? != begin.next_tree_commit()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
    } else {
        let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
        if receipt.approval() != packet.digest() || receipt.begin() != begin.digest()
            || receipt.next_tree_commit() != begin.next_tree_commit()
            || receipt.old_tree_commit() != digest_at(body, 600)
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
    }
    let names = journal.protected_writer_physical_names_v1()?;
    let held = HeldControllerFirstSourceSuccessorV2 {
        journal: RefCell::new(journal), packet, begin,
        begin_durable, anchored: saved.anchored, complete: saved.complete,
        uid, names,
        seed_file, authorization_file, recipe, comparison,
    };
    held.recheck()?;
    if source.state()? == SourceFirstSuccessorStateV2::Before {
        held.recheck_current_admission()?;
    }
    inventory.recheck()?;
    Ok(held)
    })();
    // The returned validation and all Source evidence remain independent. An
    // Err ends only the short Journal loan; no decoded maps or cause disappear.
    if let (Some(observed), Some(destination)) = (mixed, evidence) {
        *destination = Some(observed.into_evidence_v3());
    }
    validation
}

impl HeldControllerFirstSourceSuccessorV2<'_> {
    /// Borrows the exact genuinely retained delivered approval DATA.
    pub const fn packet(&self) -> &SourceSuccessorApprovalDataV2 { &self.packet }

    /// Borrows the exact native Begin DATA.
    pub const fn begin(&self) -> &ControllerFirstSourceSuccessorBeginV2 { &self.begin }

    /// Borrows the current durable Controller Anchored DATA, if present.
    pub fn anchored(&self) -> Option<&ControllerFirstSourceSuccessorAnchoredV2> { self.anchored.as_ref() }

    /// Borrows the current durable Controller Complete DATA, if present.
    pub fn complete(&self) -> Option<&ControllerFirstSourceSuccessorCompleteV2> { self.complete.as_ref() }

    /// Returns the Source UID from the exact native Begin.
    pub fn source_uid(&self) -> u32 { self.begin.source_uid() }

    pub(super) const fn uid(&self) -> u32 { self.uid }

    /// Rejoins the same named mutable writer, pins and durable native phase.
    ///
    /// # Errors
    /// Rejects changed custody, credentials, approval or phase provenance.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.seed_file.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.authorization_file.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let seed = PinnedControllerSourceTreeSeedIssuerV1::decode(self.seed_file.bytes())?;
        let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(self.authorization_file.bytes())?;
        if seed.generation() != u64::from_be_bytes(take(self.packet.body(), 16)?)
            || seed.verifying_key() == authorization.verifying_key()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.packet.verify_signature(seed.verifying_key())?;
        verify_signed_project_authorization_claims_v2(&self.packet.body()[312..536], &authorization)?;
        let mut journal = self.journal.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_controller(&journal, self.uid)?;
        if journal.protected_writer_physical_names_v1()? != self.names {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let rows = match self.recipe {
            IssuanceKeyRecipeV3::GlobalV2 => issuance::retained(&journal)?,
            IssuanceKeyRecipeV3::ProjectV3(project) => issuance::retained_project_v3(&journal, project)?,
        }.ok_or(SourceGenesisErrorV1::Stale)?;
        if !rows.delivered || rows.packet != self.packet
            || rows.begin.as_ref() != self.begin_durable.then_some(&self.begin)
            || rows.anchored != self.anchored || rows.complete != self.complete
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let original = hold_existing_completed_source_genesis_v2(&mut journal, self.packet.intent()?.project())?;
        if original.completed_record_commitment_v2()? != self.begin.genesis_complete() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Ok(())
    }

    /// Rechecks genuine current policy and the original nonrenewable approval.
    ///
    /// Historical settlement uses [`Self::recheck`] instead of this admission.
    ///
    /// # Errors
    /// Rejects changed current authorization, boot, clock continuity or expiry.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let body = self.packet.body();
        {
            let mut journal = self.journal.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
            journal.require_git_coverage_new_admission_v1()?;
            let original = hold_existing_completed_source_genesis_v2(&mut journal, self.packet.intent()?.project())?;
            let (generation, head, revision, auth_head, limits, packet) = original.current_successor_authorization_v2()?;
            let current = crate::publisher_policy::parse_unverified_project_authorization_claims_v2(&body[312..536])?;
            if generation != u64::from_be_bytes(take(body, 208)?) || head != digest_at(body, 216)
                || revision != digest_at(body, 248) || auth_head != digest_at(body, 280)
                || packet.as_slice() != &body[312..536] || limits != current.limits
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
        }
        self.recheck()?;
        require_approval_clock(&self.packet, super::flight::kernel_pair()?)
    }

    // The same writer is already mutably borrowed by the native engine. Do
    // not recurse through its RefCell or replace the held pins with DATA.
    pub(crate) fn native_begin_crossing_v3(&self, journal: &mut Journal) -> Result<(), SourceGenesisErrorV1> {
        if self.comparison != ControllerSuccessorSignatureRecipeV3::MixedV3 || self.begin_durable {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.seed_file.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.authorization_file.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let seed = PinnedControllerSourceTreeSeedIssuerV1::decode(self.seed_file.bytes())?;
        let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(self.authorization_file.bytes())?;
        let body = self.packet.body();
        if seed.generation() != u64::from_be_bytes(take(body, 16)?)
            || seed.verifying_key() == authorization.verifying_key()
        { return Err(SourceGenesisErrorV1::Conflict); }
        self.packet.verify_signature(seed.verifying_key())?;
        verify_signed_project_authorization_claims_v2(&body[312..536], &authorization)?;
        require_controller(journal, self.uid)?;
        if journal.protected_writer_physical_names_v1()? != self.names {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let rows = match self.recipe {
            IssuanceKeyRecipeV3::GlobalV2 => issuance::retained(journal)?,
            IssuanceKeyRecipeV3::ProjectV3(project) => issuance::retained_project_v3(journal, project)?,
        }.ok_or(SourceGenesisErrorV1::Stale)?;
        if !rows.delivered || rows.packet != self.packet || rows.begin.is_some()
            || rows.anchored != self.anchored || rows.complete != self.complete
        { return Err(SourceGenesisErrorV1::Stale); }
        journal.require_git_coverage_new_admission_v1()?;
        {
            let original = hold_existing_completed_source_genesis_v2(journal, self.packet.intent()?.project())?;
            if original.completed_record_commitment_v2()? != self.begin.genesis_complete() {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            let (generation, head, revision, auth_head, limits, packet) = original.current_successor_authorization_v2()?;
            let current = crate::publisher_policy::parse_unverified_project_authorization_claims_v2(&body[312..536])?;
            if generation != u64::from_be_bytes(take(body, 208)?) || head != digest_at(body, 216)
                || revision != digest_at(body, 248) || auth_head != digest_at(body, 280)
                || packet.as_slice() != &body[312..536] || limits != current.limits
            { return Err(SourceGenesisErrorV1::Stale); }
        }
        require_approval_clock(&self.packet, super::flight::kernel_pair()?)
    }

    fn sequence(&self) -> Result<u64, SourceGenesisErrorV1> {
        self.recheck()?;
        Ok(self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?.snapshot_sequence())
    }
}

pub(super) fn require_approval_clock(
    packet: &SourceSuccessorApprovalDataV2,
    clock: aos_sandbox_core::RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    let body = packet.body();
    let issued = u64::from_be_bytes(take(body, 736)?);
    let expires = u64::from_be_bytes(take(body, 744)?);
    let issued_boottime = u64::from_be_bytes(take(body, 728)?);
    let wall = u64::try_from(clock.wall_seconds()).map_err(|_| SourceGenesisErrorV1::Stale)?;
    let boot_deadline = issued_boottime.checked_add(
        expires.checked_sub(issued).ok_or(SourceGenesisErrorV1::NonCanonical)?
            .checked_mul(1_000_000_000).ok_or(SourceGenesisErrorV1::NonCanonical)?,
    ).ok_or(SourceGenesisErrorV1::NonCanonical)?;
    if take::<16>(body, 712)? != clock.host_boot_id() || wall < issued || wall >= expires
        || clock.boottime_nanoseconds() < issued_boottime || clock.boottime_nanoseconds() >= boot_deadline
    {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    let original = aos_sandbox_core::RawPairedClockSample::new_untrusted(
        clock.provenance(), take(body, 712)?, i64::try_from(issued).map_err(|_| SourceGenesisErrorV1::NonCanonical)?, issued_boottime,
    ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    original.validate_later_sample(clock).map_err(|_| SourceGenesisErrorV1::Stale)?;
    Ok(())
}

#[derive(Default)]
pub(super) struct ControllerFirstSuccessorMutationResultsV2 {
    attempted: bool,
    transactions: Vec<JournalTransaction>,
    preparation: Option<Result<(), SourceGenesisErrorV1>>,
    preflight: Option<Result<(), JournalError>>,
    crossing: Option<Result<(), SourceGenesisErrorV1>>,
    crossing_clock: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    native: Option<Result<CommitResult, JournalError>>,
    post: Option<Result<(), SourceGenesisErrorV1>>,
    clock_post: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
}

impl ControllerFirstSuccessorMutationResultsV2 {
    fn failed(&self) -> bool {
        matches!(self.preparation, Some(Err(_))) || matches!(self.preflight, Some(Err(_)))
            || matches!(self.crossing, Some(Err(_)))
            || matches!(self.crossing_clock, Some(Err(_)))
            || matches!(self.native, Some(Err(_))) || matches!(self.post, Some(Err(_)))
            || matches!(self.clock_post, Some(Err(_)))
    }

    pub(super) fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.preparation { return Some(error); }
        if let Some(Err(error)) = &self.preflight { return Some(error); }
        if let Some(Err(error)) = &self.crossing { return Some(error); }
        if let Some(Err(error)) = &self.crossing_clock { return Some(error); }
        if let Some(Err(error)) = &self.native { return Some(error); }
        if let Some(Err(error)) = &self.post { return Some(error); }
        if let Some(Err(error)) = &self.clock_post { return Some(error); }
        None
    }
}

impl HeldControllerFirstSourceSuccessorV2<'_> {
    fn phase_v3(&self, phase: NativePhase) -> NativePhase {
        match (self.comparison, phase) {
            (ControllerSuccessorSignatureRecipeV3::MixedV3, NativePhase::ControllerBegin) => NativePhase::MixedControllerBegin,
            (ControllerSuccessorSignatureRecipeV3::MixedV3, NativePhase::ControllerAnchored) => NativePhase::MixedControllerAnchored,
            (ControllerSuccessorSignatureRecipeV3::MixedV3, NativePhase::ControllerComplete) => NativePhase::MixedControllerComplete,
            _ => phase,
        }
    }

    fn key_v3(&self, suffix: &[u8]) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        match self.recipe {
            IssuanceKeyRecipeV3::GlobalV2 => Ok(issuance::key(suffix)),
            IssuanceKeyRecipeV3::ProjectV3(project) => issuance::project_key_v3(project, suffix).map_err(Into::into),
        }
    }

    fn capacity_request_v3(&self) -> Result<crate::journal::GlobalCapacityReservationRequestV1, JournalError> {
        match self.recipe {
            IssuanceKeyRecipeV3::GlobalV2 => controller_capacity_request(&self.packet, &self.begin),
            recipe => issuance::controller_capacity_request_with_recipe(&self.packet, &self.begin, recipe),
        }
    }

    pub(super) fn append_begin(&mut self, results: &mut ControllerFirstSuccessorMutationResultsV2) -> Result<(), ()> {
        if results.attempted { return Err(()); }
        results.attempted = true;
        results.preparation = Some((|| {
            self.recheck()?;
            if self.begin_durable { return Ok(()); }
            self.recheck_current_admission()?;
            let request = self.capacity_request_v3()?;
            let admission = transaction_id(self.packet.digest(), NativePhase::ControllerBegin);
            let reservation = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?
                .prepare_first_source_successor_capacity_v2(&request, admission)?;
            results.transactions.push(JournalTransaction::new(admission, vec![
                JournalRecord::put(RecordNamespace::DesiredState, self.key_v3(b"consumer-begin")?, self.begin.as_bytes().to_vec()),
                reservation,
            ])?);
            // Canonical prospective DATA prices the whole fixed suffix. The
            // genuine Source receipt and Root loan replace these comparisons
            // before either actual settlement append can be selected.
            let prospective = ControllerFirstSourceSuccessorAnchoredV2::new(ControllerFirstSourceSuccessorAnchoredFieldsV2 {
                approval: self.packet.digest(), receipt: ObjectDigest::from_bytes([1; 32]),
                floor: ObjectDigest::from_bytes([2; 32]),
            })?;
            let ack = SourceFirstSuccessorAckV2::new(SourceFirstSuccessorAckFieldsV2 {
                instance: take(self.packet.body(), 32)?, project: self.packet.intent()?.project(),
                receipt: prospective.receipt(), root_floor: prospective.floor(), controller_anchored: prospective.digest(),
            })?;
            let complete = ControllerFirstSourceSuccessorCompleteV2::new(ControllerFirstSourceSuccessorCompleteFieldsV2 {
                approval: self.packet.digest(), receipt: prospective.receipt(), floor: prospective.floor(),
                ack: ack.digest(), begin: self.begin.digest(), anchored: prospective.digest(),
            })?;
            results.transactions.push(JournalTransaction::new(transaction_id(self.packet.digest(), NativePhase::ControllerAnchored), vec![
                JournalRecord::put(RecordNamespace::DesiredState, self.key_v3(b"consumer-anchored")?, prospective.as_bytes().to_vec()),
            ])?);
            let reservation = results.transactions[0].records()[1].clone();
            results.transactions.push(JournalTransaction::new(transaction_id(self.packet.digest(), NativePhase::ControllerComplete), vec![
                JournalRecord::put(RecordNamespace::DesiredState, self.key_v3(b"consumer-complete")?, complete.as_bytes().to_vec()),
                JournalRecord::delete(reservation.namespace(), reservation.key().to_vec()),
            ])?);
            Ok(())
        })());
        if matches!(results.preparation, Some(Ok(()))) && !results.transactions.is_empty() {
            results.preflight = Some(self.journal.try_borrow().map_err(|_| JournalError::ProtectedBoundary)
                .and_then(|journal| journal.preflight_first_source_successor_v2(&results.transactions, &[
                    self.phase_v3(NativePhase::ControllerBegin), self.phase_v3(NativePhase::ControllerAnchored), self.phase_v3(NativePhase::ControllerComplete),
                ])));
            if matches!(results.preflight, Some(Ok(()))) {
                // Current policy/clock follows the potentially slow preview.
                results.crossing = Some(self.recheck_current_admission());
                if matches!(results.crossing, Some(Ok(()))) {
                    results.native = Some(self.journal.try_borrow_mut().map_err(|_| JournalError::ProtectedBoundary)
                        .and_then(|mut journal| match self.comparison {
                            ControllerSuccessorSignatureRecipeV3::StrictV2 => journal.commit_first_source_successor_v2(&results.transactions[0], self.phase_v3(NativePhase::ControllerBegin)),
                            ControllerSuccessorSignatureRecipeV3::MixedV3 => journal.commit_selected_source_successor_v3(
                                &results.transactions[0], self.phase_v3(NativePhase::ControllerBegin),
                                crate::journal::source_tree_successor::FirstSuccessorNativeCutV3::ControllerBegin(self),
                            ),
                        }));
                }
                if matches!(results.native, Some(Ok(_))) { self.begin_durable = true; }
            }
        }
        results.post = Some(self.recheck());
        if self.comparison == ControllerSuccessorSignatureRecipeV3::MixedV3 {
            results.clock_post = Some(super::flight::kernel_pair().and_then(|clock| {
                require_approval_clock(&self.packet, clock)?;
                Ok(clock)
            }));
        }
        if results.failed() { Err(()) } else { Ok(()) }
    }

    pub(super) fn append_anchored(
        &mut self, source: &HeldSourceFirstSuccessorObservationV2<'_>,
        root: &super::successor_flight::RootFirstSourceSuccessorFloorProofV2<'_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        self.append_anchored_with_recipe_v3(SourceSuccessorObservationViewV3::Strict(source),
            super::successor_flight::RootSuccessorFloorViewV3::Strict(root), results)
    }

    fn append_anchored_with_recipe_v3(
        &mut self, source: SourceSuccessorObservationViewV3<'_, '_>,
        root: super::successor_flight::RootSuccessorFloorViewV3<'_, '_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        if results.attempted { return Err(()); }
        results.attempted = true;
        let mut expected = None;
        results.preparation = Some((|| {
            self.recheck()?;
            source.recheck()?;
            root.recheck()?;
            let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
            if root.floor().receipt() != receipt || receipt.begin() != self.begin.digest()
                || receipt.approval() != self.packet.digest() || source.source_uid()? != self.source_uid()
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            let anchored = ControllerFirstSourceSuccessorAnchoredV2::new(ControllerFirstSourceSuccessorAnchoredFieldsV2 {
                approval: self.packet.digest(), receipt: receipt.digest(), floor: root.floor().digest(),
            })?;
            expected = Some(anchored.clone());
            if let Some(existing) = &self.anchored {
                if existing != &anchored { return Err(SourceGenesisErrorV1::Conflict); }
                return Ok(());
            }
            results.transactions.push(JournalTransaction::new(transaction_id(self.packet.digest(), NativePhase::ControllerAnchored), vec![
                JournalRecord::put(RecordNamespace::DesiredState, self.key_v3(b"consumer-anchored")?, anchored.as_bytes().to_vec()),
            ])?);
            // Price the entire still-eligible Controller suffix with actual
            // receipt/floor joins. The prospective ACK is canonical sizing
            // DATA only; actual completion later requires Source's native ACK.
            let ack = SourceFirstSuccessorAckV2::new(SourceFirstSuccessorAckFieldsV2 {
                instance: receipt.instance(), project: receipt.project(), receipt: receipt.digest(),
                root_floor: root.floor().digest(), controller_anchored: anchored.digest(),
            })?;
            let complete = ControllerFirstSourceSuccessorCompleteV2::new(ControllerFirstSourceSuccessorCompleteFieldsV2 {
                approval: self.packet.digest(), receipt: receipt.digest(), floor: root.floor().digest(),
                ack: ack.digest(), begin: self.begin.digest(), anchored: anchored.digest(),
            })?;
            let request = self.capacity_request_v3()?;
            let deletion = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?
                .first_source_successor_capacity_deletion_v2(&request, transaction_id(self.packet.digest(), NativePhase::ControllerBegin))?;
            results.transactions.push(JournalTransaction::new(transaction_id(self.packet.digest(), NativePhase::ControllerComplete), vec![
                JournalRecord::put(RecordNamespace::DesiredState, self.key_v3(b"consumer-complete")?, complete.as_bytes().to_vec()), deletion,
            ])?);
            Ok(())
        })());
        self.commit_settlement(source, root, results, NativePhase::ControllerAnchored);
        if matches!(results.native, Some(Ok(_))) { self.anchored = expected; }
        results.post = Some(self.recheck());
        results.clock_post = Some(root.observe_original_clock());
        if results.failed() { Err(()) } else { Ok(()) }
    }

    pub(super) fn append_complete(
        &mut self, source: &HeldSourceFirstSuccessorObservationV2<'_>,
        root: &super::successor_flight::RootFirstSourceSuccessorFloorProofV2<'_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        self.append_complete_with_recipe_v3(SourceSuccessorObservationViewV3::Strict(source),
            super::successor_flight::RootSuccessorFloorViewV3::Strict(root), results)
    }

    fn append_complete_with_recipe_v3(
        &mut self, source: SourceSuccessorObservationViewV3<'_, '_>,
        root: super::successor_flight::RootSuccessorFloorViewV3<'_, '_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        if results.attempted { return Err(()); }
        results.attempted = true;
        let mut expected = None;
        results.preparation = Some((|| {
            self.recheck()?;
            source.recheck()?;
            root.recheck()?;
            let anchored = self.anchored.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
            let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
            let ack = source.ack().ok_or(SourceGenesisErrorV1::Conflict)?;
            if source.state()? != SourceFirstSuccessorStateV2::Anchored || root.floor().receipt() != receipt
                || anchored.receipt() != receipt.digest() || anchored.floor() != root.floor().digest()
                || ack.receipt() != receipt.digest() || ack.root_floor() != root.floor().digest()
                || ack.controller_anchored() != anchored.digest() || source.source_uid()? != self.source_uid()
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            let complete = ControllerFirstSourceSuccessorCompleteV2::new(ControllerFirstSourceSuccessorCompleteFieldsV2 {
                approval: self.packet.digest(), receipt: receipt.digest(), floor: root.floor().digest(),
                ack: ack.digest(), begin: self.begin.digest(), anchored: anchored.digest(),
            })?;
            expected = Some(complete.clone());
            if let Some(existing) = &self.complete {
                if existing != &complete { return Err(SourceGenesisErrorV1::Conflict); }
                return Ok(());
            }
            let request = self.capacity_request_v3()?;
            let deletion = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?
                .first_source_successor_capacity_deletion_v2(&request, transaction_id(self.packet.digest(), NativePhase::ControllerBegin))?;
            results.transactions.push(JournalTransaction::new(transaction_id(self.packet.digest(), NativePhase::ControllerComplete), vec![
                JournalRecord::put(RecordNamespace::DesiredState, self.key_v3(b"consumer-complete")?, complete.as_bytes().to_vec()), deletion,
            ])?);
            Ok(())
        })());
        self.commit_settlement(source, root, results, NativePhase::ControllerComplete);
        if matches!(results.native, Some(Ok(_))) { self.complete = expected; }
        results.post = Some(self.recheck());
        results.clock_post = Some(root.observe_original_clock());
        if results.failed() { Err(()) } else { Ok(()) }
    }

    fn commit_settlement(
        &self, source: SourceSuccessorObservationViewV3<'_, '_>,
        root: super::successor_flight::RootSuccessorFloorViewV3<'_, '_>,
        results: &mut ControllerFirstSuccessorMutationResultsV2, phase: NativePhase,
    ) {
        if matches!(results.preparation, Some(Ok(()))) && !results.transactions.is_empty() {
            let phases: &[NativePhase] = match (self.comparison, phase) {
                (ControllerSuccessorSignatureRecipeV3::StrictV2, NativePhase::ControllerAnchored) => &[NativePhase::ControllerAnchored, NativePhase::ControllerComplete],
                (ControllerSuccessorSignatureRecipeV3::StrictV2, NativePhase::ControllerComplete) => &[NativePhase::ControllerComplete],
                (ControllerSuccessorSignatureRecipeV3::MixedV3, NativePhase::ControllerAnchored) => &[NativePhase::MixedControllerAnchored, NativePhase::MixedControllerComplete],
                (ControllerSuccessorSignatureRecipeV3::MixedV3, NativePhase::ControllerComplete) => &[NativePhase::MixedControllerComplete],
                _ => { return; }
            };
            results.preflight = Some(self.journal.try_borrow().map_err(|_| JournalError::ProtectedBoundary)
                .and_then(|journal| journal.preflight_first_source_successor_v2(&results.transactions, phases)));
            if matches!(results.preflight, Some(Ok(()))) {
                // Settlement does not claim a fresh approval or renew D.
                results.crossing = Some((|| {
                    self.recheck()?;
                    source.recheck()?;
                    root.recheck()
                })());
                if matches!(results.crossing, Some(Ok(()))) {
                    results.crossing_clock = Some(root.observe_original_clock());
                }
                if matches!(results.crossing_clock, Some(Ok(_))) {
                    results.native = Some(self.journal.try_borrow_mut().map_err(|_| JournalError::ProtectedBoundary)
                        .and_then(|mut journal| match self.comparison {
                            ControllerSuccessorSignatureRecipeV3::StrictV2 => journal.commit_first_source_successor_v2(&results.transactions[0], self.phase_v3(phase)),
                            ControllerSuccessorSignatureRecipeV3::MixedV3 => journal.commit_selected_source_successor_v3(
                                &results.transactions[0], self.phase_v3(phase),
                                crate::journal::source_tree_successor::FirstSuccessorNativeCutV3::Settled(root),
                            ),
                        }));
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ControllerObservationPhaseV2 { Before, Prepared, Completed }

pub(super) struct VerifiedControllerFirstSuccessorObservationV2 {
    pub(super) phase: ControllerObservationPhaseV2,
    pub(super) packet: SourceSuccessorApprovalDataV2,
    pub(super) begin: ControllerFirstSourceSuccessorBeginV2,
    pub(super) root_intent: Option<ObjectDigest>,
    pub(super) receipt: Option<SourceFirstSuccessorReceiptV2>,
    pub(super) anchored: Option<ControllerFirstSourceSuccessorAnchoredV2>,
    pub(super) complete: Option<ControllerFirstSourceSuccessorCompleteV2>,
    pub(super) ack: Option<SourceFirstSuccessorAckV2>,
    pub(super) source_names: ProtectedJournalNamesV1,
    pub(super) source_sequence: u64,
}

// Comparison DATA only. The common parser is private; this wrapper does not
// export a strict-v2 live Controller/Source/Root loan or mutation entrypoint.
pub(super) struct VerifiedControllerFirstSuccessorObservationV3 {
    pub(super) data: VerifiedControllerFirstSuccessorObservationV2,
}

pub(super) fn sign_controller_first_successor_readback_v2(
    controller: &HeldControllerFirstSourceSuccessorV2<'_>,
    source: &HeldSourceFirstSuccessorObservationV2<'_>,
    flight: &super::successor_flight::OriginalRootFirstSourceSuccessorFlightV2<'_>,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_OBSERVATION_BYTES], SourceGenesisErrorV1> {
    sign_controller_successor_with_recipe_v3(ControllerSuccessorOwnerViewV3::Strict(controller),
        SourceSuccessorObservationViewV3::Strict(source), super::successor_flight::RootSuccessorFlightViewV3::Strict(flight),
        generation, key, ControllerSuccessorSignatureRecipeV3::StrictV2)
}

pub(super) fn sign_controller_project_successor_readback_v3(
    controller: &HeldControllerProjectSuccessorV3<'_>,
    source: &crate::hierarchy::SourceProjectContinuationObservationV3<'_>,
    flight: &super::successor_flight::OriginalRootProjectSuccessorFlightV3<'_>,
    generation: u64, key: &SigningKey,
) -> Result<[u8; CONTROLLER_OBSERVATION_BYTES], SourceGenesisErrorV1> {
    sign_controller_successor_with_recipe_v3(ControllerSuccessorOwnerViewV3::Mixed(controller),
        SourceSuccessorObservationViewV3::Mixed(source), super::successor_flight::RootSuccessorFlightViewV3::Mixed(flight),
        generation, key, ControllerSuccessorSignatureRecipeV3::MixedV3)
}

fn sign_controller_successor_with_recipe_v3(
    controller: ControllerSuccessorOwnerViewV3<'_, '_>, source: SourceSuccessorObservationViewV3<'_, '_>,
    flight: super::successor_flight::RootSuccessorFlightViewV3<'_, '_>,
    generation: u64, key: &SigningKey, recipe: ControllerSuccessorSignatureRecipeV3,
) -> Result<[u8; CONTROLLER_OBSERVATION_BYTES], SourceGenesisErrorV1> {
    let controller = controller.data();
    controller.recheck()?;
    source.recheck()?;
    flight.recheck()?;
    if !controller.begin_durable || generation == 0 || controller.source_uid() != source.source_uid()?
        || flight.source_uid()? != source.source_uid()?
        || controller.packet.intent()?.project() != source.project()?
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let phase = if let Some(complete) = &controller.complete {
        let anchored = controller.anchored.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
        let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
        let ack = source.ack().ok_or(SourceGenesisErrorV1::Conflict)?;
        if source.state()? != SourceFirstSuccessorStateV2::Anchored
            || complete.approval() != controller.packet.digest() || complete.begin() != controller.begin.digest()
            || complete.anchored() != anchored.digest() || complete.receipt() != receipt.digest()
            || complete.floor() != anchored.floor() || complete.ack() != ack.digest()
            || anchored.receipt() != receipt.digest() || ack.receipt() != receipt.digest()
            || ack.root_floor() != anchored.floor() || ack.controller_anchored() != anchored.digest()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        3
    } else if source.state()? == SourceFirstSuccessorStateV2::Before {
        controller.recheck_current_admission()?;
        1
    } else { 2 };
    let mut bytes = [0; CONTROLLER_OBSERVATION_BYTES];
    bytes[..8].copy_from_slice(recipe.magic());
    bytes[8..10].copy_from_slice(&u16::from(recipe.version()).to_be_bytes());
    bytes[10] = 1;
    bytes[11] = phase;
    bytes[16..32].copy_from_slice(&flight.nonce());
    bytes[32..40].copy_from_slice(&generation.to_be_bytes());
    bytes[40..44].copy_from_slice(&controller.uid.to_be_bytes());
    bytes[44..48].copy_from_slice(&source.source_uid()?.to_be_bytes());
    bytes[48..56].copy_from_slice(&controller.sequence()?.to_be_bytes());
    bytes[56..64].copy_from_slice(&source.snapshot_sequence()?.to_be_bytes());
    bytes[64..112].copy_from_slice(&controller.names.to_bytes());
    bytes[112..160].copy_from_slice(&source.names()?.to_bytes());
    bytes[160..1056].copy_from_slice(controller.packet.as_bytes());
    bytes[1056..1352].copy_from_slice(controller.begin.as_bytes());
    if let Some(receipt) = source.receipt() {
        if receipt.approval() != controller.packet.digest() || receipt.begin() != controller.begin.digest() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        bytes[1352..1384].copy_from_slice(receipt.root_intent().as_bytes());
        bytes[1384..1920].copy_from_slice(receipt.as_bytes());
    }
    if let Some(anchored) = controller.anchored.as_ref() { bytes[1920..2064].copy_from_slice(anchored.as_bytes()); }
    if let Some(complete) = controller.complete.as_ref() { bytes[2064..2304].copy_from_slice(complete.as_bytes()); }
    if let Some(ack) = source.ack() { bytes[2304..2496].copy_from_slice(ack.as_bytes()); }
    let preimage = [recipe.domain(), &bytes[..CONTROLLER_OBSERVATION_BODY]].concat();
    source.recheck()?;
    controller.recheck()?;
    // The final original-flight pair follows all slow owner observations.
    let clock = flight.signing_boundary_clock()?;
    if phase == 1 { require_approval_clock(&controller.packet, clock)?; }
    bytes[CONTROLLER_OBSERVATION_BODY..].copy_from_slice(&key.sign(&preimage).to_bytes());
    drop(preimage);
    // The caller parks this actual returned signature Result before all later
    // independent owner checks; none can discard the signed packet on failure.
    Ok(bytes)
}

pub(super) fn verify_controller_first_successor_readback_v2(
    bytes: &[u8],
    pin: &super::super::PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
) -> Result<VerifiedControllerFirstSuccessorObservationV2, SourceGenesisErrorV1> {
    verify_controller_successor_with_recipe(bytes, pin, nonce, controller_uid, source_uid, ControllerSuccessorSignatureRecipeV3::StrictV2)
}

pub(super) fn verify_controller_project_successor_readback_v3(
    bytes: &[u8], pin: &super::super::PinnedControllerHoldSignerV1, nonce: [u8; 16],
    controller_uid: u32, source_uid: u32,
) -> Result<VerifiedControllerFirstSuccessorObservationV3, SourceGenesisErrorV1> {
    verify_controller_successor_with_recipe(bytes, pin, nonce, controller_uid, source_uid, ControllerSuccessorSignatureRecipeV3::MixedV3)
        .map(|data| VerifiedControllerFirstSuccessorObservationV3 { data })
}

fn verify_controller_successor_with_recipe(
    bytes: &[u8], pin: &super::super::PinnedControllerHoldSignerV1, nonce: [u8; 16],
    controller_uid: u32, source_uid: u32, recipe: ControllerSuccessorSignatureRecipeV3,
) -> Result<VerifiedControllerFirstSuccessorObservationV2, SourceGenesisErrorV1> {
    if bytes.len() != CONTROLLER_OBSERVATION_BYTES || nonce == [0; 16]
        || bytes.get(..8) != Some(recipe.magic().as_slice())
        || bytes[8..11] != [0, recipe.version(), 1] || bytes[12..16] != [0; 4]
        || bytes[16..32] != nonce || u64::from_be_bytes(take(bytes, 32)?) != pin.generation()
        || u32::from_be_bytes(take(bytes, 40)?) != controller_uid
        || u32::from_be_bytes(take(bytes, 44)?) != source_uid
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    pin.verifying_key().verify_strict(
        &[recipe.domain(), &bytes[..CONTROLLER_OBSERVATION_BODY]].concat(),
        &Signature::from_bytes(&take(bytes, CONTROLLER_OBSERVATION_BODY)?),
    ).map_err(|_| SourceGenesisErrorV1::Stale)?;
    let phase = match bytes[11] {
        1 => ControllerObservationPhaseV2::Before,
        2 => ControllerObservationPhaseV2::Prepared,
        3 => ControllerObservationPhaseV2::Completed,
        _ => return Err(SourceGenesisErrorV1::NonCanonical),
    };
    let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes[160..1056])?;
    let begin = ControllerFirstSourceSuccessorBeginV2::decode(&bytes[1056..1352])?;
    let names = ProtectedJournalNamesV1::from_bytes(&take::<48>(bytes, 64)?)?;
    let source_names = ProtectedJournalNamesV1::from_bytes(&take::<48>(bytes, 112)?)?;
    if names == source_names || begin.approval() != packet.digest() || begin.source_uid() != source_uid
        || begin.predecessor_floor() != digest_at(packet.body(), 144)
        || begin.genesis_complete() != digest_at(packet.body(), 176)
        || begin.old_tree_head() != digest_at(packet.body(), 536)
        || begin.old_lineage_head() != digest_at(packet.body(), 568)
        || begin.next_tree_commit() != digest_at(packet.body(), 680)
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let (root_intent, receipt, anchored, complete, ack) = if phase == ControllerObservationPhaseV2::Before {
        if bytes[1352..2496] != [0; 1144] || source_names != begin.source_names() {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        (None, None, None, None, None)
    } else {
        let receipt = SourceFirstSuccessorReceiptV2::decode(&bytes[1384..1920])?;
        let anchored = (bytes[1920..2064] != [0; 144])
            .then(|| ControllerFirstSourceSuccessorAnchoredV2::decode(&bytes[1920..2064])).transpose()?;
        let complete = (bytes[2064..2304] != [0; 240])
            .then(|| ControllerFirstSourceSuccessorCompleteV2::decode(&bytes[2064..2304])).transpose()?;
        let ack = (bytes[2304..2496] != [0; 192])
            .then(|| SourceFirstSuccessorAckV2::decode(&bytes[2304..2496])).transpose()?;
        if receipt.approval() != packet.digest() || receipt.begin() != begin.digest()
            || receipt.root_intent() != digest_at(bytes, 1352)
            || receipt.source_names() != begin.source_names()
            || (ack.is_none() && source_names != receipt.source_names())
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        if let Some(anchored) = &anchored {
            if anchored.approval() != packet.digest() || anchored.receipt() != receipt.digest() {
                return Err(SourceGenesisErrorV1::Conflict);
            }
        }
        if let Some(ack) = &ack {
            let anchored = anchored.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
            if ack.receipt() != receipt.digest() || ack.root_floor() != anchored.floor()
                || ack.controller_anchored() != anchored.digest() || ack.project() != receipt.project()
                || ack.instance() != receipt.instance()
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
        }
        if let Some(complete) = &complete {
            let ack = ack.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
            let anchored = anchored.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
            if complete.approval() != packet.digest() || complete.receipt() != receipt.digest()
                || complete.floor() != anchored.floor() || complete.ack() != ack.digest()
                || complete.begin() != begin.digest() || complete.anchored() != anchored.digest()
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
        }
        if (phase == ControllerObservationPhaseV2::Completed) != complete.is_some() {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        (Some(receipt.root_intent()), Some(receipt), anchored, complete, ack)
    };
    Ok(VerifiedControllerFirstSuccessorObservationV2 {
        phase, packet, begin, root_intent, receipt, anchored, complete, ack, source_names,
        source_sequence: u64::from_be_bytes(take(bytes, 56)?),
    })
}
