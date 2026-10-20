//! Produces Intent and Source Held from the actual completed J original.
//!
//! The parent retains the original accepted rows, sealed Q04/terminal, J return,
//! and both actual writers. These stages pay their own complete entered bounds
//! inside the same J ledger before allocating. Every returned append/readback
//! and independent native/profile/clock post remains in its once-only owner.
//! The first prefix stops before Cache Held. Its private assignment child then
//! joins the actual held Cache before planning a nonauthorizing assignment;
//! neither stage supplies Ownership, Inventory, complete B or a Root terminal.

pub(super) mod assignment;
pub(super) mod inputs_ready;
pub(super) mod root_validated;
pub(super) mod use_reserved;
pub(super) mod signed;
pub(super) mod dispatch;
pub(super) mod session;
pub(in crate::controller_resource_reservation::create_intake) mod outcome;
pub(in crate::controller_resource_reservation::create_intake) mod handoff;
pub(in crate::controller_resource_reservation::create_intake) mod source_released;

use std::error::Error as StdError;

use aos_sandbox_core::{ObjectDescriptor, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, KEY_BYTES, RECORD_OVERHEAD_BYTES, HistoryErrorV1, KeyV1,
    LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
    controller_intent::{ControllerIntentBodyDataV1, ControllerIntentIdentityDataV1,
        controller_intent_seed_v1},
    source_held::{SOURCE_HELD_RECORD_BYTES_V1, SourceHeldBodyDataV1, SourceHeldReceiptDataV1},
};

use crate::journal::create_storage_history::{prepare_history_pair_v1, readback_history_pair_bytes_v1};
use crate::journal::{CommitResult, JournalError, JournalTransaction, ProtectedJournalNamesV1, CreateStorageWriterPositionOriginalV1};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::Journal;

use super::super::{ProjectPreparationReservationAttemptV1, ResourceReservationErrorV1,
    q04_intake::{CreateContinuationCaptureOwnerV1 as Owner, Q04OriginalIntakeAttemptV1}};
use super::ready::CreateStorageAcceptedIdentityV1;

/// Borrows originals from the actual completed accepted/Q04 parent only.
pub(in crate::controller_resource_reservation) struct OriginalIntentComponentsV1<'original> {
    pub(in crate::controller_resource_reservation) accepted_context: &'original [u8],
    pub(in crate::controller_resource_reservation) operation: &'original [u8],
    pub(in crate::controller_resource_reservation) desired: &'original [u8],
    pub(in crate::controller_resource_reservation) effect: &'original [u8],
    pub(in crate::controller_resource_reservation) specification: &'original ObjectDescriptor,
    pub(in crate::controller_resource_reservation) coissuance: &'original [u8],
    pub(in crate::controller_resource_reservation) terminal: &'original [u8],
}

/// Borrows the actual successful J return and exact read-back member bytes.
pub(in crate::controller_resource_reservation) struct OriginalJDataV1<'original> {
    pub(in crate::controller_resource_reservation) transaction: [u8; 16],
    pub(in crate::controller_resource_reservation) names: ProtectedJournalNamesV1,
    pub(in crate::controller_resource_reservation) native: CommitResult,
    pub(in crate::controller_resource_reservation) clock: RawPairedClockSample,
    pub(in crate::controller_resource_reservation) head_key: &'original [u8],
    pub(in crate::controller_resource_reservation) head: &'original [u8],
    pub(in crate::controller_resource_reservation) claim_key: &'original [u8],
    pub(in crate::controller_resource_reservation) claim: &'original [u8],
}

#[derive(Debug, thiserror::Error)]
pub(super) enum HistoryProductionErrorV1 {
    #[error(transparent)]
    Resource(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    History(#[from] HistoryErrorV1),
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    #[error(transparent)]
    Nonce(#[from] std::io::Error),
}

type ResultV1<T> = Result<T, HistoryProductionErrorV1>;

/// Keeps one exact original healthy writer position; its fields confer no loan.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct CreateStorageWriterPositionV1 {
    pub(crate) names: ProtectedJournalNamesV1,
    pub(crate) next: u64,
    pub(crate) end: u64,
}

// Records where the whole outer primary was produced. Pair posts execute
// after its local primary, so projection must not confuse their later errors
// with an allocation/encoding error that occurred before pair entry.
#[derive(Clone, Copy, Default)]
enum OuterPrimaryPhaseV1 {
    #[default]
    Funding,
    IntentEntry,
    IntentConstruction,
    IntentPair,
    SourceEntry,
    SourceConstruction,
    SourcePair,
    FinalAssociation,
}

#[derive(Default)]
pub(super) struct CreateStorageOriginalHistoriesV1 {
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    primary_phase: OuterPrimaryPhaseV1,
    descriptor: Vec<u8>,
    nonce: Option<std::io::Result<[u8; 16]>>,
    intent_body: Vec<u8>,
    intent_encoding: Option<Result<(), HistoryErrorV1>>,
    seed: Option<Result<[u8; 32], HistoryErrorV1>>,
    pub(super) intent: OriginalHistoryPairV1,
    pub(super) source: OriginalHistoryPairV1,
    source_body: Option<Result<SourceHeldBodyDataV1, JournalError>>,
    source_encoding: Option<Result<[u8; 264], HistoryErrorV1>>,
    pub(super) production: Option<ResultV1<()>>,
    complete: bool,
}

impl CreateStorageOriginalHistoriesV1 {
    pub(super) fn produce_once(
        &mut self,
        parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        accepted: CreateStorageAcceptedIdentityV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.production.is_some() { intake.close(); return Err(ResourceReservationErrorV1::Conflict); }
        self.production = Some(self.produce_inner(parent, intake, controller, source, profile, accepted));
        if matches!(self.funding, Some(Ok(()))) && !self.intent.posts_attempted {
            if let Ok(j) = intake.create_storage_j_data_v1() {
                let original = j.clock;
                self.intent.finish_posts_once(intake, controller, source.journal(), profile,
                    original, accepted.original_cutoff, HistoryRoleV1::Controller);
            }
        }
        if self.source.before_join.is_some() && !self.source.posts_attempted {
            if let Ok(j) = intake.create_storage_j_data_v1() {
                let original = j.clock;
                self.source.finish_posts_once(intake, source.journal(), controller, profile,
                    original, accepted.original_cutoff, HistoryRoleV1::Source);
            }
        }
        self.complete = self.production.as_ref().is_some_and(Result::is_ok)
            && self.intent.complete && self.source.complete && self.failure().is_none();
        if self.complete { Ok(()) } else { intake.close(); Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(
        &mut self,
        parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        accepted: CreateStorageAcceptedIdentityV1,
    ) -> ResultV1<()> {
        // The original J entry already pays these resident empty reservoirs.
        // These distinct owners reserve new dynamic buffers/frames and exact
        // future append bytes. Twelve rows are two observations at each of
        // primary-before, Native final crossing and independent-after, twice.
        self.funding = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            let components = parent.create_storage_intent_components_v1(accepted.coissuance_binding)?;
            let j = intake.create_storage_j_data_v1()?;
            let descriptor = components.specification.media_type().as_str().len()
                .checked_add(48).ok_or(ResourceReservationErrorV1::Conflict)?;
            let body = [components.accepted_context, components.operation, components.desired,
                components.effect, components.coissuance, components.terminal,
                j.head_key, j.head, j.claim_key, j.claim].into_iter()
                .try_fold(264_usize + 11 * 4 + descriptor, |sum, value| sum.checked_add(value.len()))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let intent_record = body.checked_add(RECORD_OVERHEAD_BYTES)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            intake.reserve_create_capture_complete(Owner::ControllerIntent, pair_fixed_demand(intent_record)?)?;
            intake.reserve_create_capture_complete(Owner::SourceHeld, pair_fixed_demand(SOURCE_HELD_RECORD_BYTES_V1)?)?;
            intake.reserve_create_capture_complete(Owner::HistoryNames,
                crate::journal::create_storage_name_peak_demand_v1()?)?;
            intake.extend_create_capture_observers_once(profile, 2 * 3 * 2)
        })());
        retained(&self.funding)?;
        self.primary_phase = OuterPrimaryPhaseV1::IntentEntry;
        self.intent.enter_once(parent, intake, controller, source.journal(), profile, HistoryRoleV1::Controller)?;
        self.primary_phase = OuterPrimaryPhaseV1::IntentConstruction;
        self.nonce = Some(crate::policy_compiler::fresh_root_nonce());
        let nonce = *retained(&self.nonce)?;
        let lane = intake.create_lane()?;
        let components = parent.create_storage_intent_components_v1(accepted.coissuance_binding)?;
        self.descriptor = aos_sandbox_core::encode_object_descriptor(components.specification);
        let j = intake.create_storage_j_data_v1()?;
        let identity = ControllerIntentIdentityDataV1 {
            lane, operation: accepted.operation, project: accepted.project,
            sandbox: accepted.sandbox, accepted_request: accepted.accepted_request,
            coissuance_binding: accepted.coissuance_binding, controller_nonce: nonce,
            boot: j.clock.host_boot_id(), started: j.clock.boottime_nanoseconds(),
            cutoff: accepted.original_cutoff, j_transaction: j.transaction, j_names: j.names,
            j_commit: j.native.commit_sequence, j_end: j.native.durable_bytes,
        };
        let body = ControllerIntentBodyDataV1 { identity,
            accepted_context: components.accepted_context, operation: components.operation,
            desired: components.desired, effect: components.effect, specification: &self.descriptor,
            coissuance: components.coissuance, terminal: components.terminal,
            j_head_key: j.head_key, j_head: j.head, j_claim_key: j.claim_key, j_claim: j.claim };
        let length = body.encoded_bytes()?;
        self.intent_body.try_reserve_exact(length)?;
        self.intent_body.resize(length, 0);
        self.intent_encoding = Some(body.encode_into(&mut self.intent_body));
        retained(&self.intent_encoding)?;
        self.seed = Some(controller_intent_seed_v1(&self.intent_body));
        let seed = *retained(&self.seed)?;
        let original = j.clock;
        let j_end = j.native.durable_bytes;
        let j_next = j.native.commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?;
        // The actual J return fixes the first Controller position. Its opaque
        // readback and parent originals remain resident during this append.
        self.primary_phase = OuterPrimaryPhaseV1::IntentPair;
        self.intent.produce_once(parent, intake, controller, source.journal(), profile,
            HistoryRoleV1::Controller, lane, seed, original, accepted.original_cutoff,
            Some((j_next, j_end)), &self.intent_body, None)?;

        self.primary_phase = OuterPrimaryPhaseV1::SourceEntry;
        self.source.enter_once(parent, intake, source.journal(), controller, profile, HistoryRoleV1::Source)?;
        self.primary_phase = OuterPrimaryPhaseV1::SourceConstruction;
        self.source_body = Some((|| {
            let position = *retained_journal(&self.source.before)?;
            Ok(SourceHeldBodyDataV1 { operation: accepted.operation, project: accepted.project,
                sandbox: accepted.sandbox, accepted_request: accepted.accepted_request,
                coissuance_binding: accepted.coissuance_binding, seed, controller_nonce: nonce,
                boot: original.host_boot_id(), started: original.boottime_nanoseconds(),
                cutoff: accepted.original_cutoff, source_names: position.names,
                source_before_next: position.next, source_before_end: position.end })
        })());
        let source_body = *retained(&self.source_body)?;
        self.source_encoding = Some(source_body.encode());
        let source_bytes = retained(&self.source_encoding)?;
        parent.require_create_storage_association(controller, source, profile)?;
        self.primary_phase = OuterPrimaryPhaseV1::SourcePair;
        self.source.produce_once(parent, intake, source.journal(), controller, profile,
            HistoryRoleV1::Source, lane, seed, original, accepted.original_cutoff,
            Some((source_body.source_before_next, source_body.source_before_end)), source_bytes, None)?;
        self.primary_phase = OuterPrimaryPhaseV1::FinalAssociation;
        parent.require_create_storage_association(controller, source, profile)?;
        Ok(())
    }

    pub(super) fn controller_position_v1(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.intent.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn source_held_data_v1(&self, lane: [u8; 16])
        -> Result<SourceHeldReceiptDataV1<'_>, ResourceReservationErrorV1>
    {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let position = self.source.after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let record = self.source.record.as_slice().try_into().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let receipt = SourceHeldReceiptDataV1 { record, latest_head: self.source.head,
            source_names: position.names, source_after_next: position.next, source_after_end: position.end };
        receipt.body(lane).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(receipt)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.funding)
            .or_else(|| self.intent.primary_failure())
            .or_else(|| cause(&self.nonce))
            .or_else(|| cause(&self.intent_encoding)).or_else(|| cause(&self.seed))
            .or_else(|| matches!(self.primary_phase, OuterPrimaryPhaseV1::IntentEntry
                | OuterPrimaryPhaseV1::IntentConstruction).then(|| cause(&self.production)).flatten())
            .or_else(|| self.intent.post_failure())
            .or_else(|| self.source.primary_failure())
            .or_else(|| cause(&self.source_body)).or_else(|| cause(&self.source_encoding))
            .or_else(|| matches!(self.primary_phase, OuterPrimaryPhaseV1::SourceEntry
                | OuterPrimaryPhaseV1::SourceConstruction).then(|| cause(&self.production)).flatten())
            .or_else(|| self.source.post_failure())
            .or_else(|| cause(&self.production))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum HistoryRoleV1 { Controller, Source }

impl HistoryRoleV1 {
    fn other(self) -> Self { match self { Self::Controller => Self::Source, Self::Source => Self::Controller } }

    fn owner(self) -> OwnerV1 { match self { Self::Controller => OwnerV1::Controller, Self::Source => OwnerV1::Source } }
}

// Only genuine parent-owned producers can construct these typed bindings.
// Every closed variant uses the same atomic append, crossing and retained posts.
#[derive(Clone, Copy)]
pub(super) enum HistorySuccessorBindingV1<'held> {
    Assignment(&'held assignment::AssignmentAppendBindingV1<'held>),
    InputsReady(&'held inputs_ready::InputsReadyAppendBindingV1<'held>),
    RootValidated(&'held root_validated::RootValidatedAppendBindingV1<'held>),
    UseReserved(&'held use_reserved::UseReservedAppendBindingV1<'held>),
    Signed(&'held signed::SignedAppendBindingV1<'held>),
    Dispatch(&'held dispatch::DispatchAppendBindingV1<'held>),
    Session(&'held session::SessionAppendBindingV1<'held>),
    Outcome(&'held outcome::OutcomeAppendBindingV1<'held>),
    Handoff(&'held handoff::HandoffAppendBindingV1<'held>),
    SourceReleased(&'held source_released::SourceReleasedAppendBindingV1<'held>),
}

impl HistorySuccessorBindingV1<'_> {
    fn capture_owner(self) -> Owner {
        match self { Self::Assignment(_) => Owner::AssignmentPlanned, Self::InputsReady(_) | Self::RootValidated(_) | Self::UseReserved(_) | Self::Signed(_) | Self::Dispatch(_) | Self::Session(_) | Self::Outcome(_) | Self::Handoff(_) | Self::SourceReleased(_) => Owner::RootExchange }
    }

    fn coordinates(self) -> Result<(u64, u8, [u8; 32]), HistoryErrorV1> {
        match self {
            Self::Assignment(binding) => Ok((2, 12, binding.predecessor()?)),
            Self::InputsReady(binding) => Ok((3, 2, binding.predecessor()?)),
            Self::RootValidated(binding) => Ok((4, 3, binding.predecessor()?)),
            Self::UseReserved(binding) => Ok((5, 4, binding.predecessor()?)),
            Self::Signed(binding) => Ok((6, 5, binding.predecessor()?)),
            Self::Dispatch(binding) => Ok((7, 6, binding.predecessor()?)),
            Self::Session(binding) => Ok((8, 7, binding.predecessor()?)),
            Self::Outcome(binding) => Ok((9, 8, binding.predecessor()?)),
            Self::Handoff(binding) => Ok((10, 9, binding.predecessor()?)),
            Self::SourceReleased(binding) => Ok((2, 2, binding.predecessor()?)),
        }
    }

    fn require_successor(self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::State,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        match self {
            Self::Assignment(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::InputsReady(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::RootValidated(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::UseReserved(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::Signed(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::Dispatch(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::Session(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::Outcome(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::Handoff(binding) => binding.require_successor(parent, intake, state, journal, transaction),
            Self::SourceReleased(binding) => binding.require_successor(parent, intake, state, journal, transaction),
        }
    }

    fn require_state_successor(self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::State,
        transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        match self {
            Self::Assignment(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::InputsReady(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::RootValidated(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::UseReserved(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::Signed(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::Dispatch(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::Session(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::Outcome(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::Handoff(binding) => binding.require_state_successor(parent, intake, state, transaction),
            Self::SourceReleased(binding) => binding.require_state_successor(parent, intake, state, transaction),
        }
    }
}

pub(super) struct OriginalHistoryPairV1 {
    before_join: Option<Result<(), ResourceReservationErrorV1>>,
    before_names_binding: Option<Result<(), ResourceReservationErrorV1>>,
    before_original: CreateStorageWriterPositionOriginalV1,
    other_before_original: CreateStorageWriterPositionOriginalV1,
    readback_original: CreateStorageWriterPositionOriginalV1,
    after_original: CreateStorageWriterPositionOriginalV1,
    other_after_original: CreateStorageWriterPositionOriginalV1,
    before: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
    other_before: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    record: Vec<u8>,
    encoding: Option<Result<[u8; 32], HistoryErrorV1>>,
    head: [u8; HEAD_BYTES],
    transaction: Option<Result<JournalTransaction, JournalError>>,
    crossing: HistoryCrossingV1,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), JournalError>>,
    after: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
    other_after: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
    names_binding: Option<Result<(), JournalError>>,
    after_join: Option<Result<(), ResourceReservationErrorV1>>,
    clock_original: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    clock_binding: Option<Result<(), JournalError>>,
    production: Option<ResultV1<()>>,
    complete: bool,
    posts_attempted: bool,
}

impl Default for OriginalHistoryPairV1 {
    fn default() -> Self {
        Self { before_join: None, before_names_binding: None,
            before_original: CreateStorageWriterPositionOriginalV1::default(),
            other_before_original: CreateStorageWriterPositionOriginalV1::default(),
            readback_original: CreateStorageWriterPositionOriginalV1::default(),
            after_original: CreateStorageWriterPositionOriginalV1::default(),
            other_after_original: CreateStorageWriterPositionOriginalV1::default(), before: None, other_before: None, geometry: None,
            funding: None, record: Vec::new(), encoding: None, head: [0; HEAD_BYTES],
            transaction: None, crossing: HistoryCrossingV1::default(), append: None,
            readback: None, after: None, other_after: None, names_binding: None,
            after_join: None, clock_original: Default::default(), clock: None,
            clock_binding: None, production: None, complete: false, posts_attempted: false }
    }
}

impl OriginalHistoryPairV1 {
    fn enter_once(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, target: &Journal, other: &Journal,
        profile: &ProductionControllerNormalRootProfileV1, role: HistoryRoleV1) -> ResultV1<()>
    {
        if self.before_join.is_some() { return Err(JournalError::ProtectedBoundary.into()); }
        self.before_join = Some(intake.require_create_capture_profile_v1(profile));
        retained(&self.before_join)?;
        self.before_original.capture_once(target, role);
        self.before = Some(self.before_original.position());
        self.other_before_original.capture_once(other, role.other());
        self.other_before = Some(self.other_before_original.position());
        self.before_names_binding = Some((|| {
            let target = *retained_journal(&self.before)?;
            let other = *retained_journal(&self.other_before)?;
            let (controller, source) = match role {
                HistoryRoleV1::Controller => (target, other),
                HistoryRoleV1::Source => (other, target),
            };
            parent.require_create_storage_names(controller.names, source.names)
        })());
        retained(&self.before)?;
        retained(&self.other_before)?;
        retained(&self.before_names_binding)?;
        Ok(())
    }

    fn produce_once(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, target: &mut Journal, other: &Journal,
        profile: &ProductionControllerNormalRootProfileV1, role: HistoryRoleV1,
        lane: [u8; 16], seed: [u8; 32], original: RawPairedClockSample, cutoff: u64,
        expected: Option<(u64, u64)>, body: &[u8],
        planned: Option<HistorySuccessorBindingV1<'_>>) -> ResultV1<()>
    {
        if self.production.is_some() { return Err(JournalError::ProtectedBoundary.into()); }
        self.production = Some(self.produce_inner(parent, intake, target, other, profile,
            role, lane, seed, original, cutoff, expected, body, planned));
        self.finish_posts_once(intake, target, other, profile, original, cutoff, role);
        self.complete = self.production.as_ref().is_some_and(Result::is_ok)
            && self.failure().is_none() && self.readback.as_ref().is_some_and(Result::is_ok);
        if self.complete { Ok(()) } else { Err(JournalError::ProtectedBoundary.into()) }
    }

    fn finish_posts_once(&mut self, intake: &Q04OriginalIntakeAttemptV1,
        target: &Journal, other: &Journal, profile: &ProductionControllerNormalRootProfileV1,
        original: RawPairedClockSample, cutoff: u64, role: HistoryRoleV1)
    {
        if self.posts_attempted { return; }
        self.posts_attempted = true;
        // Every available independent post runs even after primary Err. Its
        // entire return is parked before the earlier primary is classified.
        self.after_original.capture_once(target, role);
        self.after = Some(self.after_original.position());
        self.other_after_original.capture_once(other, role.other());
        self.other_after = Some(self.other_after_original.position());
        self.names_binding = Some((|| {
            let before = retained_journal(&self.before)?;
            let after = retained_journal(&self.after)?;
            if after.names != before.names || retained_journal(&self.other_after)? != retained_journal(&self.other_before)? {
                return Err(JournalError::ProtectedBoundary);
            }
            if let Some(Ok(committed)) = self.append.as_ref() {
                if after.end != committed.durable_bytes
                    || committed.commit_sequence.checked_add(1) != Some(after.next) {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        self.after_join = Some(intake.require_create_history_post_profile_v1(profile));
        self.clock = Some(self.clock_original.observe_once(None));
        self.clock_binding = Some(require_clock(original, retained_journal(&self.clock).copied(), cutoff));
    }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, target: &mut Journal, other: &Journal,
        profile: &ProductionControllerNormalRootProfileV1, role: HistoryRoleV1,
        lane: [u8; 16], seed: [u8; 32], original: RawPairedClockSample, cutoff: u64,
        expected: Option<(u64, u64)>, body: &[u8],
        planned: Option<HistorySuccessorBindingV1<'_>>) -> ResultV1<()>
    {
        retained(&self.before_join)?;
        retained(&self.before_names_binding)?;
        let before = *retained(&self.before)?;
        let other_before = *retained(&self.other_before)?;
        if expected.is_some_and(|value| value != (before.next, before.end)) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.geometry = Some(target.create_storage_semantic_append_demand_v1());
        let record_bytes = RECORD_OVERHEAD_BYTES.checked_add(body.len()).ok_or(JournalError::JournalTooLarge)?;
        let owner = match role {
            HistoryRoleV1::Controller if planned.is_some() => planned.ok_or(JournalError::ProtectedBoundary)?.capture_owner(),
            HistoryRoleV1::Controller => Owner::ControllerIntent,
            HistoryRoleV1::Source => Owner::SourceHeld,
        };
        let complete = match planned {
            Some(HistorySuccessorBindingV1::UseReserved(_) | HistorySuccessorBindingV1::Signed(_) | HistorySuccessorBindingV1::Dispatch(_) | HistorySuccessorBindingV1::Session(_) | HistorySuccessorBindingV1::Outcome(_) | HistorySuccessorBindingV1::Handoff(_) | HistorySuccessorBindingV1::SourceReleased(_)) =>
                pair_use_complete_demand_v1(record_bytes, retained(&self.geometry)?),
            _ => pair_complete_demand(record_bytes, retained(&self.geometry)?),
        };
        self.funding = Some(complete.and_then(|demand| match planned {
                Some(HistorySuccessorBindingV1::UseReserved(binding)) => binding.require_prepaid_v1(demand),
                Some(HistorySuccessorBindingV1::Signed(binding)) => binding.require_prepaid_v1(demand),
                Some(HistorySuccessorBindingV1::Dispatch(binding)) => binding.require_prepaid_v1(demand),
                Some(HistorySuccessorBindingV1::Session(binding)) => binding.require_prepaid_v1(demand),
                Some(HistorySuccessorBindingV1::Outcome(binding)) => binding.require_prepaid_v1(demand),
                Some(HistorySuccessorBindingV1::Handoff(binding)) => binding.require_prepaid_v1(demand),
                Some(HistorySuccessorBindingV1::SourceReleased(binding)) => binding.require_prepaid_v1(demand),
                _ => intake.reserve_create_capture_complete(owner, demand),
            }));
        retained(&self.funding)?;
        self.record.try_reserve_exact(record_bytes)?;
        self.record.resize(record_bytes, 0);
        let (revision, state, predecessor) = match planned {
            Some(binding) if matches!(role, HistoryRoleV1::Controller)
                || matches!((role, binding), (HistoryRoleV1::Source, HistorySuccessorBindingV1::SourceReleased(_))) => binding.coordinates()?,
            Some(_) => return Err(JournalError::ProtectedBoundary.into()),
            None => (1, 1, [0; 32]),
        };
        let key = KeyV1::new(lane, role.owner(), revision)?;
        let phase = PhaseV1::new(role.owner(), state)?;
        self.encoding = Some(RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor, correlation: seed,
        }, body, &mut self.record));
        let checksum = *retained(&self.encoding)?;
        self.head = LatestHeadV1::new(revision, checksum)?.encode();
        self.transaction = Some(prepare_history_pair_v1(key, phase, &self.record, &self.head));
        let transaction = retained(&self.transaction)?;
        let mut loan = CreateStorageHistoryAppendLoanV1 { parent, intake, profile, other,
            target_identity: std::ptr::from_ref(target) as usize, before, other_before,
            original, cutoff, owner: role.owner(), transaction, crossing: &mut self.crossing, planned };
        self.append = Some(match role {
            HistoryRoleV1::Controller => target.commit_create_storage_controller_history_v1(transaction, &mut loan),
            HistoryRoleV1::Source => target.commit_create_storage_source_held_v1(transaction, &mut loan),
        });
        if let Some(Ok(committed)) = self.append.as_ref() {
            self.readback = Some(readback_pair(target, transaction, &self.record, &self.head, before, committed, role, &mut self.readback_original));
        }
        retained(&self.append)?;
        retained(&self.readback)?;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.primary_failure().or_else(|| self.post_failure())
    }

    fn primary_failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.before_join).or_else(|| self.before_original.failure()).or_else(|| cause(&self.before))
            .or_else(|| self.other_before_original.failure()).or_else(|| cause(&self.other_before))
            .or_else(|| cause(&self.before_names_binding))
            .or_else(|| cause(&self.geometry)).or_else(|| cause(&self.funding))
            .or_else(|| cause(&self.encoding)).or_else(|| cause(&self.transaction))
            .or_else(|| self.crossing.failure()).or_else(|| cause(&self.append))
            .or_else(|| self.readback_original.failure()).or_else(|| cause(&self.readback)).or_else(|| cause(&self.production))
    }

    fn post_failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.after_original.failure().or_else(|| cause(&self.after))
            .or_else(|| self.other_after_original.failure()).or_else(|| cause(&self.other_after))
            .or_else(|| cause(&self.names_binding)).or_else(|| cause(&self.after_join))
            .or_else(|| self.clock_original.failure()).or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.clock_binding))
    }
}

// Requires the whole closed Controller lane, including absence of unrelated
// records. Original producers supply their own borrowed row bytes, never keys
// decoded from a prospective request as an authorization source.
fn require_exact_controller_prefix_v1(state: &super::super::State, lane: [u8; 16],
    records: &[(u64, &[u8])], head: &[u8],
) -> Result<(), JournalError> {
    let mut count = 0;
    let head_key = KeyV1::new(lane, OwnerV1::Controller, 0).map_err(|_| JournalError::ProtectedBoundary)?.encode();
    for ((namespace, key), value) in state {
        if *namespace != crate::RecordNamespace::CreateStorageHistory { continue; }
        count += 1;
        if key.as_slice() == head_key && value.as_slice() == head { continue; }
        let mut found = false;
        for (revision, expected) in records {
            let expected_key = KeyV1::new(lane, OwnerV1::Controller, *revision)
                .map_err(|_| JournalError::ProtectedBoundary)?.encode();
            if key.as_slice() == expected_key && value.as_slice() == *expected {
                found = true;
                break;
            }
        }
        if !found { return Err(JournalError::ProtectedBoundary); }
    }
    if count != records.len() + 1 { return Err(JournalError::ProtectedBoundary); }
    Ok(())
}

#[derive(Default)]
struct HistoryCrossingV1 {
    transition: Option<Result<(), JournalError>>,
    target_original: CreateStorageWriterPositionOriginalV1,
    other_original: CreateStorageWriterPositionOriginalV1,
    target: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
    other: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
    binding: Option<Result<(), JournalError>>,
    profile: Option<Result<(), ResourceReservationErrorV1>>,
    clock_original: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    signing_clock: Option<Result<(), aos_sandbox_core::SignatureVerificationError>>,
    completion: Option<Result<(), JournalError>>,
}

impl HistoryCrossingV1 {
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.transition).or_else(|| self.target_original.failure()).or_else(|| cause(&self.target))
            .or_else(|| self.other_original.failure()).or_else(|| cause(&self.other))
            .or_else(|| cause(&self.binding)).or_else(|| cause(&self.profile))
            .or_else(|| self.clock_original.failure()).or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.signing_clock)).or_else(|| cause(&self.completion))
    }
}

/// Borrows the actual paid J original for its exact next C or Source append.
/// No constructor, target selector or raw-writer factory is exported.
pub(crate) struct CreateStorageHistoryAppendLoanV1<'crossing, 'original> {
    parent: &'original ProjectPreparationReservationAttemptV1,
    intake: &'original Q04OriginalIntakeAttemptV1,
    profile: &'original ProductionControllerNormalRootProfileV1,
    other: &'original Journal,
    target_identity: usize,
    before: CreateStorageWriterPositionV1,
    other_before: CreateStorageWriterPositionV1,
    original: RawPairedClockSample,
    cutoff: u64,
    owner: OwnerV1,
    transaction: &'crossing JournalTransaction,
    crossing: &'crossing mut HistoryCrossingV1,
    planned: Option<HistorySuccessorBindingV1<'original>>,
}

impl CreateStorageHistoryAppendLoanV1<'_, '_> {
    pub(crate) fn require_transition_for_owner(&mut self, journal: &Journal, transaction: &JournalTransaction, owner: OwnerV1)
        -> Result<(), JournalError>
    {
        if self.crossing.transition.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.crossing.transition = Some((|| {
            if self.owner != owner || std::ptr::from_ref(journal) as usize != self.target_identity
                || transaction != self.transaction
                || (self.planned.is_none() && journal.records(crate::RecordNamespace::CreateStorageHistory).next().is_some())
                || journal.snapshot_sequence() != self.before.next {
                return Err(JournalError::ProtectedBoundary);
            }
            if let Some(binding) = self.planned {
                binding.require_successor(self.parent, self.intake, journal.controller_resource_state_v1()?,
                    journal, transaction)?;
            }
            Ok(())
        })());
        retained_journal(&self.crossing.transition).map(|_| ())
    }

    // The shared cleared-Q04 gate independently decodes all eight original
    // phases and compares this actual parent's sealed identity, never a token
    // copied from an old phase or a historical row alone.
    pub(crate) fn matches_identity(&self, identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1) -> bool {
        self.parent.matches_create_continuation_identity(identity)
    }

    /// Checks this real parent's exact first Intent or typed planned successor.
    ///
    /// # Errors
    /// Rejects an unentered loan, another parent/accepted A, changed J member,
    /// mismatched Intent/planned member, unrelated history or any other mutation.
    pub(crate) fn require_controller_history_successor(
        &self,
        state: &std::collections::BTreeMap<(crate::RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        retained_journal(&self.crossing.transition)?;
        if let Some(binding) = self.planned {
            if self.owner != OwnerV1::Controller || transaction != self.transaction {
                return Err(JournalError::ProtectedBoundary);
            }
            return binding.require_state_successor(self.parent, self.intake, state, transaction);
        }
        if self.owner != OwnerV1::Controller || transaction != self.transaction
            || state.keys().any(|(namespace, _)| *namespace == crate::RecordNamespace::CreateStorageHistory) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.parent.require_create_continuation_state(state).map_err(native_error)?;
        let j = require_j_readback_members_v1(self.intake, state)?;
        let [member, head] = transaction.records() else { return Err(JournalError::ProtectedBoundary); };
        let lane = self.intake.create_lane().map_err(native_error)?;
        let key = KeyV1::new(lane, OwnerV1::Controller, 1).map_err(|_| JournalError::ProtectedBoundary)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 1).map_err(|_| JournalError::ProtectedBoundary)?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() {
            return Err(JournalError::ProtectedBoundary);
        }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or(JournalError::ProtectedBoundary)?, key, phase)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let body = ControllerIntentBodyDataV1::decode(envelope.body()).map_err(|_| JournalError::ProtectedBoundary)?;
        let accepted = self.parent.create_storage_original_identity_v1().map_err(native_error)?;
        let components = self.parent.create_storage_intent_components_v1(accepted.coissuance_binding).map_err(native_error)?;
        if body.identity.lane != lane || body.identity.operation != accepted.operation
            || body.identity.project != accepted.project || body.identity.sandbox != accepted.sandbox
            || body.identity.accepted_request != accepted.accepted_request
            || body.identity.coissuance_binding != accepted.coissuance_binding
            || body.identity.cutoff != accepted.original_cutoff
            || body.identity.boot != j.clock.host_boot_id()
            || body.identity.started != j.clock.boottime_nanoseconds()
            || body.identity.j_transaction != j.transaction || body.identity.j_names != j.names
            || body.identity.j_commit != j.native.commit_sequence || body.identity.j_end != j.native.durable_bytes
            || body.j_head_key != j.head_key || body.j_head != j.head
            || body.j_claim_key != j.claim_key || body.j_claim != j.claim
            || body.accepted_context != components.accepted_context || body.operation != components.operation
            || body.desired != components.desired || body.effect != components.effect
            || body.coissuance != components.coissuance || body.terminal != components.terminal
            || body.specification != aos_sandbox_core::encode_object_descriptor(components.specification)
            || controller_intent_seed_v1(envelope.body()).map_err(|_| JournalError::ProtectedBoundary)? != envelope.coordinates().correlation {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_crossing(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.crossing.completion.is_some() { return Err(JournalError::ProtectedBoundary); }
        let role = match self.owner {
            OwnerV1::Controller => HistoryRoleV1::Controller,
            OwnerV1::Source => HistoryRoleV1::Source,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        self.crossing.target_original.capture_once(journal, role);
        self.crossing.target = Some(self.crossing.target_original.position());
        self.crossing.other_original.capture_once(self.other, role.other());
        self.crossing.other = Some(self.crossing.other_original.position());
        self.crossing.binding = Some((|| {
            if *retained_journal(&self.crossing.target)? != self.before
                || *retained_journal(&self.crossing.other)? != self.other_before
                || std::ptr::from_ref(journal) as usize != self.target_identity {
                return Err(JournalError::ProtectedBoundary);
            }
            self.parent.require_terminal_retention().map_err(native_error)
        })());
        self.crossing.profile = Some(self.intake.require_create_capture_profile_v1(self.profile));
        self.crossing.clock = Some(self.crossing.clock_original.observe_once(None));
        if let (Some(HistorySuccessorBindingV1::Signed(binding)), Some(Ok(sample))) =
            (self.planned, self.crossing.clock.as_ref()) {
            self.crossing.signing_clock = Some(binding.require_clock_v1(*sample));
        }
        self.crossing.completion = Some((|| {
            retained_journal(&self.crossing.transition)?;
            retained_journal(&self.crossing.binding)?;
            retained_journal(&self.crossing.profile)?;
            require_clock(self.original, retained_journal(&self.crossing.clock).copied(), self.cutoff)?;
            if self.crossing.signing_clock.as_ref().is_some_and(Result::is_err) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        retained_journal(&self.crossing.completion).map(|_| ())
    }
}

// The same actual J readback must remain present for both first Intent and
// its exact private planned successor. A generic bank head is insufficient.
fn require_j_readback_members_v1<'original>(
    intake: &'original Q04OriginalIntakeAttemptV1,
    state: &super::super::State,
) -> Result<OriginalJDataV1<'original>, JournalError> {
    let j = intake.create_storage_j_data_v1().map_err(native_error)?;
    for (key, value) in [(j.head_key, j.head), (j.claim_key, j.claim)] {
        if state.iter().find(|((namespace, stored), _)| {
            *namespace == crate::RecordNamespace::ControllerResourceReservation && stored.as_slice() == key
        }).map(|(_, bytes)| bytes.as_slice()) != Some(value) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(j)
}

fn pair_fixed_demand(record: usize) -> Result<ResourceVector, ResourceReservationErrorV1> {
    // The simultaneous dominant lanes are body+record, prepared TX members,
    // Native field/frame encoding (including old+new reallocations), the new
    // materialized pair and readback scratch. Existing resident maps belong B.
    let cells = 64_usize.checked_mul(std::mem::size_of::<(
        crate::RecordNamespace, Vec<u8>, Vec<u8>, [usize; 6],
    )>()).ok_or(ResourceReservationErrorV1::Conflict)?;
    // Final Native crossing and the independently owed trailing pair each
    // retain their own paired-clock boot readers and partial native buffers.
    // The existing HistoryNames peak already includes their two failed FDs.
    let clocks = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
        .and_then(|bytes| bytes.checked_mul(2)).ok_or(ResourceReservationErrorV1::Conflict)?;
    let clock_cells = crate::policy_compiler::RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
        .and_then(|cells| cells.checked_mul(2)).and_then(|cells| cells.checked_add(2))
        .and_then(|cells| u64::try_from(cells).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
    let memory = record.checked_mul(12).and_then(|n| n.checked_add(8 * (HEAD_BYTES + KEY_BYTES)))
        .and_then(|n| n.checked_add(cells)).and_then(|n| n.checked_add(clocks))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let append = aos_sandbox_journal::geometry::encoded_transaction_append_bytes([
        aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(record) },
        aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
    ].into_iter()).map_err(JournalError::from)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::MetadataEntries, 64_u64.checked_add(clock_cells).ok_or(ResourceReservationErrorV1::Conflict)?)
        .with(D::StorageBytes, append))
}

fn pair_complete_demand(record: usize, semantic: &ResourceVector) -> Result<ResourceVector, ResourceReservationErrorV1> {
    pair_fixed_demand(record)?.checked_add(*semantic).map_err(ResourceReservationErrorV1::from)
}

// One new historical row is a resident namespace entry. The existing head
// is replaced. Compiled Result/Option slots and pure model/parser overhead
// remain byte obligations; they do not become a new per-field namespace fee.
fn pair_use_complete_demand_v1(record: usize, semantic: &ResourceVector)
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    pair_fixed_demand(record)?.with(D::MetadataEntries, 1)
        .checked_add(*semantic).map_err(ResourceReservationErrorV1::from)
}

// Passive byte/namespace arithmetic shared with the actual UseReserved entry.
// The real pair still verifies its own retained semantic map and original payer.
pub(in crate::controller_resource_reservation) fn use_history_pair_receiving_demand_v1(
    record: usize,
    semantic: &ResourceVector,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let inline = use_reserved::UseReservedOriginalsV1::fixed_inline_receiving_bytes_v1()?
        .max(signed::SignedOriginalsV1::fixed_inline_receiving_bytes_v1()?)
        .max(dispatch::DispatchOriginalsV1::fixed_inline_receiving_bytes_v1()?)
        .max(session::SessionOriginalsV1::fixed_inline_receiving_bytes_v1()?)
        .max(outcome::OutcomeOriginalsV1::fixed_inline_receiving_bytes_v1()?)
        .max(handoff::HandoffOriginalsV1::fixed_inline_receiving_bytes_v1()?);
    let names = crate::journal::create_storage_name_peak_demand_v1()?;
    pair_use_complete_demand_v1(record, semantic)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(inline).map_err(|_| ResourceReservationErrorV1::Conflict)?))?
        .checked_add(names.with(D::OpenFiles, 0).with(D::MetadataEntries, 0))
        .map_err(ResourceReservationErrorV1::from)
}

fn readback_pair(journal: &Journal, transaction: &JournalTransaction, record: &[u8],
    head: &[u8; HEAD_BYTES], before: CreateStorageWriterPositionV1, committed: &CommitResult,
    role: HistoryRoleV1, original: &mut CreateStorageWriterPositionOriginalV1)
    -> Result<(), JournalError>
{
    original.capture_once(journal, role);
    let position = original.position()?;
    let expected_end = before.end.checked_add(crate::journal::encoded_transaction_append_bytes(transaction)?)
        .ok_or(JournalError::JournalTooLarge)?;
    if position.names != before.names || position.end != expected_end
        || committed.durable_bytes != expected_end || committed.commit_sequence.checked_add(1) != Some(position.next)
        || before.next.checked_add(4) != Some(position.next) {
        return Err(JournalError::ProtectedBoundary);
    }
    readback_history_pair_bytes_v1(journal, transaction, record, head, before.next, committed)?;
    Ok(())
}

fn require_clock(original: RawPairedClockSample, current: Result<RawPairedClockSample, JournalError>, cutoff: u64)
    -> Result<(), JournalError>
{
    let current = current?;
    original.validate_later_sample(current).map_err(|_| JournalError::ProtectedBoundary)?;
    if current.host_boot_id() != original.host_boot_id() || current.boottime_nanoseconds() >= cutoff {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn native_error(error: ResourceReservationErrorV1) -> JournalError {
    super::super::create_intake_append::native_error(error)
}

fn retained<T, E>(result: &Option<Result<T, E>>) -> ResultV1<&T>
{
    result.as_ref().and_then(|value| value.as_ref().ok())
        .ok_or_else(|| JournalError::ProtectedBoundary.into())
}

fn retained_journal<T, E>(result: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    result.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    result.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod chronology_tests {
    use super::*;

    #[test]
    fn actual_outer_allocation_cause_precedes_later_independent_name_failure() {
        let mut owner = CreateStorageOriginalHistoriesV1::default();
        owner.primary_phase = OuterPrimaryPhaseV1::IntentConstruction;
        let actual = Vec::<u8>::new().try_reserve_exact(usize::MAX).unwrap_err();
        owner.production = Some(Err(HistoryProductionErrorV1::Allocation(actual)));
        owner.intent.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(2))));

        let first = owner.failure().unwrap();

        assert!(matches!(first.downcast_ref::<HistoryProductionErrorV1>(),
            Some(HistoryProductionErrorV1::Allocation(_))));
        assert!(owner.intent.post_failure().is_some());
    }

    #[test]
    fn earlier_pair_native_cause_precedes_outer_coarse_pair_projection() {
        let mut owner = CreateStorageOriginalHistoriesV1::default();
        owner.primary_phase = OuterPrimaryPhaseV1::IntentPair;
        owner.intent.before = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));
        owner.production = Some(Err(JournalError::ProtectedBoundary.into()));
        owner.intent.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(2))));

        let first = owner.failure().unwrap();

        assert!(matches!(first.downcast_ref::<JournalError>(),
            Some(JournalError::Io(error)) if error.raw_os_error() == Some(5)));
        assert!(owner.intent.post_failure().is_some());
    }
}

impl CreateStorageOriginalHistoriesV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn intent_bundle_data_v1(&self)
        -> Result<(&[u8], aos_sandbox_protocol::domain_ledger::create_storage_history::ready::IntentNativeReceiptDataV1), ResourceReservationErrorV1>
    {
        if !self.intent.complete || self.intent.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let position = self.intent.after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((&self.intent.record,
            aos_sandbox_protocol::domain_ledger::create_storage_history::ready::IntentNativeReceiptDataV1 {
                latest_head: self.intent.head, names: position.names,
                after_next: position.next, after_end: position.end,
            }))
    }
}

#[cfg(test)]
mod controller_prefix_tests {
    use super::*;

    #[test]
    fn shared_controller_prefix_refuses_foreign_rows_and_an_unconfirmed_head() {
        let lane = [3; 16];
        let mut state = super::super::super::State::new();
        let key = |revision| (crate::RecordNamespace::CreateStorageHistory,
            KeyV1::new(lane, OwnerV1::Controller, revision).unwrap().encode().to_vec());
        state.insert(key(1), b"actual-intent".to_vec());
        state.insert(key(2), b"actual-plan".to_vec());
        state.insert(key(0), b"actual-head".to_vec());
        let records: &[(u64, &[u8])] = &[(1, b"actual-intent"), (2, b"actual-plan")];

        require_exact_controller_prefix_v1(&state, lane, records, b"actual-head").unwrap();
        assert!(require_exact_controller_prefix_v1(&state, lane, records, b"other-head").is_err());
        state.insert(key(3), b"foreign-later-row".to_vec());
        assert!(require_exact_controller_prefix_v1(&state, lane, records, b"actual-head").is_err());
    }
}
