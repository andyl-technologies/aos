//! Prices and retains the closed post-ACK public Create terminal append.
//!
//! The passive invoice is consumed before final748, while the same current
//! Applying/Applied Controller and its REQUESTED projection remain held. It
//! grants no append authority; the actual post-ACK destination is separate.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectLedgerRecord, EffectHistoryDataError, EffectState, decode_effect_with_q04,
    CreateStoppedPreAckTransactionDataV1, CreateStoppedTerminalTransactionDataV1,
    create_stopped_terminal_transaction_id_v1, effect_decoding_receiving_bytes_v1,
};
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1;
use aos_sandbox_protocol::domain_ledger::operation::{
    OperationRecord, decode_operation, encode_operation_record, effect_key,
};
use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
use aos_sandbox_protocol::public_api::projection::{
    PROJECTION_KEY_PREFIX, PublicProjectionKindV1, PublicProjectionRecordV1,
    PublicProjectionPlanV1, PublicProjectionError, PublicProjectionResourceV1, projection_key,
};

use super::{CommitResult, Journal, JournalError, JournalTransaction, RecordNamespace};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, CreateStoppedPostAckContextV1};
use aos_sandbox_api::aos::sandbox::v1::SandboxPhase;
use sha2::{Digest as _, Sha256};
use super::JournalRecord;
use super::historical_observation::HistoricalObservationV1;

mod receiving;
mod start;
pub(crate) use start::{LifecycleTerminalMetadataOriginalV4, start_terminal_receiving_demand_v2};

impl Journal {
    pub(crate) fn recovered_metadata_append_receiving_demand_v1(&self, parent: OperationId)
        -> Result<ResourceVector, JournalError> {
        receiving::recovered_native_append_demand_v1(self, parent)
    }
}

/// Prices the same Stop models and joint Recover row before atomic assembly.
///
/// # Errors
/// Refuses missing protected models or checked shared supplier overflow.
pub(crate) fn stop_cleanup_terminal_model_receiving_demand_v1(journal: &Journal, parent: OperationId)
    -> Result<ResourceVector, JournalError> {
    receiving::stop_cleanup_terminal_model_demand_v1(journal, parent)
}

#[derive(Clone, Copy)]
enum FirstV1 { Entry, Geometry, Parent, Effect, Projection, Successor, Transaction, Append }

/// Retains the reached post-ACK Controller models and native append result.
pub(crate) struct CreateStoppedControllerTerminalAppendOriginalV1 {
    parent: OperationId,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    models: Option<Box<TerminalModelsV1>>,
    retired: Option<CommitResult>,
    first: Option<FirstV1>,
}

struct TerminalModelsV1 {
    parent: Option<Result<OperationRecord, crate::ReconcilerError>>,
    effect: Option<Result<(EffectLedgerRecord, Option<Q04EffectSubgateV1>), EffectHistoryDataError>>,
    projection: Option<Result<PublicProjectionRecordV1, PublicProjectionError>>,
    candidate: Option<aos_sandbox_api::aos::sandbox::v1::Sandbox>,
    candidate_check: Option<Result<(), PublicProjectionError>>,
    successor: Option<Result<PublicProjectionPlanV1, PublicProjectionError>>,
    operation: Option<Result<Vec<u8>, crate::ReconcilerError>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    append: Option<Result<CommitResult, JournalError>>,
}

impl CreateStoppedControllerTerminalAppendOriginalV1 {
    /// Requires the actual native terminal append without manufacturing a cause.
    pub(crate) fn completed_v1(&self) -> Result<CommitResult, JournalError> {
        if self.first.is_some() { return Err(JournalError::ProtectedBoundary); }
        if let Some(result) = self.retired { return Ok(result); }
        self.models.as_ref().and_then(|models| models.append.as_ref())
            .and_then(|v| v.as_ref().ok()).copied().ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows the exact first reached semantic or native cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let models = self.models.as_deref();
        match self.first? {
            FirstV1::Entry => cause(&self.entry),
            FirstV1::Geometry => cause(&self.geometry),
            FirstV1::Parent => models.and_then(|m| cause(&m.parent)),
            FirstV1::Effect => models.and_then(|m| cause(&m.effect)),
            FirstV1::Projection => models.and_then(|m| cause(&m.projection)),
            FirstV1::Successor => models.and_then(|m| cause(&m.operation).or_else(|| cause(&m.candidate_check)).or_else(|| cause(&m.successor))),
            FirstV1::Transaction => models.and_then(|m| cause(&m.transaction)),
            FirstV1::Append => models.and_then(|m| cause(&m.append)),
        }
    }
}

/// Prices the actual three-row Controller terminal branch before final748.
///
/// This nonauthorizing supplier reads only held raw extents. The sole terminal
/// successor preserves the exact Applied516 Effect, uses the fixed-width
/// existing Operation encoder, and changes only observed phase and sequence
/// in the existing Sandbox projection. Both phases occupy one protobuf byte;
/// incrementing one nonzero uint64 adds at most nine bytes plus one byte in
/// its enclosing length prefix. All other fields are preserved.
///
/// # Errors
/// Refuses absent held rows, missing Sandbox projections, or arithmetic and
/// canonical append/decoder geometry overflow.
pub(crate) fn create_stopped_terminal_receiving_demand_v1(journal: &Journal,
    parent: OperationId,
) -> Result<ResourceVector, JournalError> {
    receiving::native_append_demand_v1(journal, parent)
}

/// Measures only the actual pure terminal recipe used by an independent reader.
///
/// Native append IO, writer carriers and financial admission are not included.
/// This passive supplier cannot grant an append or a completion lender.
pub(crate) fn create_stopped_metadata_model_receiving_demand_v1(
    journal: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    parent: OperationId,
) -> Result<ResourceVector, JournalError> {
    receiving::independent_model_demand_v1(journal, parent)
}


/// Prices the exact passive geometry interfaces before their first traversal.
///
/// The caller must join this Memory-only amount to its actual earlier fixed
/// Stage. It authenticates no Rows and cannot issue a reader or append grant.
pub(crate) fn create_stopped_geometry_control_bytes_v2() -> Option<usize> {
    receiving::geometry_control_bytes_v2()?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

/// Prices the independent Rows geometry before its real Root fixed admission.
///
/// This contains no ordinary Journal/view constructor or native owner fee.
pub(crate) fn create_stopped_independent_geometry_control_bytes_v2() -> Option<usize> {
    receiving::independent_geometry_control_bytes_v2()?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}


impl CreateStoppedControllerTerminalAppendOriginalV1 {
    fn record_once_v1(context: &mut CreateStoppedPostAckContextV1<'_>, journal: &mut Journal) -> Self {
        let mut actual = Self { parent: context.parent_operation_v1(), entry: None,
            geometry: None, models: None, retired: None, first: None };
        actual.entry = Some(context.require_current_v1(journal));
        if !matches!(actual.entry, Some(Ok(()))) {
            actual.first = Some(FirstV1::Entry);
            return actual;
        }
        actual.geometry = Some(create_stopped_terminal_receiving_demand_v1(journal, actual.parent));
        if !matches!(actual.geometry, Some(Ok(_))) {
            actual.first = Some(FirstV1::Geometry);
            return actual;
        }
        // The exact terminal destination already paid this complete shape
        // before748. No healthy payer or financial raise occurs after ACK.
        actual.models = Some(Box::new(TerminalModelsV1::new()));
        if let Err(first) = actual.record_body_v1(context, journal) { actual.first = Some(first); }
        actual
    }

    fn record_body_v1(&mut self, context: &mut CreateStoppedPostAckContextV1<'_>,
        journal: &mut Journal,
    ) -> Result<(), FirstV1> {
        let models = self.models.as_mut().ok_or(FirstV1::Entry)?;
        prepare_terminal_metadata_models_v1(models, HistoricalObservationV1::from_journal_v1(journal), self.parent,
            TerminalMetadataInputV1::PostAck { context, journal })?;
        let transaction = models.transaction.as_ref().and_then(|v| v.as_ref().ok()).ok_or(FirstV1::Transaction)?;
        let effect_key = effect_key(self.parent, 0);
        let key = projection_key(PublicProjectionKindV1::Sandbox, *context.sandbox_v1().as_bytes());
        let mut loan = CreateStoppedControllerTerminalAppendLoanV1 { context, transaction,
            before: [
                Sha256::digest(journal.get(RecordNamespace::Effect, &effect_key).ok_or(FirstV1::Effect)?).into(),
                Sha256::digest(journal.get(RecordNamespace::Operation, self.parent.as_bytes()).ok_or(FirstV1::Parent)?).into(),
                Sha256::digest(journal.get(RecordNamespace::DesiredState, &key).ok_or(FirstV1::Projection)?).into(),
            ],
        };
        models.append = Some(journal.commit_create_storage_original_v1(transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::CreateStoppedTerminal(&mut loan)));
        if matches!(models.append, Some(Ok(_))) { Ok(()) } else { Err(FirstV1::Append) }
    }
}

// A finite input selects the same pure recipe. Only PostAck has a genuine
// append destination; IndependentRead can produce transaction DATA only.
enum TerminalMetadataInputV1<'call, 'turn> {
    PostAck { context: &'call CreateStoppedPostAckContextV1<'turn>, journal: &'call Journal },
    IndependentRead {
        project: aos_sandbox_model::ProjectId,
        sandbox: aos_sandbox_model::SandboxId,
        receipt: &'call [u8],
        sample: aos_sandbox_model::RawPairedClockSample,
    },
}

impl TerminalMetadataInputV1<'_, '_> {
    fn project_v1(&self) -> aos_sandbox_model::ProjectId {
        match self { Self::PostAck { context, .. } => context.project_v1(),
            Self::IndependentRead { project, .. } => *project }
    }

    fn sandbox_v1(&self) -> aos_sandbox_model::SandboxId {
        match self { Self::PostAck { context, .. } => context.sandbox_v1(),
            Self::IndependentRead { sandbox, .. } => *sandbox }
    }

    fn receipt_bytes_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        match self { Self::PostAck { context, .. } => context.receipt_bytes_v1(),
            Self::IndependentRead { receipt, .. } => Ok(receipt) }
    }

    fn actual_after_clock_v1(&self) -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1> {
        match self { Self::PostAck { context, .. } => context.actual_after_clock_v1(),
            Self::IndependentRead { sample, .. } => Ok(*sample) }
    }

    fn require_controller_transition_v1(&self, transaction: &JournalTransaction)
        -> Result<(), JournalError> {
        match self { Self::PostAck { context, journal } => context.require_controller_transition_v1(journal, transaction),
            Self::IndependentRead { .. } => Ok(()) }
    }
}

fn prepare_terminal_metadata_models_v1(
    models: &mut TerminalModelsV1,
    journal: HistoricalObservationV1<'_>,
    parent: OperationId,
    context: TerminalMetadataInputV1<'_, '_>,
) -> Result<(), FirstV1> {
    models.parent = Some((|| {
        let raw = journal.get(RecordNamespace::Operation, parent.as_bytes())
            .ok_or(crate::ReconcilerError::CorruptLedger("post-ACK Create parent is absent"))?;
        let parent = decode_operation(raw)?;
        if parent.state() != OperationState::Applying || parent.effect_count() != 1 {
            return Err(crate::ReconcilerError::CorruptLedger("post-ACK Create parent changed"));
        }
        Ok(parent)
    })());
    if !matches!(models.parent, Some(Ok(_))) { return Err(FirstV1::Parent); }
    let effect_key = effect_key(parent, 0);
    models.effect = Some((|| {
        let raw = journal.get(RecordNamespace::Effect, &effect_key)
            .ok_or(EffectHistoryDataError::CorruptLedger("post-ACK Effect is absent"))?;
        let value = decode_effect_with_q04(raw)?;
        let receipt = context.receipt_bytes_v1().map_err(|_|
            EffectHistoryDataError::CorruptLedger("post-ACK receipt is absent"))?;
        if value.1.as_ref().is_none_or(|gate| gate.status() != 4)
            || !matches!(value.0.state(), EffectState::Applied { receipt: applied, .. }
                if applied.as_bytes() == receipt) {
            return Err(EffectHistoryDataError::CorruptLedger("post-ACK Applied receipt changed"));
        }
        Ok(value)
    })());
    if !matches!(models.effect, Some(Ok(_))) { return Err(FirstV1::Effect); }
    models.projection = Some(crate::controller_service::public_projection::get_from_observation_v2(
            journal, PublicProjectionKindV1::Sandbox, *context.sandbox_v1().as_bytes())
        .and_then(|value| value.ok_or(PublicProjectionError::CorruptRecord)));
    if !matches!(models.projection, Some(Ok(_))) { return Err(FirstV1::Projection); }
    models.operation = Some((|| {
        let before = models.parent.as_ref().and_then(|v| v.as_ref().ok()).copied()
            .ok_or(crate::ReconcilerError::CorruptLedger("post-ACK parent is incomplete"))?;
        let sample = context.actual_after_clock_v1()
            .map_err(|_| crate::ReconcilerError::PublicOperationClock)?;
        let after = crate::reconciler::transition_operation(before, OperationState::Succeeded,
            Some(sample.wall_seconds()))?;
        Ok(encode_operation_record(after))
    })());
    if !matches!(models.operation, Some(Ok(_))) { return Err(FirstV1::Successor); }
    models.candidate_check = Some((|| {
        let before = models.projection.as_ref().and_then(|v| v.as_ref().ok())
            .ok_or(PublicProjectionError::CorruptRecord)?;
        terminal_sandbox_candidate_v2(&mut models.candidate, before, parent, context.project_v1(),
            TerminalObservationV2::CreateStopped)?;
        Ok(())
    })());
    if !matches!(models.candidate_check, Some(Ok(()))) { return Err(FirstV1::Successor); }
    models.successor = Some((|| {
        let candidate = models.candidate.as_ref().ok_or(PublicProjectionError::CorruptRecord)?;
        PublicProjectionPlanV1::new(context.project_v1(), parent,
            PublicProjectionResourceV1::Sandbox(candidate.clone()))
    })());
    if !matches!(models.successor, Some(Ok(_))) { return Err(FirstV1::Successor); }
    models.transaction = Some((|| {
        let key = projection_key(PublicProjectionKindV1::Sandbox, *context.sandbox_v1().as_bytes());
        let effect = journal.get(RecordNamespace::Effect, &effect_key).ok_or(JournalError::ProtectedBoundary)?;
        let parent_bytes = journal.get(RecordNamespace::Operation, parent.as_bytes()).ok_or(JournalError::ProtectedBoundary)?;
        let projection = journal.get(RecordNamespace::DesiredState, &key).ok_or(JournalError::ProtectedBoundary)?;
        CreateStoppedPreAckTransactionDataV1::from_data_v1(parent, context.project_v1(),
            context.sandbox_v1(), parent_bytes, effect, &key, projection).map_err(terminal_error)?;
        let operation = models.operation.as_ref().and_then(|v| v.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        let successor = models.successor.as_ref().and_then(|v| v.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        let transaction = JournalTransaction::new(create_stopped_terminal_transaction_id_v1(parent, effect), vec![
            JournalRecord::put(RecordNamespace::Effect, effect_key.to_vec(), effect.to_vec()),
            JournalRecord::put(RecordNamespace::Operation, parent.as_bytes().to_vec(), operation.clone()),
            JournalRecord::put(RecordNamespace::DesiredState, successor.desired_key().to_vec(), successor.desired_value().to_vec()),
        ]).map_err(JournalError::from)?;
        CreateStoppedTerminalTransactionDataV1::from_data_v1(parent, context.project_v1(),
            context.sandbox_v1(), operation, effect).and_then(|data| data.require_transaction_v1(&transaction))
            .map_err(terminal_error)?;
        context.require_controller_transition_v1(&transaction)?;
        Ok(transaction)
    })());
    if !matches!(models.transaction, Some(Ok(_))) { return Err(FirstV1::Transaction); }
    Ok(())
}

// The two actual public terminal writers share projection ownership, phase
// sequencing and canonical model validation; only their observed facts differ.
pub(crate) fn stop_terminal_receiving_demand_v5(journal: &Journal, parent: OperationId, residual: bool)
    -> Result<ResourceVector, JournalError> {
    receiving::stop_terminal_model_demand_v5(journal, parent, residual)
}

enum TerminalObservationV2<'manifest> {
    CreateStopped,
    StartRunning(&'manifest aos_sandbox_model::CanonicalAssignmentManifestV1),
    Stopped(crate::lifecycle::LiveRuntimeFenceV1),
}

fn terminal_sandbox_candidate_v2(candidate: &mut Option<aos_sandbox_api::aos::sandbox::v1::Sandbox>,
    before: &PublicProjectionRecordV1,
    parent: OperationId, project: aos_sandbox_model::ProjectId, next: TerminalObservationV2<'_>,
) -> Result<(), PublicProjectionError> {
    if before.operation() != parent || before.project() != project {
        return Err(PublicProjectionError::CorruptRecord);
    }
    let PublicProjectionResourceV1::Sandbox(sandbox) = before.resource() else {
        return Err(PublicProjectionError::CorruptRecord);
    };
    *candidate = Some(sandbox.clone());
    let candidate = candidate.as_mut().ok_or(PublicProjectionError::CorruptRecord)?;
    let observed = candidate.observed.as_option_mut().ok_or(PublicProjectionError::CorruptRecord)?;
    if observed.observation_sequence == 0 { return Err(PublicProjectionError::CorruptRecord); }
    match next {
        TerminalObservationV2::CreateStopped => {
            if observed.phase.as_known() != Some(SandboxPhase::SANDBOX_PHASE_REQUESTED) {
                return Err(PublicProjectionError::CorruptRecord);
            }
            observed.phase = SandboxPhase::SANDBOX_PHASE_STOPPED.into();
        }
        TerminalObservationV2::Stopped(fence) => {
            let desired = candidate.desired.as_option().ok_or(PublicProjectionError::CorruptRecord)?;
            if desired.lifecycle.as_known() != Some(aos_sandbox_api::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED)
                || fence.desired().expected_generation().get().checked_add(1) != Some(desired.generation)
                || observed.desired_generation != fence.desired().expected_generation().get()
                || observed.incarnation_id.as_slice() != fence.incarnation().as_bytes()
                || observed.assignment_epoch != fence.assignment_epoch().get()
                || sandbox.sandbox_id.as_slice() != fence.sandbox().as_bytes()
            { return Err(PublicProjectionError::CorruptRecord); }
            observed.phase = SandboxPhase::SANDBOX_PHASE_STOPPED.into();
            observed.desired_generation = desired.generation;
        }
        TerminalObservationV2::StartRunning(manifest) => {
            let desired = candidate.desired.as_option().ok_or(PublicProjectionError::CorruptRecord)?;
            if observed.phase.as_known() != Some(SandboxPhase::SANDBOX_PHASE_STOPPED)
                || desired.lifecycle.as_known() != Some(aos_sandbox_api::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING)
                || desired.generation != manifest.manifest().desired_generation().get()
                || observed.desired_generation.checked_add(1) != Some(desired.generation)
                || sandbox.sandbox_id.as_slice() != manifest.manifest().sandbox().as_bytes()
            { return Err(PublicProjectionError::CorruptRecord); }
            // READY is the public running phase: it carries the actual live
            // assignment placement qualified by HostDone and GuardianReady.
            observed.phase = SandboxPhase::SANDBOX_PHASE_READY.into();
            observed.incarnation_id = manifest.manifest().incarnation().as_bytes().to_vec();
            observed.node_id = manifest.manifest().node().as_bytes().to_vec();
            observed.assignment_epoch = manifest.manifest().epoch().get();
            observed.desired_generation = manifest.manifest().desired_generation().get();
        }
    }
    observed.observation_sequence = observed.observation_sequence.checked_add(1)
        .ok_or(PublicProjectionError::CorruptRecord)?;
    Ok(())
}

impl TerminalModelsV1 {
    fn new() -> Self {
        Self { parent: None, effect: None, projection: None, candidate: None,
            candidate_check: None, successor: None, operation: None,
            transaction: None, append: None }
    }
}

/// Retains the sole canonical three-row terminal recipe as nonauthorizing DATA.
///
/// The independent Root reader pays and constructs this owner from its actual
/// current C models. Only a separate genuine purpose-bound completion lender
/// may allow a native caller to append its exact transaction.
pub(crate) struct CreateStoppedMetadataTransitionOriginalV1 {
    models: TerminalModelsV1,
    prepared: bool,
    first: Option<FirstV1>,
    reentered: bool,
}

impl CreateStoppedMetadataTransitionOriginalV1 {
    /// Prices the independent reader's exact new same-owner interfaces.
    pub(crate) fn observation_control_bytes_v2() -> Option<usize> {
        size_of::<HistoricalObservationV1<'_>>().checked_mul(3)?
            .checked_add(size_of::<(
                &mut Self, HistoricalObservationV1<'_>, OperationId,
                aos_sandbox_model::ProjectId, aos_sandbox_model::SandboxId, &[u8],
                aos_sandbox_model::RawPairedClockSample,
            )>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?)?
            .checked_add(crate::controller_service::public_projection::projection_observation_control_bytes_v2()?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(crate) fn new() -> Self {
        Self { models: TerminalModelsV1::new(), prepared: false, first: None, reentered: false }
    }

    pub(crate) fn prepare_once_v1(&mut self, journal: HistoricalObservationV1<'_>,
        parent: OperationId, project: aos_sandbox_model::ProjectId,
        sandbox: aos_sandbox_model::SandboxId, receipt: &[u8],
        sample: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        if self.prepared {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.prepared = true;
        if let Err(first) = prepare_terminal_metadata_models_v1(&mut self.models,
            journal, parent, TerminalMetadataInputV1::IndependentRead { project, sandbox, receipt, sample }) {
            self.first = Some(first);
            return Err(JournalError::ProtectedBoundary);
        }
        self.transaction_v1().map(|_| ())
    }

    pub(crate) fn transaction_v1(&self) -> Result<&JournalTransaction, JournalError> {
        if !self.prepared || self.first.is_some() || self.reentered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.models.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let models = &self.models;
        let selected = match self.first {
            None => return self.reentered.then_some(&METADATA_CLOSED as _),
            Some(first) => first,
        };
        match selected {
            FirstV1::Parent => cause(&models.parent),
            FirstV1::Effect => cause(&models.effect),
            FirstV1::Projection => cause(&models.projection),
            FirstV1::Successor => cause(&models.operation).or_else(|| cause(&models.candidate_check))
                .or_else(|| cause(&models.successor)),
            FirstV1::Transaction => cause(&models.transaction),
            _ => None,
        }
    }
}

const METADATA_CLOSED: JournalError = JournalError::ProtectedBoundary;

/// Borrows the actual ACK-dependent destination and one exact terminal CAS.
pub(super) struct CreateStoppedControllerTerminalAppendLoanV1<'loan, 'turn> {
    context: &'loan CreateStoppedPostAckContextV1<'turn>,
    transaction: &'loan JournalTransaction,
    before: [[u8; 32]; 3],
}

impl CreateStoppedControllerTerminalAppendLoanV1<'_, '_> {
    pub(super) fn matches_identity_v1(&self,
        identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    ) -> bool {
        self.context.parent_operation_v1() == identity.operation()
            && self.context.project_v1() == identity.project()
            && self.context.sandbox_v1() == identity.sandbox()
    }

    pub(super) fn require_transition(&self, journal: &Journal, transaction: &JournalTransaction)
        -> Result<(), JournalError> {
        if transaction != self.transaction { return Err(JournalError::ProtectedBoundary); }
        let parent = self.context.parent_operation_v1();
        let key = projection_key(PublicProjectionKindV1::Sandbox, *self.context.sandbox_v1().as_bytes());
        let rows = [
            journal.get(RecordNamespace::Effect, &effect_key(parent, 0)),
            journal.get(RecordNamespace::Operation, parent.as_bytes()),
            journal.get(RecordNamespace::DesiredState, &key),
        ];
        for (raw, before) in rows.into_iter().zip(self.before) {
            if raw.is_none_or(|raw| <[u8; 32]>::from(Sha256::digest(raw)) != before) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        self.context.require_controller_transition_v1(journal, transaction)
    }

    pub(super) fn final_crossing(&self, journal: &Journal) -> Result<(), JournalError> {
        self.require_transition(journal, self.transaction)?;
        self.context.final_crossing_v1(journal, self.transaction)
    }
}

impl Journal {
    /// Commits the specific prearmed post-ACK public terminal transition.
    ///
    /// # Errors
    /// Retains every reached semantic/native result in the original attempt;
    /// no failure changes the already durable Applied or Source success prefix.
    pub(crate) fn record_create_stopped_terminal_once_v1(&mut self,
        context: &mut CreateStoppedPostAckContextV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let actual = CreateStoppedControllerTerminalAppendOriginalV1::record_once_v1(context, self);
        context.retain_controller_append_original_v1(actual)
    }
}

fn terminal_error(cause: aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedTerminalDataErrorV1)
    -> JournalError {
    JournalError::Q04ControllerLedger(Box::new(crate::ReconcilerError::from(cause)))
}

fn cause<T, E: Error + 'static>(v: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    v.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_owner_keeps_earlier_successor_cause_before_later_native_refusal() {
        let actual = CreateStoppedControllerTerminalAppendOriginalV1 {
            parent: OperationId::from_bytes([1; 16]), entry: Some(Ok(())),
            geometry: None, retired: None, first: Some(FirstV1::Successor),
            models: Some(Box::new(TerminalModelsV1 {
                parent: None, effect: None, projection: None, candidate: None,
                candidate_check: Some(Err(PublicProjectionError::CorruptRecord)),
                successor: None, operation: None, transaction: None,
                append: Some(Err(JournalError::ProtectedBoundary)),
            })),
        };
        let selected = actual.models.as_ref().unwrap().candidate_check.as_ref().unwrap()
            .as_ref().unwrap_err();

        assert!(std::ptr::eq(actual.failure().unwrap().downcast_ref::<PublicProjectionError>().unwrap(), selected));
        assert!(actual.completed_v1().is_err());
        assert!(actual.models.as_ref().unwrap().candidate_check.as_ref().unwrap().is_err());
    }

    #[test]
    fn terminal_owner_retains_transition_journal_cause_before_append_refusal() {
        let mut models = TerminalModelsV1::new();
        models.transaction = Some(Err(JournalError::ProtectedBoundary));
        models.append = Some(Err(JournalError::ProtectedBoundary));
        let actual = CreateStoppedControllerTerminalAppendOriginalV1 {
            parent: OperationId::from_bytes([1; 16]),
            entry: Some(Ok(())),
            geometry: None,
            models: Some(Box::new(models)),
            retired: None,
            first: Some(FirstV1::Transaction),
        };
        let selected = actual.models.as_ref().unwrap().transaction.as_ref().unwrap()
            .as_ref().unwrap_err();

        assert!(std::ptr::eq(
            actual.failure().unwrap().downcast_ref::<JournalError>().unwrap(),
            selected,
        ));
        assert!(actual.completed_v1().is_err());
    }
}


impl CreateStoppedControllerTerminalAppendOriginalV1 {
    // Called only after the upper actual Source/C/clock/native full relation.
    // Keep the real native CommitResult and once/failure state; only successful
    // pure decoded/candidate/encoded transaction payloads are retired.
    pub(crate) fn retire_completed_payloads_v1(&mut self) -> Result<(), JournalError> {
        if self.retired.is_some() || self.models.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        let result = self.completed_v1()?;
        self.retired = Some(result);
        self.models = None;
        Ok(())
    }
}
