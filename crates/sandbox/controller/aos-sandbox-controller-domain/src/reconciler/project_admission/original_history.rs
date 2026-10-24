//! Owns complete Controller original-Create history and its retained readbacks.
//!
//! Replay joins the original Operation, Effect, raw idempotency row and actual
//! journal index, captured/current projections, and authenticated capacity.
//! Retained flight and terminal readbacks share that complete Native graph.
//! The history-floor factory keeps its protected COMMIT/readback beside the
//! opaque Journal borrow consumed by Source ACK. None grants current policy,
//! Root transport authority, Create success, or release of an owner hold.

use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    CONTROLLER_PROJECT_EFFECT_VERSION, EffectLedgerRecord, EffectPlan, EffectState, decode_effect,
    encode_effect,
};
use aos_sandbox_protocol::domain_ledger::operation::{
    OperationRecord, decode_operation, effect_key, encode_operation_record,
};
use aos_sandbox_protocol::domain_ledger::public_operation::{OperationState, resource_version};
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionKindV1, PublicProjectionRecordV1, PublicProjectionResourceV1,
};
use sha2::{Digest as _, Sha256};

use crate::controller::ControllerRequestScopeV1;
use crate::controller_service::public_projection::PublicProjectionStoreV1;
use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, IdempotencyOutcome,
    Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
    SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1,
};
use crate::policy_compiler::{
    RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeV1,
    RootProjectHistoryFloorProofV1, RootProjectHistoryFloorV1, RootProjectHistoryTerminalKindV1,
    create_project_source_commitment_v1,
};
use crate::reconciler::{ReconcilerError, recovered_public_operation_admission_v1};

use super::{
    ControllerProjectAdmissionJournalErrorV1, ProjectAdmissionMetadata, ProjectAdmissionPhase,
    RetainedRootProjectTerminal,
};

const CAPACITY_DOMAIN: &[u8] = b"aos.sandbox.controller-project-capacity-owner.v1\0";

/// Retains the actual original Effect selected for historical recovery.
///
/// This readback does not authorize a new dispatch or owner transition. Each
/// consumer separately rechecks the protected original Effect and its phase.
pub struct RetainedControllerProjectAdmissionV1 {
    operation: aos_sandbox_model::OperationId,
    plan: EffectPlan,
    metadata: ProjectAdmissionMetadata,
}

impl RetainedControllerProjectAdmissionV1 {
    /// Returns the immutable original operation.
    #[must_use]
    pub const fn operation(&self) -> aos_sandbox_model::OperationId {
        self.operation
    }

    /// Returns the exact original Effect plan.
    #[must_use]
    pub const fn plan(&self) -> &EffectPlan {
        &self.plan
    }

    /// Returns the Source reservation retained before dispatch.
    #[must_use]
    pub const fn reservation(&self) -> SourceProjectAdmissionReservationV1 {
        self.metadata.reservation()
    }

    /// Reports whether Root dispatch has not yet been authorized.
    #[must_use]
    pub const fn is_prepared(&self) -> bool {
        matches!(self.metadata.phase(), ProjectAdmissionPhase::Prepared)
    }

    /// Reports whether an exact Root terminal was accepted locally.
    #[must_use]
    pub const fn has_accepted_terminal(&self) -> bool {
        matches!(
            self.metadata.phase(),
            ProjectAdmissionPhase::AcceptedRootTerminal | ProjectAdmissionPhase::RootRetired
        )
    }

    /// Returns the historical outcome, without establishing Root transport.
    #[must_use]
    pub const fn outcome(&self) -> Option<RootProjectAdmissionOutcomeV1> {
        match self.metadata.terminal() {
            Some(RetainedRootProjectTerminal::Outcome(outcome)) => Some(outcome),
            _ => None,
        }
    }
}

/// Selects one original Effect for exact Source-flight recovery.
///
/// The configured scope is checked against the protected idempotency decision.
/// A Source row without matching metadata cannot be adopted. With no Source
/// row, only the unique nonretired Controller flight is returned; a node with
/// no flight therefore has no Root-service startup dependency.
///
/// # Errors
///
/// Rejects changed fixed names, an inconsistent original admission or request,
/// an ambiguous flight, or a mismatched configured request scope.
pub fn retained_controller_project_admission_v1(
    journal: &Journal,
    scope: ControllerRequestScopeV1,
    reservation: Option<SourceProjectAdmissionReservationV1>,
) -> Result<Option<RetainedControllerProjectAdmissionV1>, ControllerProjectAdmissionJournalErrorV1>
{
    require_controller_writer(journal)?;
    validate_all(journal)?;
    let mut selected = None;
    for (key, bytes) in journal.records(RecordNamespace::Effect) {
        if bytes.first() != Some(&CONTROLLER_PROJECT_EFFECT_VERSION) {
            continue;
        }
        let effect = decode_effect(bytes)
            .map_err(ReconcilerError::from)?
            .into_parts();
        let Some(metadata) = effect.3 else {
            continue;
        };
        let matches = match reservation {
            Some(reservation) => metadata.reservation() == reservation,
            None => metadata.phase() != ProjectAdmissionPhase::RootRetired,
        };
        if !matches {
            continue;
        }
        let operation = aos_sandbox_model::OperationId::from_bytes(
            key.get(..16)
                .ok_or_else(invalid_metadata)?
                .try_into()
                .map_err(|_| invalid_metadata())?,
        );
        if selected.is_some()
            || checked_live_create_sandbox_admission_revision_v1(
                journal, operation, scope, &effect.0,
            )?
            .is_none()
        {
            return Err(invalid_metadata().into());
        }
        selected = Some(RetainedControllerProjectAdmissionV1 {
            operation,
            plan: effect.0,
            metadata,
        });
    }
    Ok(selected)
}

pub(crate) struct AcceptedControllerProjectTerminalV1 {
    pub operation: aos_sandbox_model::OperationId,
    pub sandbox: SandboxId,
    pub project: ProjectId,
    pub source_commitment: ObjectDigest,
    pub admission_revision: ObjectDigest,
    pub admission_generation: u64,
    pub accepted_metadata: ObjectDigest,
    pub reservation: SourceProjectAdmissionReservationV1,
    pub challenge: Option<SourceProjectAdmissionChallengeV1>,
    pub root_terminal: ObjectDigest,
    pub kind: RootProjectHistoryTerminalKindV1,
}

/// Retains an actual immutable flight, solely to obtain a durable Root denial.
pub(crate) struct ControllerProjectDispatchReadbackV1 {
    pub operation: aos_sandbox_model::OperationId,
    pub sandbox: SandboxId,
    pub project: ProjectId,
    pub source_commitment: ObjectDigest,
    pub admission_revision: ObjectDigest,
    pub admission_generation: u64,
    pub metadata: ObjectDigest,
    pub reservation: SourceProjectAdmissionReservationV1,
}

pub(crate) fn controller_project_dispatch_readback_v1(
    journal: &Journal,
    operation: aos_sandbox_model::OperationId,
) -> Result<ControllerProjectDispatchReadbackV1, ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    dispatch_readback_from_original_graph(journal, operation)
}

pub(super) fn dispatch_readback_from_original_graph(
    journal: &Journal,
    operation: aos_sandbox_model::OperationId,
) -> Result<ControllerProjectDispatchReadbackV1, ControllerProjectAdmissionJournalErrorV1> {
    validate_all(journal)?;
    let effect = decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or_else(invalid_metadata)?,
    )
    .map_err(ReconcilerError::from)?
    .into_parts();
    let metadata = effect.3.ok_or_else(invalid_metadata)?;
    if metadata.phase() != ProjectAdmissionPhase::DispatchAuthorized {
        return Err(invalid_metadata().into());
    }
    Ok(ControllerProjectDispatchReadbackV1 {
        operation,
        sandbox: metadata.sandbox(),
        project: metadata.project(),
        source_commitment: metadata.source_commitment(),
        admission_revision: metadata.admission_revision(),
        admission_generation: metadata.admission_generation(),
        metadata: ObjectDigest::from_bytes(
            Sha256::digest(metadata.encode().map_err(ReconcilerError::from)?).into(),
        ),
        reservation: metadata.reservation(),
    })
}

/// Reads only actual accepted original-Effect metadata under Controller custody.
pub(crate) fn accepted_controller_project_terminal_v1(
    journal: &Journal,
    operation: aos_sandbox_model::OperationId,
) -> Result<AcceptedControllerProjectTerminalV1, ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    validate_all(journal)?;
    let effect = decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or_else(invalid_metadata)?,
    )
    .map_err(ReconcilerError::from)?
    .into_parts();
    let metadata = effect.3.ok_or_else(invalid_metadata)?;
    // A previous RootRetired row is useful only for exact floor replay, never
    // to issue a new retirement carrier or nominate another historical cut.
    if metadata.phase() != ProjectAdmissionPhase::AcceptedRootTerminal {
        return Err(invalid_metadata().into());
    }
    let terminal = metadata.terminal().ok_or_else(invalid_metadata)?;
    Ok(AcceptedControllerProjectTerminalV1 {
        operation,
        sandbox: metadata.sandbox(),
        project: metadata.project(),
        source_commitment: metadata.source_commitment(),
        admission_revision: metadata.admission_revision(),
        admission_generation: metadata.admission_generation(),
        accepted_metadata: metadata
            .acceptance_digest()
            .map_err(ReconcilerError::from)?,
        reservation: metadata.reservation(),
        challenge: metadata.challenge(),
        root_terminal: terminal.record_digest(),
        kind: terminal.kind(),
    })
}

/// Borrows Controller custody after its exact historical Root-floor acceptance.
///
/// The borrow keeps the retained writer alive and excludes subsequent mutable
/// Controller cuts while Source immediately verifies and records its own ACK.
/// This token cannot be decoded, serialized, or minted from a digest. It never
/// authorizes Create success or owner-hold release.
pub struct ControllerProjectHistoryAcceptanceV1<'controller> {
    controller: &'controller Journal,
    operation: aos_sandbox_model::OperationId,
    accepted_metadata: ObjectDigest,
    floor: ObjectDigest,
}

impl ControllerProjectHistoryAcceptanceV1<'_> {
    pub(crate) fn validate_source_ack(
        &self,
        floor: RootProjectHistoryFloorV1,
        reservation: SourceProjectAdmissionReservationV1,
        challenge: Option<SourceProjectAdmissionChallengeV1>,
        source_terminal: ObjectDigest,
    ) -> Result<(), JournalError> {
        require_controller_writer(self.controller)?;
        validate_all(self.controller).map_err(|_| JournalError::ProtectedBoundary)?;
        let effect = decode_effect(
            self.controller
                .get(RecordNamespace::Effect, &effect_key(self.operation, 0))
                .ok_or(JournalError::ProtectedBoundary)?,
        )
        .map_err(ReconcilerError::from)
        .map_err(|_| JournalError::ProtectedBoundary)?
        .into_parts();
        let metadata = effect.3.ok_or(JournalError::ProtectedBoundary)?;
        if metadata.phase() != ProjectAdmissionPhase::RootRetired
            || metadata.retired_floor() != Some(self.floor)
            || floor.record_digest() != self.floor
            || metadata
                .acceptance_digest()
                .map_err(|_| JournalError::ProtectedBoundary)?
                != self.accepted_metadata
            || metadata.reservation() != reservation
            || metadata.challenge() != challenge
            || floor.source_terminal_digest() != source_terminal
            || !metadata.matches_floor(self.operation, floor)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

/// Durably accepts an exact Root history floor without completing Create.
///
/// The returned borrow is consumed immediately by Source's terminal ACK path;
/// Controller remains under the same retained writer throughout that join.
/// A lost reply replays the identical protected metadata without another cut.
///
/// # Errors
///
/// Rejects foreign custody, an altered original Create/admission, a changed
/// Root terminal or floor, missing accepted outcome, capacity loss, or an
/// ambiguous durable append/readback. No failed append lifts Source's fence.
pub fn accept_controller_project_history_floor_v1<'controller>(
    journal: &'controller mut Journal,
    operation: aos_sandbox_model::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    proof: RootProjectHistoryFloorProofV1,
) -> Result<
    ControllerProjectHistoryAcceptanceV1<'controller>,
    ControllerProjectAdmissionJournalErrorV1,
> {
    require_controller_writer(journal)?;
    let mut effect = load_scoped_effect(journal, operation, scope, plan)?;
    let prior = effect
        .project_admission()
        .cloned()
        .ok_or_else(invalid_metadata)?;
    let floor = proof.floor();
    if !prior.matches_floor(operation, floor)
        || !matches!(
            prior.phase(),
            ProjectAdmissionPhase::AcceptedRootTerminal | ProjectAdmissionPhase::RootRetired
        )
    {
        return Err(invalid_metadata().into());
    }
    let floor_digest = floor.record_digest();
    let accepted_metadata = prior.acceptance_digest().map_err(ReconcilerError::from)?;
    let next_phase = ProjectAdmissionPhase::RootRetired;
    let next_floor = Some(floor_digest);
    let mut next = prior.clone();
    next.set_historical_phase(next_phase);
    next.set_historical_retired_floor(next_floor);
    if prior.phase() == ProjectAdmissionPhase::RootRetired {
        if prior != next {
            return Err(invalid_metadata().into());
        }
    } else {
        let reservation = journal.recover_global_capacity_reservation_v1(prior.capacity_id())?;
        effect.set_project_admission(Some(next.clone()));
        let transaction = JournalTransaction::new(
            aos_sandbox_model::OperationId::new().into_bytes(),
            vec![
                effect_record(operation, &effect)?,
                reservation.settlement_record(),
            ],
        )
        .map_err(JournalError::from)?;
        let mut capacity = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
        )?;
        let preflight = capacity.preflight_reserved_terminal_v1(&reservation, &transaction)?;
        capacity.commit_reserved_terminal_v1(&preflight, reservation, &transaction)?;
    }
    require_controller_writer(journal)?;
    validate_all(journal)?;
    let readback = decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or_else(invalid_metadata)?,
    )
    .map_err(ReconcilerError::from)?;
    if readback.project_admission() != Some(next).as_ref() {
        return Err(invalid_metadata().into());
    }
    Ok(ControllerProjectHistoryAcceptanceV1 {
        controller: journal,
        operation,
        accepted_metadata,
        floor: floor_digest,
    })
}

/// Recovers the immutable admission revision of a live public Create effect.
///
/// The current public resource version advances with reconciliation. Rebuilding
/// the admitted records from the retained plan keeps the Source commitment
/// stable from Accepted through Applying and every retry. This is a readback,
/// not permission to execute Create or to release any owner hold.
///
/// # Errors
///
/// Returns an error for corrupt protected ledger records or an inconsistent
/// idempotency decision.
pub(crate) fn live_create_sandbox_admission_revision_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<(ObjectDigest, u64, [u8; 32])>, ReconcilerError> {
    retained_create_sandbox_admission_revision_v1(journal, operation_id, false)
}

pub(in crate::reconciler) fn retained_create_sandbox_admission_revision_v1(
    journal: &Journal,
    operation_id: OperationId,
    allow_terminal_history: bool,
) -> Result<Option<(ObjectDigest, u64, [u8; 32])>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation() else {
        return Ok(None);
    };
    // Production Create admission installs its immutable first generation.
    if operation.effect_count() != 1
        || operation.ownership_gated()
        || operation.runtime_intent_digest().is_some()
        || public.method()
            != aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox
        || public.accepted_generation() != 1
        || (!allow_terminal_history
            && !matches!(
                operation.state(),
                OperationState::Accepted | OperationState::Applying
            ))
    {
        return Ok(None);
    }

    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger(
            "live Create effect is absent",
        ))?;
    let effect = decode_effect(effect_bytes)
        .map_err(ReconcilerError::from)?
        .into_parts();
    let matching_live_state = matches!(
        (&operation.state(), &effect.1),
        (OperationState::Accepted, EffectState::Planned)
            | (OperationState::Applying, EffectState::Applying { .. })
    );
    let matching_terminal_history = allow_terminal_history
        && matches!(
            (&operation.state(), &effect.1),
            (
                OperationState::Succeeded
                    | OperationState::CanceledBeforeCommit
                    | OperationState::FailedBeforeCommit,
                EffectState::Applied { .. }
            ) | (
                OperationState::PermanentlyBlocked,
                EffectState::PermanentlyBlocked { .. }
            )
        );
    if (!matching_live_state && !matching_terminal_history)
        || effect.0.public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
    {
        return Ok(None);
    }
    let Some(context) = effect
        .0
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
    else {
        return Ok(None);
    };
    let admission = recovered_public_operation_admission_v1(journal, operation_id)?.ok_or(
        ReconcilerError::CorruptLedger("live Create admission is absent"),
    )?;
    let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
        context.canonical_request(),
    )
    .map_err(|_| ReconcilerError::CorruptLedger("live Create request is invalid"))?;
    if !matches!(
        request.request(),
        aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Create(_)
    ) || request.operation_method()
        != aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox
        || admission.project() != context.project()
        || admission.accepted_wall_seconds() != context.accepted_wall_seconds()
        || admission.authorization().resource_kind()
            != aos_sandbox_model::ResourceKind::ChildDelegation
        || request.selector() != Some(admission.authorization().selector())
        || request.target_project() != Some(admission.project())
    {
        return Ok(None);
    }
    let decision = journal
        .get(
            RecordNamespace::Idempotency,
            request.idempotency_key().as_bytes(),
        )
        .ok_or(ReconcilerError::CorruptLedger(
            "live Create idempotency decision is absent",
        ))?;
    if decision.len() != 48 || decision[32..] != *operation_id.as_bytes() {
        return Err(ReconcilerError::CorruptLedger(
            "live Create idempotency decision disagrees",
        ));
    }
    let request_digest: [u8; 32] = decision[..32]
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("live Create request digest is invalid"))?;
    if request_digest == [0; 32]
        || journal.check_idempotency(request.idempotency_key(), request_digest)
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(ReconcilerError::CorruptLedger(
            "live Create request digest disagrees",
        ));
    }

    let admitted_operation = encode_operation_record(OperationRecord::new(
        OperationState::Accepted,
        1,
        false,
        None,
        Some(admission.durable()),
    ));
    let admitted_effect = encode_effect(&EffectLedgerRecord::from_parts((
        effect.0,
        EffectState::Planned,
        None,
        None,
    )))
    .map_err(ReconcilerError::from)?;
    let revision = resource_version(operation_id, &admitted_operation, &[&admitted_effect]);

    Ok(Some((
        ObjectDigest::from_bytes(revision),
        public.accepted_generation(),
        request_digest,
    )))
}

/// Checks a live Create effect against its original scoped request digest.
///
/// This readback also requires the executor's plan to match the retained
/// effect exactly. The scope must come from the controller's configured
/// admission service, not from a public request.
///
/// # Errors
///
/// Returns an error for corrupt or inconsistent protected ledger records.
pub fn checked_live_create_sandbox_admission_revision_v1(
    journal: &Journal,
    operation_id: OperationId,
    scope: crate::controller::ControllerRequestScopeV1,
    expected_plan: &EffectPlan,
) -> Result<Option<(ObjectDigest, u64)>, ReconcilerError> {
    let Some((revision, generation, request_digest)) =
        live_create_sandbox_admission_revision_v1(journal, operation_id)?
    else {
        return Ok(None);
    };
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger(
            "live Create effect is absent",
        ))?;
    let effect = decode_effect(effect_bytes).map_err(ReconcilerError::from)?;
    if effect.plan() != expected_plan {
        return Ok(None);
    }
    let context = effect
        .plan()
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
        .ok_or(ReconcilerError::CorruptLedger(
            "live Create context is absent",
        ))?;
    if scope.public_request_digest(
        context.caller(),
        context.project(),
        context.canonical_request(),
    ) != request_digest
    {
        return Ok(None);
    }

    Ok(Some((revision, generation)))
}

pub(super) fn load_scoped_effect(
    journal: &Journal,
    operation: aos_sandbox_model::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
) -> Result<EffectLedgerRecord, ReconcilerError> {
    checked_live_create_sandbox_admission_revision_v1(journal, operation, scope, plan)?
        .ok_or_else(invalid_metadata)?;
    validate_all(journal)?;
    decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or_else(invalid_metadata)?,
    )
    .map_err(ReconcilerError::from)
}

pub(super) fn require_controller_writer(journal: &Journal) -> Result<(), JournalError> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 {
        return Err(JournalError::ProtectedBoundary);
    }
    journal.require_protected_named_location(
        std::path::Path::new("/var/lib/aos/sandboxd"),
        "controller.journal",
        uid,
        crate::journal::controller::production_journal_limits(),
    )
}

pub(super) fn capacity_request(
    operation: aos_sandbox_model::OperationId,
    metadata: &ProjectAdmissionMetadata,
    plan: &EffectPlan,
    future_transactions: u32,
    records: u32,
    bytes: u64,
) -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
        owner_namespace: RecordNamespace::Effect,
        owner_id: Sha256::new()
            .chain_update(CAPACITY_DOMAIN)
            .chain_update(effect_key(operation, 0))
            .finalize()
            .into(),
        owner_digest: *metadata.reservation().record_digest().as_bytes(),
        operation_id: *operation.as_bytes(),
        artifact_digest: Sha256::digest(plan.request()).into(),
        checkpoint_digest: *metadata.admission_revision().as_bytes(),
        chain_head_digest: *metadata.source_commitment().as_bytes(),
        future_transactions,
        terminal_records: records,
        terminal_bytes: bytes,
        poison_records: records,
        poison_bytes: bytes,
    }
}

pub(super) fn effect_record(
    operation: aos_sandbox_model::OperationId,
    effect: &EffectLedgerRecord,
) -> Result<JournalRecord, ReconcilerError> {
    Ok(JournalRecord::put(
        RecordNamespace::Effect,
        effect_key(operation, 0).to_vec(),
        encode_effect(effect).map_err(ReconcilerError::from)?,
    ))
}

pub(super) fn invalid_metadata() -> ReconcilerError {
    ReconcilerError::CorruptLedger("invalid Controller project-admission metadata")
}

/// Validates the immutable original Create join without granting currentness.
pub(in crate::reconciler) fn validate_all(journal: &Journal) -> Result<(), ReconcilerError> {
    let mut expected_capacity = std::collections::BTreeSet::new();
    let mut pending_flights = 0;
    for (key, bytes) in journal.records(RecordNamespace::Effect) {
        if bytes.first() != Some(&CONTROLLER_PROJECT_EFFECT_VERSION) {
            continue;
        }
        let effect = decode_effect(bytes).map_err(ReconcilerError::from)?;
        let Some(metadata) = effect.project_admission() else {
            continue;
        };
        let operation_bytes: [u8; 16] = key
            .get(..16)
            .ok_or_else(invalid_metadata)?
            .try_into()
            .map_err(|_| invalid_metadata())?;
        let operation = aos_sandbox_model::OperationId::from_bytes(operation_bytes);
        let (revision, generation, request_digest) = retained_create_sandbox_admission_revision_v1(
            journal,
            operation,
            metadata.phase() == ProjectAdmissionPhase::RootRetired,
        )?
        .ok_or_else(invalid_metadata)?;
        if key != effect_key(operation, 0)
            || create_project_source_commitment_v1(
                operation,
                metadata.admission_revision(),
                metadata.admission_generation(),
                metadata.sandbox(),
                metadata.project(),
                metadata.source_heads(),
            ) != metadata.source_commitment()
            || crate::policy_compiler::project_admission_client_nonce_v1(
                operation,
                metadata.source_commitment(),
            ) != metadata.reservation().client_nonce()
            || revision != metadata.admission_revision()
            || generation != metadata.admission_generation()
            || metadata.terminal().is_some_and(|terminal| {
                matches!(terminal,
                RetainedRootProjectTerminal::Outcome(outcome)
                    if outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
                        && outcome.operation() != operation_bytes)
            })
        {
            return Err(invalid_metadata());
        }
        let context = effect
            .plan()
            .public_mutation_context()
            .map_err(ReconcilerError::from)?
            .ok_or_else(invalid_metadata)?;
        if context.project() != metadata.project() {
            return Err(invalid_metadata());
        }
        validate_original_projection(journal, operation, metadata, effect.plan(), request_digest)?;
        if metadata.phase() == ProjectAdmissionPhase::RootRetired {
            if journal
                .lookup_global_capacity_reservation_v1(metadata.capacity_id())?
                .is_some()
            {
                return Err(invalid_metadata());
            }
        } else {
            pending_flights += 1;
            if pending_flights > 1 {
                return Err(invalid_metadata());
            }
            if !expected_capacity.insert(metadata.capacity_id()) {
                return Err(invalid_metadata());
            }
            let retained =
                journal.recover_global_capacity_reservation_v1(metadata.capacity_id())?;
            let request = retained.request();
            let (transactions, records) = match metadata.phase() {
                ProjectAdmissionPhase::Prepared => (3, 8),
                ProjectAdmissionPhase::DispatchAuthorized => (2, 5),
                ProjectAdmissionPhase::AcceptedRootTerminal => (1, 2),
                ProjectAdmissionPhase::RootRetired => return Err(invalid_metadata()),
            };
            if request
                != capacity_request(
                    operation,
                    metadata,
                    effect.plan(),
                    transactions,
                    records,
                    request.terminal_bytes,
                )
            {
                return Err(invalid_metadata());
            }
        }
    }
    let actual_capacity = journal
        .controller_project_capacity_ids_v1()?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if actual_capacity != expected_capacity {
        return Err(invalid_metadata());
    }
    Ok(())
}

pub(super) fn validate_original_projection(
    journal: &Journal,
    operation: aos_sandbox_model::OperationId,
    metadata: &ProjectAdmissionMetadata,
    plan: &EffectPlan,
    request_digest: [u8; 32],
) -> Result<(), ReconcilerError> {
    let projection = PublicProjectionRecordV1::from_retained_record_bytes(
        PublicProjectionKindV1::Sandbox,
        *metadata.sandbox().as_bytes(),
        metadata.original_projection(),
    )
    .map_err(|_| invalid_metadata())?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
        return Err(invalid_metadata());
    };
    let context = plan
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
        .ok_or_else(invalid_metadata)?;
    let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Create(request) =
        context.validated_request().map_err(ReconcilerError::from)?
    else {
        return Err(invalid_metadata());
    };
    let desired = sandbox.desired.as_option().ok_or_else(invalid_metadata)?;
    let policy = desired
        .requested_policy
        .as_option()
        .ok_or_else(invalid_metadata)?;
    if projection.operation() != operation
        || projection.project() != metadata.project()
        || projection.revision() != metadata.source_heads().projection_revision()
        || !sandbox.parent_sandbox_id.is_empty()
        || !request.parent_sandbox_id.is_empty()
        || sandbox.sandbox_id.as_slice() != metadata.sandbox().as_bytes()
        || sandbox.project_id.as_slice() != metadata.project().as_bytes()
        || request.project_id.as_slice() != metadata.project().as_bytes()
        || desired.specification.as_option() != request.specification.as_option()
        || desired.requested_policy.as_option() != request.requested_policy.as_option()
        || sandbox.effective_policy.as_option() != Some(policy)
        || policy.sha256.as_slice() != metadata.source_heads().publisher_digest().as_bytes()
        || sandbox.resource_version
            != crate::production_operation_compiler::admitted_public_resource_version_v1(
                operation,
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox,
                1,
                request_digest,
            )
    {
        return Err(invalid_metadata());
    }
    // The immutable captured projection is still the selected child while this
    // attempt is unsettled. After exact Root retirement, legitimate later
    // projection successors do not replace or invalidate its historical copy.
    if metadata.phase() != ProjectAdmissionPhase::RootRetired {
        let current = PublicProjectionStoreV1::new(journal)
            .one_parentless_create_sandbox(operation, metadata.project())
            .map_err(|_| invalid_metadata())?;
        if current
            != Some((
                metadata.sandbox(),
                metadata.source_heads().projection_revision(),
            ))
        {
            return Err(invalid_metadata());
        }
    }
    Ok(())
}
