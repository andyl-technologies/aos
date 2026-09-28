//! Retained, nonauthorizing project-admission metadata in the original Effect.
//!
//! This metadata preserves the accepted Create identity across publisher expiry
//! and Root reply loss. Decoding it does not establish current policy authority,
//! authenticate a Root reply, or complete Create. Owner transitions separately
//! validate the protected Operation/Effect join and the opaque Root transport.
//!
//! The private `metadata` module owns the canonical retained row. This owner
//! module owns its protected original-admission and terminal transition graph.

mod metadata;

#[cfg(test)]
mod tests;

#[cfg(feature = "project-negative-recovery-vm-fixture")]
pub(super) mod vm_fixture;

pub(super) use metadata::{
    MAXIMUM_RECORD_BYTES, ProjectAdmissionMetadata, ProjectAdmissionPhase,
    RetainedRootProjectTerminal,
};

use aos_sandbox_core::{ObjectDigest, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::controller::ControllerRequestScopeV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionRecordV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, Journal, JournalError,
    JournalRecord, JournalTransaction, RecordNamespace, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1, encoded_transaction_append_bytes,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::policy_compiler::{
    CurrentCreatePolicySourceErrorV1, CurrentCreateProjectPolicySourceV1,
    RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeProofV1,
    RootProjectAdmissionOutcomeV1, RootProjectHistoryFloorProofV1, RootProjectHistoryFloorV1,
    RootProjectHistoryTerminalKindV1, RootProjectReservationCancellationProofV1,
    SourceProjectAdmissionChallengeErrorV1, create_project_source_commitment_v1,
    current_parentless_create_project_source_for_operation_v1,
    preflight_source_project_admission_v1, project_admission_client_nonce_v1,
    read_source_project_admission_status_v1, read_source_project_reservation_status_v1,
};

use super::effect::EffectLedgerRecord;
use super::{
    EffectPlan, ReconcilerError, checked_live_create_sandbox_admission_revision_v1, decode_effect,
    effect_key, encode_effect, retained_create_sandbox_admission_revision_v1,
};

const CAPACITY_DOMAIN: &[u8] = b"aos.sandbox.controller-project-capacity-owner.v1\0";

/// Retains the actual original Effect selected for historical recovery.
///
/// This readback does not authorize a new dispatch or owner transition. Each
/// consumer separately rechecks the protected original Effect and its phase.
pub struct RetainedControllerProjectAdmissionV1 {
    operation: aos_sandbox_core::OperationId,
    plan: EffectPlan,
    metadata: ProjectAdmissionMetadata,
}

impl RetainedControllerProjectAdmissionV1 {
    /// Returns the immutable original operation.
    #[must_use]
    pub const fn operation(&self) -> aos_sandbox_core::OperationId {
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
        self.metadata.reservation
    }

    /// Reports whether Root dispatch has not yet been authorized.
    #[must_use]
    pub const fn is_prepared(&self) -> bool {
        matches!(self.metadata.phase, ProjectAdmissionPhase::Prepared)
    }

    /// Reports whether an exact Root terminal was accepted locally.
    #[must_use]
    pub const fn has_accepted_terminal(&self) -> bool {
        matches!(
            self.metadata.phase,
            ProjectAdmissionPhase::AcceptedRootTerminal | ProjectAdmissionPhase::RootRetired
        )
    }

    /// Returns the historical outcome, without establishing Root transport.
    #[must_use]
    pub const fn outcome(&self) -> Option<RootProjectAdmissionOutcomeV1> {
        match self.metadata.terminal {
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
        if bytes.first() != Some(&super::effect::CONTROLLER_PROJECT_EFFECT_VERSION) {
            continue;
        }
        let effect = decode_effect(bytes)?;
        let Some(metadata) = effect.project_admission else {
            continue;
        };
        let matches = match reservation {
            Some(reservation) => metadata.reservation == reservation,
            None => metadata.phase != ProjectAdmissionPhase::RootRetired,
        };
        if !matches {
            continue;
        }
        let operation = aos_sandbox_core::OperationId::from_bytes(
            key.get(..16)
                .ok_or_else(invalid_metadata)?
                .try_into()
                .map_err(|_| invalid_metadata())?,
        );
        if selected.is_some()
            || checked_live_create_sandbox_admission_revision_v1(
                journal,
                operation,
                scope,
                &effect.plan,
            )?
            .is_none()
        {
            return Err(invalid_metadata().into());
        }
        selected = Some(RetainedControllerProjectAdmissionV1 {
            operation,
            plan: effect.plan,
            metadata,
        });
    }
    Ok(selected)
}

pub(crate) struct AcceptedControllerProjectTerminalV1 {
    pub operation: aos_sandbox_core::OperationId,
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
    pub operation: aos_sandbox_core::OperationId,
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
    operation: aos_sandbox_core::OperationId,
) -> Result<ControllerProjectDispatchReadbackV1, ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    dispatch_readback_from_original_graph(journal, operation)
}

fn dispatch_readback_from_original_graph(
    journal: &Journal,
    operation: aos_sandbox_core::OperationId,
) -> Result<ControllerProjectDispatchReadbackV1, ControllerProjectAdmissionJournalErrorV1> {
    validate_all(journal)?;
    let effect = decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or_else(invalid_metadata)?,
    )?;
    let metadata = effect.project_admission.ok_or_else(invalid_metadata)?;
    if metadata.phase != ProjectAdmissionPhase::DispatchAuthorized {
        return Err(invalid_metadata().into());
    }
    Ok(ControllerProjectDispatchReadbackV1 {
        operation,
        sandbox: metadata.sandbox,
        project: metadata.project,
        source_commitment: metadata.source_commitment,
        admission_revision: metadata.admission_revision,
        admission_generation: metadata.admission_generation,
        metadata: ObjectDigest::from_bytes(Sha256::digest(metadata.encode()?).into()),
        reservation: metadata.reservation,
    })
}

/// Reads only actual accepted original-Effect metadata under Controller custody.
pub(crate) fn accepted_controller_project_terminal_v1(
    journal: &Journal,
    operation: aos_sandbox_core::OperationId,
) -> Result<AcceptedControllerProjectTerminalV1, ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    validate_all(journal)?;
    let effect = decode_effect(
        journal
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or_else(invalid_metadata)?,
    )?;
    let metadata = effect.project_admission.ok_or_else(invalid_metadata)?;
    // A previous RootRetired row is useful only for exact floor replay, never
    // to issue a new retirement carrier or nominate another historical cut.
    if metadata.phase != ProjectAdmissionPhase::AcceptedRootTerminal {
        return Err(invalid_metadata().into());
    }
    let terminal = metadata.terminal.ok_or_else(invalid_metadata)?;
    Ok(AcceptedControllerProjectTerminalV1 {
        operation,
        sandbox: metadata.sandbox,
        project: metadata.project,
        source_commitment: metadata.source_commitment,
        admission_revision: metadata.admission_revision,
        admission_generation: metadata.admission_generation,
        accepted_metadata: metadata.acceptance_digest()?,
        reservation: metadata.reservation,
        challenge: metadata.challenge,
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
    operation: aos_sandbox_core::OperationId,
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
        .map_err(|_| JournalError::ProtectedBoundary)?;
        let metadata = effect
            .project_admission
            .ok_or(JournalError::ProtectedBoundary)?;
        if metadata.phase != ProjectAdmissionPhase::RootRetired
            || metadata.retired_floor != Some(self.floor)
            || floor.record_digest() != self.floor
            || metadata
                .acceptance_digest()
                .map_err(|_| JournalError::ProtectedBoundary)?
                != self.accepted_metadata
            || metadata.reservation != reservation
            || metadata.challenge != challenge
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
    operation: aos_sandbox_core::OperationId,
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
        .project_admission
        .clone()
        .ok_or_else(invalid_metadata)?;
    let floor = proof.floor();
    if !prior.matches_floor(operation, floor)
        || !matches!(
            prior.phase,
            ProjectAdmissionPhase::AcceptedRootTerminal | ProjectAdmissionPhase::RootRetired
        )
    {
        return Err(invalid_metadata().into());
    }
    let floor_digest = floor.record_digest();
    let accepted_metadata = prior.acceptance_digest()?;
    let next = ProjectAdmissionMetadata {
        phase: ProjectAdmissionPhase::RootRetired,
        retired_floor: Some(floor_digest),
        ..prior.clone()
    };
    if prior.phase == ProjectAdmissionPhase::RootRetired {
        if prior != next {
            return Err(invalid_metadata().into());
        }
    } else {
        let reservation = journal.recover_global_capacity_reservation_v1(prior.capacity_id)?;
        effect.project_admission = Some(next.clone());
        let transaction = JournalTransaction::new(
            aos_sandbox_core::OperationId::new().into_bytes(),
            vec![
                effect_record(operation, &effect)?,
                reservation.settlement_record(),
            ],
        )?;
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
    )?;
    if readback.project_admission != Some(next) {
        return Err(invalid_metadata().into());
    }
    Ok(ControllerProjectHistoryAcceptanceV1 {
        controller: journal,
        operation,
        accepted_metadata,
        floor: floor_digest,
    })
}

/// Reports an unavailable exact Controller/Source project-admission cut.
#[derive(Debug, thiserror::Error)]
pub enum ControllerProjectAdmissionJournalErrorV1 {
    /// The protected owner journal or retained capacity is unavailable.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The exact admitted Operation/Effect join changed.
    #[error(transparent)]
    Ledger(#[from] ReconcilerError),
    /// The current publisher-backed Create source changed or expired.
    #[error(transparent)]
    Source(#[from] CurrentCreatePolicySourceErrorV1),
    /// Source ancestry, physical names, or capacity cannot be proved.
    #[error(transparent)]
    Ancestry(#[from] SourceProjectAdmissionChallengeErrorV1),
}

/// Retains original Create identity and the complete Controller terminal suffix.
///
/// Controller and Source writers remain held in that order. No Root request is
/// authorized until the separate durable dispatch transition succeeds. This
/// metadata neither admits a project source nor completes public Create.
///
/// # Errors
///
/// Rejects expired or changed publisher/admission identity, foreign fixed names,
/// a conflicting previous attempt, unproved Source ancestry, or insufficient
/// durable suffix capacity.
pub fn prepare_current_create_project_admission_v1(
    journal: &mut Journal,
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    source: &CurrentCreateProjectPolicySourceV1,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
) -> Result<SourceProjectAdmissionReservationV1, ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let current = current_parentless_create_project_source_for_operation_v1(
        journal,
        source.operation(),
        source.project(),
        scope,
        plan,
    )?;
    if current.commitment() != source.commitment()
        || current.operation_revision() != source.operation_revision()
        || current.projection_revision() != source.projection_revision()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent.into());
    }
    let reservation = preflight_source_project_admission_v1(
        owner,
        project_admission_client_nonce_v1(source.operation(), source.commitment()),
        source.project(),
    )?;
    let mut effect = load_scoped_effect(journal, source.operation(), scope, plan)?;
    if let Some(prior) = &effect.project_admission {
        if prior.reservation == reservation
            && prior.admission_revision == source.operation_revision()
            && prior.admission_generation == source.accepted_generation()
            && prior.source_commitment == source.commitment()
            && prior.sandbox == source.sandbox()
            && prior.project == source.project()
            && prior.source_heads == source.historical_heads()
            && matches!(
                prior.phase,
                ProjectAdmissionPhase::Prepared | ProjectAdmissionPhase::DispatchAuthorized
            )
        {
            validate_all(journal)?;
            return Ok(reservation);
        }
        // Only a completely joined historical retirement may be replaced by
        // another issue of this same original request. Source preflight has
        // already required its exact retirement ACK before advancing issue.
        if prior.phase != ProjectAdmissionPhase::RootRetired
            || prior.reservation.issue().checked_add(1) != Some(reservation.issue())
            || prior.admission_revision != source.operation_revision()
            || prior.admission_generation != source.accepted_generation()
            || prior.sandbox != source.sandbox()
            || prior.project != source.project()
            || matches!(prior.terminal, Some(RetainedRootProjectTerminal::Outcome(outcome))
                if outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed)
        {
            return Err(invalid_metadata().into());
        }
    }
    if retained_controller_project_admission_v1(journal, scope, None)?
        .is_some_and(|flight| flight.operation() != source.operation())
    {
        return Err(invalid_metadata().into());
    }

    let mut metadata = ProjectAdmissionMetadata {
        admission_revision: source.operation_revision(),
        admission_generation: source.accepted_generation(),
        source_commitment: source.commitment(),
        sandbox: source.sandbox(),
        project: source.project(),
        reservation,
        capacity_id: [1; 32],
        phase: ProjectAdmissionPhase::Prepared,
        challenge: None,
        terminal: None,
        retired_floor: None,
        source_heads: source.historical_heads(),
        original_projection: PublicProjectionStoreV1::new(journal)
            .get(
                PublicProjectionKindV1::Sandbox,
                *source.sandbox().as_bytes(),
            )
            .map_err(CurrentCreatePolicySourceErrorV1::from)?
            .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?
            .retained_record_bytes()
            .map_err(CurrentCreatePolicySourceErrorV1::from)?,
    };
    effect.project_admission = Some(metadata.clone());
    let budget = controller_project_suffix_budget(&effect)?;
    let transaction_id = aos_sandbox_core::OperationId::new().into_bytes();
    let request = capacity_request(source.operation(), &metadata, plan, 3, 8, budget);
    let prepared = journal.prepare_global_capacity_reservation_v1(request, transaction_id)?;
    metadata.capacity_id = prepared.reservation_id();
    effect.project_admission = Some(metadata);
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![
            effect_record(source.operation(), &effect)?,
            prepared.record().clone(),
        ],
    )?;
    journal.commit_global_capacity_reservation_v1(prepared, &transaction)?;
    require_controller_writer(journal)?;
    owner
        .require_fixed_named_writer_v1()
        .map_err(SourceProjectAdmissionChallengeErrorV1::from)?;
    validate_all(journal)?;
    Ok(reservation)
}

// Each remaining append rewrites this bounded Effect. Additional headroom
// covers the maximum diagnostic plus canonical capacity and frame envelopes.
// Transfers subtract actual canonical append bytes, never a caller estimate.
fn controller_project_suffix_budget(
    effect: &EffectLedgerRecord,
) -> Result<u64, ControllerProjectAdmissionJournalErrorV1> {
    let append_bound = u64::try_from(encode_effect(effect)?.len())
        .map_err(|_| JournalError::JournalTooLarge)?
        .checked_add((super::effect::MAXIMUM_DIAGNOSTIC_BYTES + 2048) as u64)
        .ok_or(JournalError::JournalTooLarge)?;
    Ok(append_bound
        .checked_mul(3)
        .ok_or(JournalError::JournalTooLarge)?)
}

/// Durably authorizes Root dispatch for one exact retained original Create.
///
/// This consumes one protected suffix slot but grants no Root or Source effect
/// authority. Repeated exact calls only read the existing authorized phase.
///
/// # Errors
///
/// Rejects changed original request/admission, missing Prepared metadata,
/// replaced fixed names, or a failed/ambiguous durable suffix transfer.
pub fn authorize_controller_project_admission_dispatch_v1(
    journal: &mut Journal,
    operation: aos_sandbox_core::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let effect = load_scoped_effect(journal, operation, scope, plan)?;
    let metadata = effect
        .project_admission
        .clone()
        .ok_or_else(invalid_metadata)?;
    if metadata.phase == ProjectAdmissionPhase::DispatchAuthorized {
        validate_all(journal)?;
        return Ok(());
    }
    if metadata.phase != ProjectAdmissionPhase::Prepared {
        return Err(invalid_metadata().into());
    }
    transfer_metadata(
        journal,
        operation,
        effect,
        ProjectAdmissionMetadata {
            phase: ProjectAdmissionPhase::DispatchAuthorized,
            ..metadata
        },
    )?;
    require_controller_writer(journal)?;
    validate_all(journal)?;
    Ok(())
}

/// Durably accepts an exact peer-checked Root outcome before Source settlement.
///
/// Historical publisher expiry does not invalidate an original admitted
/// request. Its retained Operation/Effect/projection identity, the actual
/// Source rows, and the Root transport proof must nevertheless agree exactly.
/// This acceptance neither completes Create nor authorizes Root history removal.
///
/// # Errors
///
/// Rejects an absent or changed dispatch, original admission, Source row/fixed
/// names, Root terminal, or retained suffix capacity.
pub fn accept_controller_project_admission_outcome_v1(
    journal: &mut Journal,
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    operation: aos_sandbox_core::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    proof: RootProjectAdmissionOutcomeProofV1,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let effect = load_scoped_effect(journal, operation, scope, plan)?;
    let prior = effect
        .project_admission
        .clone()
        .ok_or_else(invalid_metadata)?;
    let (reservation, canceled) =
        read_source_project_reservation_status_v1(owner)?.ok_or_else(invalid_metadata)?;
    let (challenge, _) =
        read_source_project_admission_status_v1(owner)?.ok_or_else(invalid_metadata)?;
    if canceled || reservation != prior.reservation {
        return Err(invalid_metadata().into());
    }
    let next = ProjectAdmissionMetadata {
        phase: ProjectAdmissionPhase::AcceptedRootTerminal,
        challenge: Some(challenge),
        terminal: Some(RetainedRootProjectTerminal::Outcome(proof.outcome())),
        ..prior.clone()
    };
    next.validate()?;
    if prior.phase == ProjectAdmissionPhase::AcceptedRootTerminal && next == prior {
        return Ok(());
    }
    if prior.phase != ProjectAdmissionPhase::DispatchAuthorized {
        return Err(invalid_metadata().into());
    }
    transfer_metadata(journal, operation, effect, next)?;
    require_controller_writer(journal)?;
    owner
        .require_fixed_named_writer_v1()
        .map_err(SourceProjectAdmissionChallengeErrorV1::from)?;
    validate_all(journal)?;
    Ok(())
}

/// Durably accepts Root's exact permanent no-stage cancellation.
///
/// The actual Source reservation must exist under the retained writer. A bare
/// Root response, absent row, or local timeout cannot supply this acceptance.
///
/// # Errors
///
/// Rejects changed original admission, reservation, Root marker, fixed names,
/// a Source challenge, or unavailable suffix capacity.
pub fn accept_controller_project_reservation_cancellation_v1(
    journal: &mut Journal,
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    operation: aos_sandbox_core::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    proof: RootProjectReservationCancellationProofV1,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let effect = load_scoped_effect(journal, operation, scope, plan)?;
    let prior = effect
        .project_admission
        .clone()
        .ok_or_else(invalid_metadata)?;
    let (reservation, _) =
        read_source_project_reservation_status_v1(owner)?.ok_or_else(invalid_metadata)?;
    if reservation != prior.reservation || read_source_project_admission_status_v1(owner)?.is_some()
    {
        return Err(invalid_metadata().into());
    }
    let next = ProjectAdmissionMetadata {
        phase: ProjectAdmissionPhase::AcceptedRootTerminal,
        terminal: Some(RetainedRootProjectTerminal::Cancellation(proof.marker())),
        ..prior.clone()
    };
    next.validate()?;
    if prior.phase == ProjectAdmissionPhase::AcceptedRootTerminal && next == prior {
        return Ok(());
    }
    if prior.phase != ProjectAdmissionPhase::DispatchAuthorized {
        return Err(invalid_metadata().into());
    }
    transfer_metadata(journal, operation, effect, next)?;
    require_controller_writer(journal)?;
    owner
        .require_fixed_named_writer_v1()
        .map_err(SourceProjectAdmissionChallengeErrorV1::from)?;
    validate_all(journal)?;
    Ok(())
}

fn load_scoped_effect(
    journal: &Journal,
    operation: aos_sandbox_core::OperationId,
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
}

fn require_controller_writer(journal: &Journal) -> Result<(), JournalError> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 {
        return Err(JournalError::ProtectedBoundary);
    }
    journal.require_protected_named_location(
        std::path::Path::new("/var/lib/aos/sandboxd"),
        "controller.journal",
        uid,
        crate::controller_service::journal::production_journal_limits(),
    )
}

fn capacity_request(
    operation: aos_sandbox_core::OperationId,
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
        owner_digest: *metadata.reservation.record_digest().as_bytes(),
        operation_id: *operation.as_bytes(),
        artifact_digest: Sha256::digest(plan.request()).into(),
        checkpoint_digest: *metadata.admission_revision.as_bytes(),
        chain_head_digest: *metadata.source_commitment.as_bytes(),
        future_transactions,
        terminal_records: records,
        terminal_bytes: bytes,
        poison_records: records,
        poison_bytes: bytes,
    }
}

fn effect_record(
    operation: aos_sandbox_core::OperationId,
    effect: &EffectLedgerRecord,
) -> Result<JournalRecord, ReconcilerError> {
    Ok(JournalRecord::put(
        RecordNamespace::Effect,
        effect_key(operation, 0).to_vec(),
        encode_effect(effect)?,
    ))
}

fn transfer_metadata(
    journal: &mut Journal,
    operation: aos_sandbox_core::OperationId,
    mut effect: EffectLedgerRecord,
    mut next: ProjectAdmissionMetadata,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    let prior = effect
        .project_admission
        .clone()
        .ok_or_else(invalid_metadata)?;
    let capacity = journal.recover_global_capacity_reservation_v1(prior.capacity_id)?;
    let old = capacity.request();
    let transaction_id = aos_sandbox_core::OperationId::new().into_bytes();
    let mut request = GlobalCapacityReservationRequestV1 {
        future_transactions: old
            .future_transactions
            .checked_sub(1)
            .ok_or(JournalError::InvalidTransaction)?,
        terminal_records: old
            .terminal_records
            .checked_sub(3)
            .ok_or(JournalError::InvalidTransaction)?,
        poison_records: old
            .poison_records
            .checked_sub(3)
            .ok_or(JournalError::InvalidTransaction)?,
        ..old
    };
    // Canonical sizes do not depend on digest contents or the byte budget's
    // numeric value. Use the real prepared record twice rather than copying
    // its codec or estimating frame lengths.
    let draft = journal.prepare_global_capacity_reservation_v1(request, transaction_id)?;
    next.capacity_id = draft.reservation_id();
    effect.project_admission = Some(next.clone());
    let draft_transaction = JournalTransaction::new(
        transaction_id,
        vec![
            effect_record(operation, &effect)?,
            capacity.settlement_record(),
            draft.record().clone(),
        ],
    )?;
    let consumed = encoded_transaction_append_bytes(&draft_transaction)?;
    request.terminal_bytes = old
        .terminal_bytes
        .checked_sub(consumed)
        .ok_or(JournalError::JournalTooLarge)?;
    request.poison_bytes = old
        .poison_bytes
        .checked_sub(consumed)
        .ok_or(JournalError::JournalTooLarge)?;
    let successor = journal.prepare_global_capacity_reservation_v1(request, transaction_id)?;
    next.capacity_id = successor.reservation_id();
    effect.project_admission = Some(next);
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![
            effect_record(operation, &effect)?,
            capacity.settlement_record(),
            successor.record().clone(),
        ],
    )?;
    journal.transfer_controller_project_capacity_v1(capacity, successor, &transaction)?;
    Ok(())
}

fn invalid_metadata() -> ReconcilerError {
    ReconcilerError::CorruptLedger("invalid Controller project-admission metadata")
}

pub(crate) fn validate_capacity_transfer(
    journal: &Journal,
    transaction: &JournalTransaction,
    operation: [u8; 16],
    old_capacity: [u8; 32],
    new_capacity: [u8; 32],
) -> Result<(), JournalError> {
    let (prior, next) = capacity_effect_transition(journal, transaction, operation)?;
    if prior.capacity_id != old_capacity || next.capacity_id != new_capacity {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    let mut expected = prior.clone();
    expected.capacity_id = new_capacity;
    match (prior.phase, next.phase) {
        (ProjectAdmissionPhase::Prepared, ProjectAdmissionPhase::DispatchAuthorized) => {
            expected.phase = ProjectAdmissionPhase::DispatchAuthorized;
        }
        (
            ProjectAdmissionPhase::DispatchAuthorized,
            ProjectAdmissionPhase::AcceptedRootTerminal,
        ) => {
            expected.phase = ProjectAdmissionPhase::AcceptedRootTerminal;
            expected.challenge = next.challenge;
            expected.terminal = next.terminal;
        }
        _ => return Err(JournalError::AuthorityPreflightMismatch),
    }
    if next != expected {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(())
}

pub(crate) fn validate_capacity_settlement(
    journal: &Journal,
    transaction: &JournalTransaction,
    operation: [u8; 16],
    capacity: [u8; 32],
) -> Result<(), JournalError> {
    let (prior, next) = capacity_effect_transition(journal, transaction, operation)?;
    let expected = ProjectAdmissionMetadata {
        phase: ProjectAdmissionPhase::RootRetired,
        retired_floor: next.retired_floor,
        ..prior.clone()
    };
    if prior.phase != ProjectAdmissionPhase::AcceptedRootTerminal
        || prior.capacity_id != capacity
        || next != expected
        || transaction.records().len() != 2
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(())
}

fn capacity_effect_transition(
    journal: &Journal,
    transaction: &JournalTransaction,
    operation: [u8; 16],
) -> Result<(ProjectAdmissionMetadata, ProjectAdmissionMetadata), JournalError> {
    let operation = aos_sandbox_core::OperationId::from_bytes(operation);
    let key = effect_key(operation, 0);
    let prior = journal
        .get(RecordNamespace::Effect, &key)
        .ok_or(JournalError::ProtectedBoundary)?;
    let prior = decode_effect(prior).map_err(|_| JournalError::ProtectedBoundary)?;
    let mut effects = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::Effect);
    let next = effects.next().ok_or(JournalError::ProtectedBoundary)?;
    if next.key() != key || effects.next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let next = decode_effect(next.value().ok_or(JournalError::ProtectedBoundary)?)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if next.plan != prior.plan || next.state != prior.state || next.dispatch != prior.dispatch {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok((
        prior
            .project_admission
            .ok_or(JournalError::ProtectedBoundary)?,
        next.project_admission
            .ok_or(JournalError::ProtectedBoundary)?,
    ))
}

/// Validates the immutable original Create join without granting currentness.
pub(super) fn validate_all(journal: &Journal) -> Result<(), ReconcilerError> {
    let mut expected_capacity = std::collections::BTreeSet::new();
    let mut pending_flights = 0;
    for (key, bytes) in journal.records(RecordNamespace::Effect) {
        if bytes.first() != Some(&super::effect::CONTROLLER_PROJECT_EFFECT_VERSION) {
            continue;
        }
        let effect = decode_effect(bytes)?;
        let Some(metadata) = &effect.project_admission else {
            continue;
        };
        let operation_bytes: [u8; 16] = key
            .get(..16)
            .ok_or_else(invalid_metadata)?
            .try_into()
            .map_err(|_| invalid_metadata())?;
        let operation = aos_sandbox_core::OperationId::from_bytes(operation_bytes);
        let (revision, generation, request_digest) = retained_create_sandbox_admission_revision_v1(
            journal,
            operation,
            metadata.phase == ProjectAdmissionPhase::RootRetired,
        )?
        .ok_or_else(invalid_metadata)?;
        if key != effect_key(operation, 0)
            || create_project_source_commitment_v1(
                operation,
                metadata.admission_revision,
                metadata.admission_generation,
                metadata.sandbox,
                metadata.project,
                metadata.source_heads,
            ) != metadata.source_commitment
            || crate::policy_compiler::project_admission_client_nonce_v1(
                operation,
                metadata.source_commitment,
            ) != metadata.reservation.client_nonce()
            || revision != metadata.admission_revision
            || generation != metadata.admission_generation
            || metadata.terminal.is_some_and(|terminal| {
                matches!(terminal,
                RetainedRootProjectTerminal::Outcome(outcome)
                    if outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
                        && outcome.operation() != operation_bytes)
            })
        {
            return Err(invalid_metadata());
        }
        let context = effect
            .plan
            .public_mutation_context()?
            .ok_or_else(invalid_metadata)?;
        if context.project() != metadata.project {
            return Err(invalid_metadata());
        }
        validate_original_projection(journal, operation, metadata, &effect.plan, request_digest)?;
        if metadata.phase == ProjectAdmissionPhase::RootRetired {
            if journal
                .lookup_global_capacity_reservation_v1(metadata.capacity_id)?
                .is_some()
            {
                return Err(invalid_metadata());
            }
        } else {
            pending_flights += 1;
            if pending_flights > 1 {
                return Err(invalid_metadata());
            }
            if !expected_capacity.insert(metadata.capacity_id) {
                return Err(invalid_metadata());
            }
            let retained = journal.recover_global_capacity_reservation_v1(metadata.capacity_id)?;
            let request = retained.request();
            let (transactions, records) = match metadata.phase {
                ProjectAdmissionPhase::Prepared => (3, 8),
                ProjectAdmissionPhase::DispatchAuthorized => (2, 5),
                ProjectAdmissionPhase::AcceptedRootTerminal => (1, 2),
                ProjectAdmissionPhase::RootRetired => return Err(invalid_metadata()),
            };
            if request
                != capacity_request(
                    operation,
                    metadata,
                    &effect.plan,
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

fn validate_original_projection(
    journal: &Journal,
    operation: aos_sandbox_core::OperationId,
    metadata: &ProjectAdmissionMetadata,
    plan: &EffectPlan,
    request_digest: [u8; 32],
) -> Result<(), ReconcilerError> {
    let projection = PublicProjectionRecordV1::from_retained_record_bytes(
        PublicProjectionKindV1::Sandbox,
        *metadata.sandbox.as_bytes(),
        &metadata.original_projection,
    )
    .map_err(|_| invalid_metadata())?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
        return Err(invalid_metadata());
    };
    let context = plan
        .public_mutation_context()?
        .ok_or_else(invalid_metadata)?;
    let crate::cli_model::DormantSandboxRequestKindV1::Create(request) =
        context.validated_request()?
    else {
        return Err(invalid_metadata());
    };
    let desired = sandbox.desired.as_option().ok_or_else(invalid_metadata)?;
    let policy = desired
        .requested_policy
        .as_option()
        .ok_or_else(invalid_metadata)?;
    if projection.operation() != operation
        || projection.project() != metadata.project
        || projection.revision() != metadata.source_heads.projection_revision
        || !sandbox.parent_sandbox_id.is_empty()
        || !request.parent_sandbox_id.is_empty()
        || sandbox.sandbox_id.as_slice() != metadata.sandbox.as_bytes()
        || sandbox.project_id.as_slice() != metadata.project.as_bytes()
        || request.project_id.as_slice() != metadata.project.as_bytes()
        || desired.specification.as_option() != request.specification.as_option()
        || desired.requested_policy.as_option() != request.requested_policy.as_option()
        || sandbox.effective_policy.as_option() != Some(policy)
        || policy.sha256.as_slice() != metadata.source_heads.publisher_digest.as_bytes()
        || sandbox.resource_version
            != crate::production_operation_compiler::admitted_public_resource_version_v1(
                operation,
                crate::controller_query::PublicOperationMethodV1::CreateSandbox,
                1,
                request_digest,
            )
    {
        return Err(invalid_metadata());
    }
    // The immutable captured projection is still the selected child while this
    // attempt is unsettled. After exact Root retirement, legitimate later
    // projection successors do not replace or invalidate its historical copy.
    if metadata.phase != ProjectAdmissionPhase::RootRetired {
        let current = PublicProjectionStoreV1::new(journal)
            .one_parentless_create_sandbox(operation, metadata.project)
            .map_err(|_| invalid_metadata())?;
        if current != Some((metadata.sandbox, metadata.source_heads.projection_revision)) {
            return Err(invalid_metadata());
        }
    }
    Ok(())
}
