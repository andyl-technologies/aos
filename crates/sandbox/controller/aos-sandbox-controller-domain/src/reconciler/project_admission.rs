//! Retained, nonauthorizing project-admission metadata in the original Effect.
//!
//! This metadata preserves the accepted Create identity across publisher expiry
//! and Root reply loss. Decoding it does not establish current policy authority,
//! authenticate a Root reply, or complete Create. Owner transitions separately
//! validate the protected Operation/Effect join and the opaque Root transport.
//!
//! Protocol owns the complete canonical historical metadata DATA. This native
//! owner retains the prepare, dispatch and Source-terminal transitions. Its
//! private original-history owner keeps complete replay and protected readbacks
//! together with the validated history-floor acceptance and opaque Journal loan.

mod original_history;

#[cfg(test)]
mod metadata_tests;

#[cfg(test)]
mod tests;

#[cfg(feature = "project-negative-recovery-vm-fixture")]
pub(super) mod vm_fixture;

pub(super) use aos_sandbox_protocol::domain_ledger::project_admission_metadata::{
    ProjectAdmissionMetadataV1 as ProjectAdmissionMetadata,
    ProjectAdmissionPhaseV1 as ProjectAdmissionPhase,
    RetainedRootProjectTerminalV1 as RetainedRootProjectTerminal,
};

pub(super) use original_history::validate_all;
pub(crate) use original_history::{
    AcceptedControllerProjectTerminalV1, ControllerProjectDispatchReadbackV1,
    accepted_controller_project_terminal_v1, controller_project_dispatch_readback_v1,
    live_create_sandbox_admission_revision_v1,
};
pub use original_history::{
    ControllerProjectHistoryAcceptanceV1, RetainedControllerProjectAdmissionV1,
    accept_controller_project_history_floor_v1, checked_live_create_sandbox_admission_revision_v1,
    retained_controller_project_admission_v1,
};

use original_history::{
    capacity_request, effect_record, invalid_metadata, load_scoped_effect,
    require_controller_writer,
};
#[cfg(test)]
use original_history::dispatch_readback_from_original_graph;
#[cfg(test)]
use original_history::validate_original_projection;
#[cfg(any(test, feature = "project-negative-recovery-vm-fixture"))]
pub(super) use original_history::retained_create_sandbox_admission_revision_v1;

use aos_sandbox_protocol::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataDataErrorV1;

use crate::controller::ControllerRequestScopeV1;
use crate::controller_service::public_projection::PublicProjectionStoreV1;
use crate::journal::{
    GlobalCapacityReservationRequestV1, Journal, JournalError,
    JournalTransaction, SourceProjectAdmissionReservationV1, encoded_transaction_append_bytes,
};
use crate::policy_compiler::{
    CurrentCreatePolicySourceErrorV1, CurrentCreateProjectPolicySourceV1,
    RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeProofV1,
    RootProjectReservationCancellationProofV1, SourceProjectAdmissionChallengeErrorV1,
    current_parentless_create_project_source_for_operation_v1,
    preflight_source_project_admission_v1, project_admission_client_nonce_v1,
    read_source_project_admission_status_v1, read_source_project_reservation_status_v1,
};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1;

use super::ReconcilerError;
#[cfg(test)]
use super::effect_key;
#[cfg(test)]
use crate::journal::{JournalRecord, RecordNamespace};
#[cfg(test)]
use crate::policy_compiler::create_project_source_commitment_v1;
#[cfg(test)]
use aos_sandbox_model::{ObjectDigest, SandboxId};
#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::effect_history::decode_effect;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectLedgerRecord, EffectPlan, MAXIMUM_DIAGNOSTIC_BYTES, encode_effect,
};
#[cfg(test)]
use aos_sandbox_protocol::public_api::projection::PublicProjectionResourceV1;

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
    if let Some(prior) = effect.project_admission() {
        if prior.reservation() == reservation
            && prior.admission_revision() == source.operation_revision()
            && prior.admission_generation() == source.accepted_generation()
            && prior.source_commitment() == source.commitment()
            && prior.sandbox() == source.sandbox()
            && prior.project() == source.project()
            && prior.source_heads() == source.historical_heads()
            && matches!(
                prior.phase(),
                ProjectAdmissionPhase::Prepared | ProjectAdmissionPhase::DispatchAuthorized
            )
        {
            validate_all(journal)?;
            return Ok(reservation);
        }
        // Only a completely joined historical retirement may be replaced by
        // another issue of this same original request. Source preflight has
        // already required its exact retirement ACK before advancing issue.
        if prior.phase() != ProjectAdmissionPhase::RootRetired
            || prior.reservation().issue().checked_add(1) != Some(reservation.issue())
            || prior.admission_revision() != source.operation_revision()
            || prior.admission_generation() != source.accepted_generation()
            || prior.sandbox() != source.sandbox()
            || prior.project() != source.project()
            || matches!(prior.terminal(), Some(RetainedRootProjectTerminal::Outcome(outcome))
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

    let mut metadata = ProjectAdmissionMetadata::from_historical_fields(
        source.operation_revision(),
        source.accepted_generation(),
        source.commitment(),
        source.sandbox(),
        source.project(),
        reservation,
        [1; 32],
        ProjectAdmissionPhase::Prepared,
        None,
        None,
        None,
        source.historical_heads(),
        PublicProjectionStoreV1::new(journal)
            .get(
                PublicProjectionKindV1::Sandbox,
                *source.sandbox().as_bytes(),
            )
            .map_err(CurrentCreatePolicySourceErrorV1::from)?
            .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?
            .retained_record_bytes()
            .map_err(CurrentCreatePolicySourceErrorV1::from)?,
    );
    effect.set_project_admission(Some(metadata.clone()));
    let budget = controller_project_suffix_budget(&effect)?;
    let transaction_id = aos_sandbox_model::OperationId::new().into_bytes();
    let request = capacity_request(source.operation(), &metadata, plan, 3, 8, budget);
    let prepared = journal.prepare_global_capacity_reservation_v1(request, transaction_id)?;
    metadata.set_historical_capacity_id(prepared.reservation_id());
    effect.set_project_admission(Some(metadata));
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![
            effect_record(source.operation(), &effect)?,
            prepared.record().clone(),
        ],
    )
    .map_err(JournalError::from)?;
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
    let append_bound = u64::try_from(encode_effect(effect).map_err(ReconcilerError::from)?.len())
        .map_err(|_| JournalError::JournalTooLarge)?
        .checked_add((MAXIMUM_DIAGNOSTIC_BYTES + 2048) as u64)
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
    operation: aos_sandbox_model::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let effect = load_scoped_effect(journal, operation, scope, plan)?;
    let metadata = effect
        .project_admission()
        .cloned()
        .ok_or_else(invalid_metadata)?;
    if metadata.phase() == ProjectAdmissionPhase::DispatchAuthorized {
        validate_all(journal)?;
        return Ok(());
    }
    if metadata.phase() != ProjectAdmissionPhase::Prepared {
        return Err(invalid_metadata().into());
    }
    transfer_metadata(journal, operation, effect, {
        let next_phase = ProjectAdmissionPhase::DispatchAuthorized;
        let mut next = metadata;
        next.set_historical_phase(next_phase);
        next
    })?;
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
    operation: aos_sandbox_model::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    proof: RootProjectAdmissionOutcomeProofV1,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let effect = load_scoped_effect(journal, operation, scope, plan)?;
    let prior = effect
        .project_admission()
        .cloned()
        .ok_or_else(invalid_metadata)?;
    let (reservation, canceled) =
        read_source_project_reservation_status_v1(owner)?.ok_or_else(invalid_metadata)?;
    let (challenge, _) =
        read_source_project_admission_status_v1(owner)?.ok_or_else(invalid_metadata)?;
    if canceled || reservation != prior.reservation() {
        return Err(invalid_metadata().into());
    }
    let next_phase = ProjectAdmissionPhase::AcceptedRootTerminal;
    let next_challenge = Some(challenge);
    let next_terminal = Some(RetainedRootProjectTerminal::Outcome(proof.outcome()));
    let mut next = prior.clone();
    next.set_historical_phase(next_phase);
    next.set_historical_challenge(next_challenge);
    next.set_historical_terminal(next_terminal);
    next.validate().map_err(ReconcilerError::from)?;
    if prior.phase() == ProjectAdmissionPhase::AcceptedRootTerminal && next == prior {
        return Ok(());
    }
    if prior.phase() != ProjectAdmissionPhase::DispatchAuthorized {
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
    operation: aos_sandbox_model::OperationId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    proof: RootProjectReservationCancellationProofV1,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    require_controller_writer(journal)?;
    let effect = load_scoped_effect(journal, operation, scope, plan)?;
    let prior = effect
        .project_admission()
        .cloned()
        .ok_or_else(invalid_metadata)?;
    let (reservation, _) =
        read_source_project_reservation_status_v1(owner)?.ok_or_else(invalid_metadata)?;
    if reservation != prior.reservation()
        || read_source_project_admission_status_v1(owner)?.is_some()
    {
        return Err(invalid_metadata().into());
    }
    let next_phase = ProjectAdmissionPhase::AcceptedRootTerminal;
    let next_terminal = Some(RetainedRootProjectTerminal::Cancellation(proof.marker()));
    let mut next = prior.clone();
    next.set_historical_phase(next_phase);
    next.set_historical_terminal(next_terminal);
    next.validate().map_err(ReconcilerError::from)?;
    if prior.phase() == ProjectAdmissionPhase::AcceptedRootTerminal && next == prior {
        return Ok(());
    }
    if prior.phase() != ProjectAdmissionPhase::DispatchAuthorized {
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

fn transfer_metadata(
    journal: &mut Journal,
    operation: aos_sandbox_model::OperationId,
    mut effect: EffectLedgerRecord,
    mut next: ProjectAdmissionMetadata,
) -> Result<(), ControllerProjectAdmissionJournalErrorV1> {
    let prior = effect
        .project_admission()
        .cloned()
        .ok_or_else(invalid_metadata)?;
    let capacity = journal.recover_global_capacity_reservation_v1(prior.capacity_id())?;
    let old = capacity.request();
    let transaction_id = aos_sandbox_model::OperationId::new().into_bytes();
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
    next.set_historical_capacity_id(draft.reservation_id());
    effect.set_project_admission(Some(next.clone()));
    let draft_transaction = JournalTransaction::new(
        transaction_id,
        vec![
            effect_record(operation, &effect)?,
            capacity.settlement_record(),
            draft.record().clone(),
        ],
    )
    .map_err(JournalError::from)?;
    let consumed =
        encoded_transaction_append_bytes(&draft_transaction).map_err(JournalError::from)?;
    request.terminal_bytes = old
        .terminal_bytes
        .checked_sub(consumed)
        .ok_or(JournalError::JournalTooLarge)?;
    request.poison_bytes = old
        .poison_bytes
        .checked_sub(consumed)
        .ok_or(JournalError::JournalTooLarge)?;
    let successor = journal.prepare_global_capacity_reservation_v1(request, transaction_id)?;
    next.set_historical_capacity_id(successor.reservation_id());
    effect.set_project_admission(Some(next));
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![
            effect_record(operation, &effect)?,
            capacity.settlement_record(),
            successor.record().clone(),
        ],
    )
    .map_err(JournalError::from)?;
    journal.transfer_controller_project_capacity_v1(capacity, successor, &transaction)?;
    Ok(())
}

impl From<ProjectAdmissionMetadataDataErrorV1> for ReconcilerError {
    fn from(error: ProjectAdmissionMetadataDataErrorV1) -> Self {
        match error {
            ProjectAdmissionMetadataDataErrorV1::InvalidMetadata => invalid_metadata(),
        }
    }
}
