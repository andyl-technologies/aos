//! Compares the exact terminal Controller Delete successor as passive DATA.
//!
//! The live writer additionally requires its private original Source/Root/C17
//! append loan. This shared recipe lets cold replay preserve the immutable
//! accepted batch, handoff, tombstones and companions while recognizing only
//! the exact terminal Effect/Operation/Sandbox transaction.

use super::completion::DeleteRootSourceCompletionDataV4 as Frame;
use crate::domain_ledger::{
    delete_batch::DeleteBatchViewV1,
    effect_history::{EffectLedgerRecord, EffectState, decode_effect, encode_effect},
    operation::{decode_operation, effect_key, encode_operation_record},
    public_operation::OperationState,
    transaction::{JournalRecord, JournalTransaction},
};
use crate::public_api::projection::{
    PublicProjectionKindV1 as Kind, PublicProjectionPlanV1, PublicProjectionResourceV1 as Resource,
    decode_checked_public_projection_v1, projection_key,
};
use aos_sandbox_core::RecordNamespace as Namespace;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::error::Error;

type Cause = Box<dyn Error + Send + Sync>;

fn invalid() -> Cause {
    std::io::Error::other("invalid terminal Delete Controller transition").into()
}

/// Derives the canonical final Sandbox projection from the accepted batch.
///
/// # Errors
/// Refuses absent or foreign projection/batch, changed generation, malformed
/// canonical resources or overflowing observation sequence.
pub fn prepare_delete_terminal_projection_data_v4(
    state: &BTreeMap<(Namespace, Vec<u8>), Vec<u8>>,
    batch: DeleteBatchViewV1<'_>,
) -> Result<JournalRecord, Cause> {
    let crate::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(sandbox) =
        batch.root()?
    else {
        return Err(invalid());
    };
    let key = projection_key(Kind::Sandbox, *sandbox.as_bytes());
    let before = decode_checked_public_projection_v1(
        &key,
        state
            .get(&(Namespace::DesiredState, key.clone()))
            .ok_or_else(invalid)?,
    )?;
    if before.project() != batch.project() {
        return Err(invalid());
    }
    let Resource::Sandbox(mut candidate) = before.resource().clone() else {
        return Err(invalid());
    };
    let desired = candidate.desired.as_option_mut().ok_or_else(invalid)?;
    let generation = batch.root_successor_generation_data_v2()?;
    if desired.generation.checked_add(1) != Some(generation) {
        return Err(invalid());
    }
    desired.generation = generation;
    desired.lifecycle =
        aos_proto::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_DELETED.into();
    let observed = candidate.observed.as_option_mut().ok_or_else(invalid)?;
    observed.phase = aos_proto::aos::sandbox::v1::SandboxPhase::SANDBOX_PHASE_DELETED.into();
    observed.desired_generation = generation;
    observed.observation_sequence = observed
        .observation_sequence
        .checked_add(1)
        .ok_or_else(invalid)?;
    observed.incarnation_id.clear();
    observed.node_id.clear();
    observed.assignment_epoch = 0;
    observed.ownership = Default::default();
    observed.guardian = Default::default();
    observed.capability_generation = 0;
    observed.realized_root = Default::default();
    observed.root_transaction = Default::default();
    observed.environment_generation = 0;
    observed.attachments = Default::default();
    observed.active_executions.clear();
    observed.pinned_references.clear();
    observed.cache = Default::default();
    observed.logical_usage = Default::default();
    let projection = PublicProjectionPlanV1::new(
        batch.project(),
        batch.operation(),
        Resource::Sandbox(candidate),
    )?;
    Ok(JournalRecord::put(
        Namespace::DesiredState,
        projection.desired_key().to_vec(),
        projection.desired_value().to_vec(),
    ))
}

/// Checks the sole terminal three-row successor without adopting its receipt.
///
/// This is a historical framing/model comparison. It authenticates no supplied
/// Source position, Root positive disposition, native owner or financial loan.
///
/// # Errors
/// Refuses a malformed selected transition or changed original accepted rows.
pub fn require_delete_terminal_controller_transition_data_v4(
    state: &BTreeMap<(Namespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    batch: DeleteBatchViewV1<'_>,
    before_sequence: u64,
) -> Result<(), Cause> {
    let operation_id = batch.operation();
    let rows = transaction.records();
    if rows.len() != 3
        || rows[0].namespace() != Namespace::Effect
        || rows[0].key() != effect_key(operation_id, 0)
        || rows[1].namespace() != Namespace::Operation
        || rows[1].key() != operation_id.as_bytes()
    {
        return Err(invalid());
    }
    let old_operation = decode_operation(
        state
            .get(&(Namespace::Operation, operation_id.as_bytes().to_vec()))
            .ok_or_else(invalid)?,
    )?;
    let old_effect = decode_effect(
        state
            .get(&(Namespace::Effect, effect_key(operation_id, 0).to_vec()))
            .ok_or_else(invalid)?,
    )?;
    let new_operation = decode_operation(rows[1].value().ok_or_else(invalid)?)?;
    let new_effect = decode_effect(rows[0].value().ok_or_else(invalid)?)?;
    let EffectState::Applied {
        attempt: 1,
        receipt,
    } = new_effect.state()
    else {
        return Err(invalid());
    };
    let frame = Frame::decode_v4(receipt.as_bytes())?;
    let public = old_operation.public_operation().ok_or_else(invalid)?;
    let wall = new_operation
        .public_operation()
        .and_then(|value| value.completed_wall_seconds_v1())
        .ok_or_else(invalid)?;
    let controller_sequence =
        u64::from_be_bytes(frame.controller[48..56].try_into().map_err(|_| invalid())?);
    if old_operation.state() != OperationState::Accepted
        || old_operation.effect_count() != 1
        || public.method() != crate::public_api::PublicOperationMethodV1::DeleteSandbox
        || !matches!(old_effect.state(), EffectState::Planned)
        || old_effect.plan().public_mutation_method()
            != Some(crate::public_api::PublicOperationMethodV1::DeleteSandbox)
        || old_effect.dispatch().is_some()
        || old_effect.project_admission().is_some()
        || frame.controller[..16] != batch.transaction()
        || controller_sequence.checked_add(1) != Some(before_sequence)
    {
        return Err(invalid());
    }
    let context = old_effect
        .plan()
        .public_mutation_context()?
        .ok_or_else(invalid)?;
    let crate::public_api::request::DormantSandboxRequestKindV1::Delete(request) =
        context.validated_request()?
    else {
        return Err(invalid());
    };
    batch.require_public_request_v2(&request)?;
    if context.project() != batch.project() {
        return Err(invalid());
    }
    let (plan, _, dispatch, admission) = old_effect.into_parts();
    let expected_effect = encode_effect(&EffectLedgerRecord::from_parts((
        plan,
        EffectState::Applied {
            attempt: 1,
            receipt: receipt.clone(),
        },
        dispatch,
        admission,
    )))?;
    let expected_operation =
        encode_operation_record(old_operation.with_state_and_public_operation(
            OperationState::Succeeded,
            Some(public.advance(OperationState::Succeeded, wall)?),
        ));
    let expected_projection = prepare_delete_terminal_projection_data_v4(state, batch)?;
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.delete.controller-terminal.v4\0")
        .chain_update(operation_id.as_bytes())
        .chain_update(frame.encode_v4()?)
        .finalize();
    if rows[0].value() != Some(expected_effect.as_slice())
        || rows[1].value() != Some(expected_operation.as_slice())
        || rows[2] != expected_projection
        || transaction.id().as_slice() != &digest[..16]
    {
        return Err(invalid());
    }
    Ok(())
}
