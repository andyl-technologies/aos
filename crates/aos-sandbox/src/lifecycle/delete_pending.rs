//! Plans the canonical Source pending fence under the actual C17/Source cut.
//!
//! The two existing lifecycle auxiliary members and the fixed pending key are
//! one transaction. The key's value is the same complete named-cut `AOSDEL02` batch; it
//! adds no graph format. A durable receipt establishes only this saved fence.
//! It does not establish six-domain currentness, Root approval, Controller
//! acceptance or destruction authority.

mod progress;
mod completion;
pub(crate) use completion::{DeleteSourceCompletionPhaseV4, SourceDeleteCompletionPlanV4,
    require_terminal_operation_data_v4};
pub(crate) use progress::{DeleteSourceReadinessPhaseV3, SourceDeleteReadinessPlanV3};

use std::mem::size_of;

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, ResourceId, Revision};
use aos_sandbox_protocol::domain_ledger::delete_batch::{
    LifecycleDeleteBatchV1, LifecycleDeleteBatchRecordV1, native_value_digest,
};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainSchemaV1, replay_projection_records,
};
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use sha2::{Digest as _, Sha256};

use crate::controller::ControllerRequestScopeV1;
use crate::journal::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1;
use super::protected_journal::{
    LifecycleProtectedJournalSchemaV1 as Schema, LifecycleProtectedRecordKindV1 as Kind,
    LifecycleReducerRecordV1, lifecycle_reducer_envelope_v1,
};
use super::{
    LifecycleAuxiliaryPayloadV1, LifecycleAuxiliaryRecordV1, LifecycleOperationV1,
    bind_lifecycle_atomic_join_v1,
};

/// Retains an exact, nonaccepted pending transaction and its checked request.
///
/// Only the actual Source scope constructs this value after its complete C17
/// payment. Its sole transaction is consumed by the same retained appender.
pub(crate) struct SourceDeletePendingPlanV1<'authorization> {
    authorization: DeleteAuthorizationBindingV1<'authorization>,
    transaction: JournalTransaction,
    project: ProjectId,
    operation: OperationId,
    batch_digest: ObjectDigest,
    source_sequence: u64,
    controller_sequence: u64,
    complete: aos_sandbox_core::ResourceVector,
}

impl<'authorization> SourceDeletePendingPlanV1<'authorization> {
    /// Builds the existing two-member auxiliary join on the saved actual rows.
    ///
    /// This private recipe is entered only after the real Source scope's
    /// complete representation check. All supplied models are already resident
    /// on the caller; a canonical batch alone supplies no authorization.
    pub(crate) fn prepare_v1(
        view: HistoricalLedgerReadViewV1<'_>,
        source_sequence: u64,
        controller_sequence: u64,
        request_scope: ControllerRequestScopeV1,
        authorization: DeleteAuthorizationBindingV1<'authorization>,
        complete: aos_sandbox_core::ResourceVector,
        operation: LifecycleOperationV1,
        batch: LifecycleDeleteBatchV1,
    ) -> Result<Self, super::protected_journal::LifecycleProtectedJournalErrorV1> {
        let invalid = || super::protected_journal::LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
        super::format::delete_pending_record_encoded_length_v1(&operation)
            .map_err(|_| invalid())?;
        let authorized = authorization.authorization();
        require_operation_request_v1(&operation, authorized.request().idempotency_key().as_bytes())?;
        // Public authorization records whole Unix seconds. Use exactly that
        // retained native decision in the lifecycle's nanosecond time format;
        // neither a caller-selected timestamp nor a fresh clock substitutes it.
        let accepted_at = u64::try_from(authorized.accepted_wall_seconds()).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or_else(invalid)?;
        if operation.accepted_at().get() != accepted_at {
            return Err(invalid());
        }
        let DormantSandboxRequestKindV1::Delete(request) = authorized.request().request()
        else { return Err(invalid()); };
        let batch_view = batch.view().map_err(|_| invalid())?;
        let super::LifecycleIntentV1::DeleteSandbox { sandbox, .. } = operation.intent()
        else { return Err(invalid()); };
        if batch_view.version() != 2
            || operation.project() != authorized.project()
            || operation.caller() != authorized.caller()
            || batch_view.project() != operation.project()
            || batch_view.operation() != operation.operation_id()
            || batch_view.root().map_err(|_| invalid())?
                != aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(*sandbox)
            || request.sandbox_id.as_slice() != sandbox.as_bytes()
            || batch_view.before_sequence() != controller_sequence
            || batch_view.source_predecessor_next_sequence_v2() != Some(source_sequence)
            || batch_view.request_digest() != request_scope.public_request_digest(
                authorized.caller(), authorized.project(), authorization.input())
        {
            return Err(invalid());
        }
        batch_view.require_public_request_v2(request).map_err(|_| invalid())?;
        let hold = aos_sandbox_ledger_replay::source_policy_hold::current_state(view.materialized_state_v1()).map_err(JournalError::from)?;
        if hold.delete_pending.is_some()
            || hold.hold.is_some_and(|hold| hold.is_held()) || hold.v8_pending.is_some()
            || hold.q04_pending.is_some()
        { return Err(invalid()); }

        let verifier = super::protected_owner::recover_saved_lifecycle_verifier_v1(view)
            .map_err(|_| invalid())?;
        let projection = replay_projection_records::<Schema>(view.all_records(), &verifier)?;
        let encoded = super::format::encode_retained_operation_record(&operation)
            .map_err(|_| invalid())?;
        let operation_record = super::format::record_digest(&encoded).map_err(|_| invalid())?;
        let project = operation.project();
        let operation_id = operation.operation_id();
        let operation_lineage = identity(b"operation", project, operation_id)?;
        let batch_lineage = identity(b"batch", project, operation_id)?;
        let join = identity(b"join", project, operation_id)?;
        let operation_key = super::lifecycle_protected_key_v1(Kind::Auxiliary,
            project, operation_lineage, operation_id).map_err(|_| invalid())?;
        let batch_key = super::lifecycle_protected_key_v1(Kind::Auxiliary,
            project, batch_lineage, operation_id).map_err(|_| invalid())?;
        // An existing cut requires recovery of its exact retained predecessor;
        // a new C17 attempt cannot relabel it as another first Planned fence.
        if projection.records().iter().any(|record|
            record.key() == &operation_key || record.key() == &batch_key
                || record.key().identity().get(32..48) == Some(operation_id.as_bytes().as_slice()))
        { return Err(invalid()); }
        let pending_bytes = batch.as_bytes().to_vec();
        let batch_digest = ObjectDigest::from_bytes(native_value_digest(&pending_bytes));
        let operation_member = LifecycleAuxiliaryRecordV1::proposal(project, operation_id,
            operation.record_revision(), operation_record, operation_lineage, Revision::new(1),
            None, LifecycleAuxiliaryPayloadV1::Operation(operation), join, None, verifier.replay())
            .map_err(|_| invalid())?;
        let batch_member = LifecycleAuxiliaryRecordV1::proposal(project, operation_id,
            operation_member.operation_revision(), operation_record, batch_lineage, Revision::new(1),
            None, LifecycleAuxiliaryPayloadV1::DeleteBatch(LifecycleDeleteBatchRecordV1::planned_v1(batch)),
            join, None, verifier.replay()).map_err(|_| invalid())?;
        let joined = bind_lifecycle_atomic_join_v1(vec![operation_member, batch_member])
            .map_err(|_| invalid())?;
        let mut envelopes = Vec::with_capacity(2);
        for member in &joined {
            let key = if member.lineage() == operation_lineage {
                operation_key.clone()
            } else { batch_key.clone() };
            envelopes.push(lifecycle_reducer_envelope_v1(key, 1, None,
                LifecycleReducerRecordV1::Auxiliary(member), &verifier).map_err(|_| invalid())?);
        }
        let members = aos_sandbox_broker::domain_transaction_custody::plan_members_v1::<Schema>(
            view, source_sequence, projection.root(), operation_id.into_bytes(), envelopes, &verifier,
        )?;
        let mut records = members.transaction().records().to_vec();
        records.push(JournalRecord::put(RecordNamespace::SourceDomainPolicyHold,
            aos_sandbox_ledger_replay::source_policy_hold::DELETE_PENDING_KEY.to_vec(), pending_bytes));
        let transaction = JournalTransaction::new(operation_id.into_bytes(), records)?;
        Ok(Self { authorization, transaction, project, operation: operation_id, batch_digest,
            source_sequence, controller_sequence, complete })
    }

    pub(crate) fn transaction(&self) -> &JournalTransaction { &self.transaction }

    pub(crate) fn batch_bytes(&self) -> Result<&[u8], JournalError> {
        self.transaction.records().last()
            .filter(|record| record.namespace() == RecordNamespace::SourceDomainPolicyHold
                && record.key() == aos_sandbox_ledger_replay::source_policy_hold::DELETE_PENDING_KEY)
            .and_then(|record| record.value()).ok_or(JournalError::ProtectedBoundary)
    }


    /// Preserves the actual complete entered prefix, including cumulative IO.
    pub(crate) fn complete_demand(&self) -> aos_sandbox_core::ResourceVector { self.complete }


    /// Returns the actual Controller cut used by the checked canonical batch.
    pub(crate) fn controller_sequence_data_v1(&self) -> u64 { self.controller_sequence }

    /// Refuses any intervening Source or Controller transaction before entry.
    pub(crate) fn require_sequences_v1(&self, source: u64, controller: u64) -> Result<(), JournalError> {
        if source != self.source_sequence || controller != self.controller_sequence {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Checks only the D-only acquisition at the shared Source hold frontier.
    pub(crate) fn require_acquisition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction != &self.transaction { return Err(JournalError::ProtectedBoundary); }
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
        if held.delete_pending.is_some()
            || held.hold.is_some_and(|hold| hold.is_held()) || held.v8_pending.is_some()
            || held.q04_pending.is_some()
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    /// Compares the exact saved transaction, including the pending key.
    pub(crate) fn require_saved_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), JournalError> {
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
        if held.delete_pending != Some(self.batch_digest)
            || self.transaction.records().iter().any(|record|
                state.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice) != record.value())
        { return Err(JournalError::StaleAuthoritySnapshot); }
        Ok(())
    }

    /// Returns the already-paid original request for subsequent real joins.
    pub(crate) fn authorization(&self) -> &crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1 {
        self.authorization.authorization()
    }

    /// Returns the original decision's paired clock and earliest lease expiry.
    ///
    /// The authorization binding still borrows that same retained decision;
    /// neither pending persistence nor this projection renews the lease.
    pub(crate) fn authorization_horizon_v1(&self) -> (aos_sandbox_core::RawPairedClockSample, i64) {
        self.authorization.authorization_horizon_v1()
    }

    pub(crate) fn original_public_request_data_v3(&self) -> &[u8] {
        self.authorization.input()
    }

    pub(crate) fn authorization_input_data_v2(&self) -> &[u8] {
        self.authorization.authorization_input_data_v2()
    }

    pub(crate) fn authorization_witness_fields_v2(&self,
        open: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootOpenDataV2,
        challenge: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootChallengeDataV2,
    ) -> Result<aos_sandbox_protocol::domain_ledger::delete_root::authorization::DeleteRootAuthorizationFieldsV2,
        aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2> {
        self.authorization.authorization_witness_fields_v2(open, challenge)
    }

    pub(crate) fn coordinates(&self) -> (ProjectId, OperationId, ObjectDigest) {
        (self.project, self.operation, self.batch_digest)
    }
}

// The idempotency digest commits the actual checked public key. Normalized
// lifecycle request is intrinsically the canonical intent digest: constructor
// and decoder already derive/verify it. Recheck the SAME recipe at this cut.
pub(super) fn require_operation_request_v1(
    operation: &LifecycleOperationV1,
    idempotency: &[u8],
) -> Result<(), super::protected_journal::LifecycleProtectedJournalErrorV1> {
    if operation.idempotency() != super::LifecycleIdempotencyDigestV1::commit(idempotency)
        || operation.normalized_request() != super::format::normalized_request_digest_v1(operation.intent())
    {
        return Err(super::protected_journal::LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}

fn identity(domain: &[u8], project: ProjectId, operation: OperationId) -> Result<ResourceId, JournalError> {
    let digest = Sha256::new().chain_update(b"aos.sandbox.source-delete-pending-lineage.v1\0")
        .chain_update((domain.len() as u64).to_be_bytes()).chain_update(domain)
        .chain_update(project.as_bytes()).chain_update(operation.as_bytes()).finalize();
    let bytes: [u8; 16] = digest[..16].try_into().map_err(|_| JournalError::ProtectedBoundary)?;
    if bytes == [0; 16] { return Err(JournalError::ProtectedBoundary); }
    Ok(ResourceId::from_bytes(bytes))
}

/// Counts the actual retained/planner carriers, without a scalar metadata fee.
pub(crate) fn preparation_fixed_bytes_v1() -> Option<usize> {
    size_of::<Result<SourceDeletePendingPlanV1<'_>, super::protected_journal::LifecycleProtectedJournalErrorV1>>().checked_mul(3)?
        .checked_add(size_of::<aos_sandbox_broker::domain_transaction_custody::DomainPlannedMembersDataV1<Schema>>().checked_mul(3)?)?
        .checked_add(size_of::<super::LifecycleJournalVerifierV1>().checked_mul(3)?)?
        .checked_add(size_of::<super::LifecycleAuxiliaryRecordV1>().checked_mul(8)?)?
        .checked_add(size_of::<super::protected_journal::LifecycleProtectedJournalProjectionV1>().checked_mul(3)?)
}

/// Sizes the reached fixed-width operation and bounded batch before copying.
pub(crate) fn preparation_payload_bytes_v1(
    operation: &LifecycleOperationV1,
    batch: &LifecycleDeleteBatchV1,
    source_bytes: usize,
) -> Result<usize, JournalError> {
    let invalid = || JournalError::LimitExceeded("Delete pending fence representation");
    let operation_bytes = super::format::delete_pending_record_encoded_length_v1(operation)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    preparation_payload_for_operation_bound_v3(operation_bytes, batch.as_bytes().len(), source_bytes)
}

/// Prices the same recipe before a reached operation model is decoded.
///
/// The new readiness producer uses the held native prefix length as an upper
/// bound: it already contains the complete selected Operation envelope, and
/// binding/prepared/ready only replace fixed-width commitments and phase data.
/// This is representation DATA; the same full model/schema validation follows.
pub(crate) fn preparation_payload_for_operation_bound_v3(
    operation_bytes: usize,
    batch_bytes: usize,
    source_bytes: usize,
) -> Result<usize, JournalError> {
    let invalid = || JournalError::LimitExceeded("Delete pending fence representation");
    // Each auxiliary uses the existing 244+32 envelope; the operation
    // payload has a u32 length, and Planned uses its fixed 8+64 outcome slots.
    // Reducers allow at most 64 companion digests. Canonical envelope/member
    // overhead and the three actual keys are additional resident bytes.
    let fixed_member = 244usize.checked_add(32)
        .and_then(|bytes| bytes.checked_add(20 + 64 * 32 + 32))
        .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::domain_ledger::records::ENVELOPE_FIXED_BYTES))
        .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::domain_ledger::records::DURABLE_MEMBER_FIXED_BYTES))
        .and_then(|bytes| bytes.checked_add(Schema::KEY_PREFIX.len() + 1 + 48))
        .ok_or_else(invalid)?;
    let fixed = fixed_member.checked_mul(2)
        .and_then(|bytes| bytes.checked_add(4 + 8 + 64))
        .and_then(|bytes| bytes.checked_add(aos_sandbox_ledger_replay::source_policy_hold::DELETE_PENDING_KEY.len()))
        .ok_or_else(invalid)?;
    let incoming = operation_bytes.checked_add(batch_bytes.checked_mul(2).ok_or_else(invalid)?)
        .and_then(|bytes| bytes.checked_add(fixed)).ok_or_else(invalid)?;
    let reached = source_bytes.checked_add(incoming).ok_or_else(invalid)?;
    let model = super::format::delete_pending_model_bytes_v1(reached).ok_or_else(invalid)?;
    preparation_fixed_bytes_v1()
        .and_then(|bytes| bytes.checked_add(reached.checked_mul(128)?))
        .and_then(|bytes| bytes.checked_add(model))
        .ok_or_else(invalid)
}
