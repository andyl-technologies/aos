//! Compares the atomic Create STOPPED terminal transaction as historical DATA.
//!
//! The existing native COMMIT observer supplies the actual transaction. Its
//! projection is checked at that historical boundary, so a later accepted
//! Start may replace the current public projection without erasing this proof.
//! No constructor grants native IO, completion, a lease, or a lifecycle turn.

mod recovered;
pub use recovered::{CreateStoppedRecoveredTerminalDataV1, CreateStoppedRecoveredTerminalDataErrorV1};

mod observation;
pub use observation::{CreateStoppedNativeObservationDataV2, CreateStoppedNativeObservationErrorV2};

use aos_proto::aos::sandbox::v1::{DesiredLifecycle, SandboxPhase};
use aos_sandbox_core::{OperationId, ProjectId, RecordNamespace, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{EffectHistoryDataError, EffectState, decode_effect_with_q04};
use crate::domain_ledger::public_operation::PublicOperationDataError;
use crate::public_api::projection::PublicProjectionError;
use crate::domain_ledger::operation::{decode_operation, effect_key};
use crate::domain_ledger::public_operation::OperationState;
use crate::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use crate::public_api::{PublicOperationMethodV1, projection::{
    PublicProjectionResourceV1, decode_checked_public_projection_v1,
}, request::DormantSandboxRequestKindV1};

/// Retains canonical decoder causes from a terminal transaction comparison.
#[derive(Debug, thiserror::Error)]
pub enum CreateStoppedTerminalDataErrorV1 {
    /// The existing Effect or retained public-request decoder refused.
    #[error(transparent)]
    Effect(#[from] EffectHistoryDataError),
    /// The existing Operation decoder refused.
    #[error(transparent)]
    Operation(#[from] PublicOperationDataError),
    /// The existing public projection decoder refused.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// Exact terminal identities, members or semantic fields differ.
    #[error("Create STOPPED terminal transaction differs")]
    Mismatch,
}

/// Borrows the immutable public terminal rows for native-history comparison.
///
/// The enclosing Native owner separately validates the complete receipt's
/// Source, workspace-child, resource, Root6/C10 and settled-U relationships.
/// These borrowed rows cannot stand in for that owner or its financial entry.
pub struct CreateStoppedTerminalTransactionDataV1<'rows> {
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    operation_record: &'rows [u8],
    effect_record: &'rows [u8],
    transaction: [u8; 16],
}

impl<'rows> CreateStoppedTerminalTransactionDataV1<'rows> {
    /// Checks the immutable row shapes without claiming they were committed.
    ///
    /// # Errors
    /// Refuses a nonterminal public Create, an absent final Q04 companion, or
    /// another project, method, dispatch, or public-operation shape.
    pub fn from_data_v1(operation: OperationId, project: ProjectId, sandbox: SandboxId,
        operation_record: &'rows [u8], effect_record: &'rows [u8],
    ) -> Result<Self, CreateStoppedTerminalDataErrorV1> {
        require_create_rows_v1(operation, project, sandbox, operation_record,
            effect_record, OperationState::Succeeded)?;
        Ok(Self { operation, project, sandbox, operation_record, effect_record,
            transaction: create_stopped_terminal_transaction_id_v1(operation, effect_record) })
    }

    /// Returns the canonical terminal transaction comparison identity.
    #[must_use]
    pub const fn transaction_id_v1(&self) -> [u8; 16] { self.transaction }

    /// Compares all three ordered members of the actual validated COMMIT.
    ///
    /// A later projection is deliberately irrelevant. This compares the
    /// canonical STOPPED projection in this transaction against the same
    /// immutable accepted Create request and exact terminal public rows.
    ///
    /// # Errors
    /// Rejects another ID, missing/reordered/extra members, differing terminal
    /// bytes, a noncanonical projection, or changed identity, desired content,
    /// generation, lifecycle, or observed STOPPED state.
    pub fn require_transaction_v1(&self, transaction: &JournalTransaction)
        -> Result<(), CreateStoppedTerminalDataErrorV1>
    {
        if transaction.records().len() != 3 || transaction.id() != &self.transaction {
            return Err(invalid());
        }
        self.require_terminal_rows_v2(transaction.records())
    }

    /// Compares exactly the same three terminal members without selecting an ID.
    ///
    /// This borrowed row predicate is shared by the distinct recovered joint4
    /// grammar. Its caller must separately require that grammar's exact ID and
    /// fourth member; these DATA checks do not establish a native observation.
    ///
    /// # Errors
    /// Refuses every unchanged member/projection mismatch or another row count.
    #[doc(hidden)]
    pub fn require_terminal_rows_v2(&self, records: &[JournalRecord])
        -> Result<(), CreateStoppedTerminalDataErrorV1>
    {
        let [effect, operation, projection] = records else {
            return Err(invalid());
        };
        if effect.namespace() != RecordNamespace::Effect
            || effect.key() != effect_key(self.operation, 0)
            || effect.value() != Some(self.effect_record)
            || operation.namespace() != RecordNamespace::Operation
            || operation.key() != self.operation.as_bytes()
            || operation.value() != Some(self.operation_record)
            || projection.namespace() != RecordNamespace::DesiredState {
            return Err(invalid());
        }
        require_create_projection_v1(self.operation, self.project, self.sandbox,
            self.effect_record, projection.key(), projection.value().ok_or_else(invalid)?,
            SandboxPhase::SANDBOX_PHASE_STOPPED)
    }
}

/// Derives the one terminal transaction ID from its complete immutable Effect.
///
/// This is encoding DATA, not evidence of a commit. The complete receipt and
/// unchanged final gate participate through the exact encoded Effect bytes.
#[must_use]
pub fn create_stopped_terminal_transaction_id_v1(operation: OperationId, effect_record: &[u8])
    -> [u8; 16]
{
    let digest = Sha256::new().chain_update(b"aos.sandbox.create-stopped-terminal.v1\0")
        .chain_update(operation.as_bytes()).chain_update(effect_record).finalize();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&digest[..16]);
    transaction
}


/// Borrows the strict one-Effect pre-ACK COMMIT comparison without completion rights.
///
/// The actual Native context independently establishes Source Completing and
/// the complete516 relation. This DATA only validates the immutable historical
/// Applying/Applied/REQUESTED prefix and its exact native transaction membership.
pub struct CreateStoppedPreAckTransactionDataV1<'rows> {
    operation: OperationId,
    effect_record: &'rows [u8],
    transaction: [u8; 16],
}

impl<'rows> CreateStoppedPreAckTransactionDataV1<'rows> {
    /// Compares the actual Applying parent and current REQUESTED Create projection.
    ///
    /// # Errors
    /// Refuses another operation/project/request, missing final Q04 companion,
    /// non-Applied Effect or any mismatched projection/generation/lifecycle field.
    pub fn from_data_v1(operation: OperationId, project: ProjectId, sandbox: SandboxId,
        operation_record: &[u8], effect_record: &'rows [u8],
        projection_key: &[u8], projection_bytes: &[u8],
    ) -> Result<Self, CreateStoppedTerminalDataErrorV1> {
        require_create_rows_v1(operation, project, sandbox, operation_record,
            effect_record, OperationState::Applying)?;
        require_create_projection_v1(operation, project, sandbox, effect_record,
            projection_key, projection_bytes, SandboxPhase::SANDBOX_PHASE_REQUESTED)?;
        Ok(Self { operation, effect_record,
            transaction: create_stopped_pre_ack_transaction_id_v1(operation, effect_record) })
    }

    /// Returns the exact one-Effect native transaction comparison identity.
    #[must_use]
    pub const fn transaction_id_v1(&self) -> [u8; 16] { self.transaction }

    /// Requires one exact Applied Effect and no Operation or projection mutation.
    ///
    /// # Errors
    /// Refuses a different ID, Effect bytes/key, deletion or any extra member.
    pub fn require_transaction_v1(&self, transaction: &JournalTransaction)
        -> Result<(), CreateStoppedTerminalDataErrorV1> {
        let [effect] = transaction.records() else { return Err(invalid()); };
        if transaction.id() != &self.transaction
            || effect.namespace() != RecordNamespace::Effect
            || effect.key() != effect_key(self.operation, 0)
            || effect.value() != Some(self.effect_record) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Commits the complete pre-ACK Effect to its distinct native transaction ID.
///
/// This hash is comparison DATA and cannot create an append original or ACK.
#[must_use]
pub fn create_stopped_pre_ack_transaction_id_v1(operation: OperationId, effect_record: &[u8])
    -> [u8; 16] {
    let digest = Sha256::new().chain_update(b"aos.sandbox.create-stopped-pre-ack.v1\0")
        .chain_update(operation.as_bytes()).chain_update(effect_record).finalize();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&digest[..16]);
    transaction
}

fn require_create_rows_v1(operation: OperationId, project: ProjectId, sandbox: SandboxId,
    operation_record: &[u8], effect_record: &[u8], expected: OperationState,
) -> Result<(), CreateStoppedTerminalDataErrorV1> {
    // This closed grammar only admits Q04 V6. Refuse foreign versions before
    // their decoder can allocate an unrelated authorization graph.
    if effect_record.first() != Some(&6) { return Err(invalid()); }
    let public = decode_operation(operation_record)?;
    let (effect, gate) = decode_effect_with_q04(effect_record)?;
    let context = effect.plan().public_mutation_context()?.ok_or_else(invalid)?;
    if operation.as_bytes() == &[0; 16] || sandbox.as_bytes() == &[0; 16]
        || public.state() != expected || public.effect_count() != 1
        || public.ownership_gated() || public.runtime_intent_digest().is_some()
        || public.public_operation().is_none_or(|metadata|
        metadata.method() != PublicOperationMethodV1::CreateSandbox
            || metadata.accepted_generation() != 1)
        || effect_record.first() != Some(&6)
        || !matches!(effect.state(), EffectState::Applied { .. })
        || gate.as_ref().is_none_or(|gate| gate.status() != 4)
        || effect.dispatch().is_some() || effect.project_admission().is_some()
        || effect.plan().authority().is_some()
        || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateSandbox)
        || context.project() != project
        || !matches!(context.validated_request()?, DormantSandboxRequestKindV1::Create(_)) {
        return Err(invalid());
    }
    Ok(())
}

fn require_create_projection_v1(operation: OperationId, project: ProjectId, expected_sandbox: SandboxId,
    effect_record: &[u8], projection_key: &[u8], projection_bytes: &[u8], expected_phase: SandboxPhase,
) -> Result<(), CreateStoppedTerminalDataErrorV1> {
    if effect_record.first() != Some(&6) { return Err(invalid()); }
    let projection = decode_checked_public_projection_v1(projection_key, projection_bytes)?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
        return Err(invalid());
    };
    let desired = sandbox.desired.as_option().ok_or_else(invalid)?;
    let observed = sandbox.observed.as_option().ok_or_else(invalid)?;
    let (effect, _) = decode_effect_with_q04(effect_record)?;
    let context = effect.plan().public_mutation_context()?.ok_or_else(invalid)?;
    let DormantSandboxRequestKindV1::Create(request) = context.validated_request()? else {
        return Err(invalid());
    };
    if projection.operation() != operation || projection.project() != project
        || sandbox.sandbox_id.as_slice() != expected_sandbox.as_bytes()
        || sandbox.project_id.as_slice() != project.as_bytes()
        || !request.parent_sandbox_id.is_empty()
        || request.project_id.as_slice() != project.as_bytes()
        || request.specification.as_option() != desired.specification.as_option()
        || request.requested_policy.as_option() != desired.requested_policy.as_option()
        || desired.generation != 1 || observed.desired_generation != 1
        || desired.lifecycle.as_known() != Some(DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED)
        || observed.phase.as_known() != Some(expected_phase) {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> CreateStoppedTerminalDataErrorV1 {
    CreateStoppedTerminalDataErrorV1::Mismatch
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::v1::{Sandbox, SandboxDesiredState, SandboxObservedState, Timestamp};
    use aos_sandbox_core::{ResourceId, ResourceKind, Selector};
    use crate::domain_ledger::operation::{OperationRecord, encode_operation_record};
    use crate::domain_ledger::public_operation::{PublicOperationAdmissionV1, PublicOperationAuthorizationV1};
    use crate::domain_ledger::transaction::JournalRecord;
    use crate::public_api::projection::{PublicProjectionPlanV1, PublicProjectionResourceV1};

    const OPERATION: OperationId = OperationId::from_bytes([5; 16]);
    const PROJECT: ProjectId = ProjectId::from_bytes([1; 16]);
    const SANDBOX: SandboxId = SandboxId::from_bytes([9; 16]);

    fn fixture() -> (Vec<u8>, Vec<u8>, PublicProjectionResourceV1) {
        let (effect, gate) = super::super::tests::completed_q04_fixture_v1();
        let context = effect.plan().public_mutation_context().unwrap().unwrap();
        let DormantSandboxRequestKindV1::Create(request) = context.validated_request().unwrap() else {
            panic!("Create fixture changed");
        };
        let resource = PublicProjectionResourceV1::Sandbox(Sandbox {
            sandbox_id: SANDBOX.as_bytes().to_vec(), project_id: PROJECT.as_bytes().to_vec(),
            resource_version: vec![10; 32],
            desired: Some(SandboxDesiredState {
                specification: request.specification.clone(), requested_policy: request.requested_policy.clone(),
                generation: 1, lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
                ..Default::default()
            }).into(),
            observed: Some(SandboxObservedState {
                phase: SandboxPhase::SANDBOX_PHASE_STOPPED.into(), desired_generation: 1,
                observation_sequence: 1, ..Default::default()
            }).into(),
            effective_policy: request.requested_policy.clone(),
            created_at: Some(Timestamp { seconds: 100, ..Default::default() }).into(),
            updated_at: Some(Timestamp { seconds: 100, ..Default::default() }).into(),
            ..Default::default()
        });
        let authorization = PublicOperationAuthorizationV1::new(PROJECT, ResourceKind::Sandbox,
            Selector::Resource { resource: ResourceId::from_bytes(*SANDBOX.as_bytes()) }).unwrap();
        let public = PublicOperationAdmissionV1::new(PublicOperationMethodV1::CreateSandbox,
            1, [11; 16], 100, authorization).unwrap().durable_completed();
        let operation = encode_operation_record(OperationRecord::new(OperationState::Succeeded,
            1, false, None, Some(public)));
        let effect = super::super::encode_q04_effect(&effect, &gate).unwrap();
        (operation, effect, resource)
    }

    fn transaction(operation: &[u8], effect: &[u8], resource: PublicProjectionResourceV1)
        -> JournalTransaction
    {
        let projection = PublicProjectionPlanV1::new(PROJECT, OPERATION, resource).unwrap();
        JournalTransaction::new(create_stopped_terminal_transaction_id_v1(OPERATION, effect), vec![
            JournalRecord::put(RecordNamespace::Effect, effect_key(OPERATION, 0).to_vec(), effect.to_vec()),
            JournalRecord::put(RecordNamespace::Operation, OPERATION.as_bytes().to_vec(), operation.to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, projection.desired_key().to_vec(),
                projection.desired_value().to_vec()),
        ]).unwrap()
    }

    #[test]
    fn native_observer_requires_the_actual_complete_commit_and_refuses_duplicates() {
        let (operation, effect, resource) = fixture();
        let recipe = CreateStoppedTerminalTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &operation, &effect).unwrap();
        let mut observed = CreateStoppedNativeObservationDataV2::terminal_v2(recipe);
        assert!(observed.require_observed_v2().is_err());

        let actual = transaction(&operation, &effect, resource);
        let unrelated = JournalTransaction::new([77; 16], actual.records().to_vec()).unwrap();
        observed.observe_v2(&unrelated).unwrap();
        assert!(observed.require_observed_v2().is_err());
        observed.observe_v2(&actual).unwrap();
        observed.require_observed_v2().unwrap();
        assert!(observed.observe_v2(&actual).is_err());
    }

    #[test]
    fn actual_terminal_transaction_keeps_historical_stopped_independent_of_later_projection() {
        let (operation, effect, resource) = fixture();
        let selected = CreateStoppedTerminalTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &operation, &effect).unwrap();
        let original = transaction(&operation, &effect, resource.clone());
        selected.require_transaction_v1(&original).unwrap();

        // A later Start projection is separate DATA. Only the actual original
        // terminal transaction is supplied to this historical comparison.
        let PublicProjectionResourceV1::Sandbox(mut later) = resource else { panic!() };
        let mut desired = later.desired.as_option().unwrap().clone();
        desired.generation = 2;
        desired.lifecycle = DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING.into();
        later.desired = Some(desired).into();
        let changed = transaction(&operation, &effect, PublicProjectionResourceV1::Sandbox(later));

        assert!(selected.require_transaction_v1(&changed).is_err());
        selected.require_transaction_v1(&original).unwrap();
    }

    #[test]
    fn split_reordered_and_substituted_terminal_members_are_refused() {
        let (operation, effect, resource) = fixture();
        let selected = CreateStoppedTerminalTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &operation, &effect).unwrap();
        let actual = transaction(&operation, &effect, resource);
        let mut reordered = actual.records().to_vec();
        reordered.swap(0, 1);
        let mut missing = actual.records().to_vec();
        missing.pop();
        let mut changed = actual.records().to_vec();
        changed[1] = JournalRecord::put(RecordNamespace::Operation, OPERATION.as_bytes().to_vec(), vec![1]);

        for records in [reordered, missing, changed] {
            let substituted = JournalTransaction::new(*actual.id(), records).unwrap();
            assert!(selected.require_transaction_v1(&substituted).is_err());
        }
    }
    #[test]
    fn recovered_joint_commit_preserves_old_rows_and_requires_exact_new_operation() {
        use crate::domain_ledger::provisioning_root::finality_recover::{
            CreateFinalityObservationAdmissionDataV1 as Admission,
            public_operation::{metadata_complete_operation_v1, metadata_complete_terminal_transaction_v1},
        };
        use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
        use std::collections::BTreeMap;

        let (operation, effect, resource) = fixture();
        let old = transaction(&operation, &effect, resource.clone());
        let request = [b"AOSPMR01".as_slice(), &26_u16.to_be_bytes(),
            &2_u32.to_be_bytes(), &[8, 1]].concat();
        let holder = [3; 16];
        let idempotency_digest = Admission::idempotency_digest_v1(holder, b"metadata-recovery");
        let key = Admission::key_from_original_v1(holder, idempotency_digest);
        let provenance = RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap();
        let admission = Admission {
            operation: Admission::operation_id_v1(&key), request_scope: [10; 32],
            target: *OPERATION.as_bytes(), node: [2; 16], holder,
            project: *PROJECT.as_bytes(), capability: [4; 16], channel: [6; 32],
            authorization_revision: [7; 32], idempotency_digest,
            original: RawPairedClockSample::new_untrusted(provenance,
                [9; 16], 100, 10_000_000_000).unwrap(),
            cutoff: 40_000_000_000, wall_expiry: 140, canonical_request: &request,
        };
        let pending = metadata_complete_operation_v1(admission).unwrap();
        let actual = metadata_complete_terminal_transaction_v1(&old, admission, SANDBOX,
            pending, RawPairedClockSample::new_untrusted(provenance, [9; 16],
                101, 11_000_000_000).unwrap()).unwrap();
        let base = CreateStoppedTerminalTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &operation, &effect).unwrap();
        base.require_transaction_v1(&old).unwrap();
        assert!(base.require_transaction_v1(&actual).is_err());
        assert_eq!(&actual.records()[..3], old.records());

        let completed = actual.records()[3].value().unwrap();
        let recovered = CreateStoppedRecoveredTerminalDataV1::from_data_v1(
            base, admission, completed).unwrap();
        recovered.require_transaction_v1(&actual).unwrap();
        assert!(recovered.require_transaction_v1(&old).is_err());
        let mut wrong_operation = actual.records().to_vec();
        wrong_operation[3] = JournalRecord::put(RecordNamespace::Operation,
            admission.operation.to_vec(), encode_operation_record(pending));
        let wrong_operation = JournalTransaction::new(*actual.id(), wrong_operation).unwrap();
        assert!(recovered.require_transaction_v1(&wrong_operation).is_err());
        let mut reordered = actual.records().to_vec();
        reordered.swap(2, 3);
        assert!(recovered.require_transaction_v1(
            &JournalTransaction::new(*actual.id(), reordered).unwrap()).is_err());

        let mut encoded_admission = vec![0; admission.encoded_bytes_v1().unwrap()];
        admission.encode_into_v1(&mut encoded_admission).unwrap();
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::OperatorRecovery, key.to_vec()), encoded_admission);
        state.insert((RecordNamespace::Operation, admission.operation.to_vec()), completed.to_vec());
        // The current projection may already belong to a later Start. Selection
        // still requires the exact historical STOPPED member in the joint COMMIT.
        let PublicProjectionResourceV1::Sandbox(mut later) = resource else { panic!() };
        let mut desired = later.desired.as_option().unwrap().clone();
        desired.generation = 2;
        desired.lifecycle = DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING.into();
        later.desired = Some(desired).into();
        let changed = transaction(&operation, &effect, PublicProjectionResourceV1::Sandbox(later));
        state.insert((RecordNamespace::DesiredState, changed.records()[2].key().to_vec()),
            changed.records()[2].value().unwrap().to_vec());
        let base = CreateStoppedTerminalTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &operation, &effect).unwrap();
        let mut selected = CreateStoppedNativeObservationDataV2::terminal_from_state_v2(
            base, &state).unwrap();
        assert_eq!(selected.selected_transaction_id_v2(), *actual.id());
        selected.observe_v2(&old).unwrap();
        assert!(selected.require_observed_v2().is_err());
        selected.observe_v2(&actual).unwrap();
        selected.require_observed_v2().unwrap();
        assert!(selected.observe_v2(&actual).is_err());

        let mut changed_joint = actual.records().to_vec();
        changed_joint[2] = changed.records()[2].clone();
        assert!(recovered.require_transaction_v1(
            &JournalTransaction::new(*actual.id(), changed_joint).unwrap()).is_err());
    }

    #[test]
    fn pre_ack_membership_keeps_applying_requested_separate_from_terminal() {
        let (terminal, effect, resource) = fixture();
        let public = decode_operation(&terminal).unwrap();
        let metadata = public.public_operation().unwrap()
            .advance(OperationState::Applying, 100).unwrap();
        let applying = encode_operation_record(public.with_state_and_public_operation(
            OperationState::Applying, Some(metadata)));
        let PublicProjectionResourceV1::Sandbox(mut sandbox) = resource else { panic!() };
        let mut observed = sandbox.observed.as_option().unwrap().clone();
        observed.phase = SandboxPhase::SANDBOX_PHASE_REQUESTED.into();
        sandbox.observed = Some(observed).into();
        let projection = PublicProjectionPlanV1::new(PROJECT, OPERATION,
            PublicProjectionResourceV1::Sandbox(sandbox)).unwrap();
        let selected = CreateStoppedPreAckTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &applying, &effect,
            projection.desired_key(), projection.desired_value(),
        ).unwrap();
        let one = JournalTransaction::new(selected.transaction_id_v1(), vec![JournalRecord::put(
            RecordNamespace::Effect, effect_key(OPERATION, 0).to_vec(), effect.clone(),
        )]).unwrap();
        let mut extra = one.records().to_vec();
        extra.push(JournalRecord::put(RecordNamespace::Operation,
            OPERATION.as_bytes().to_vec(), terminal.clone()));
        let extra = JournalTransaction::new(*one.id(), extra).unwrap();

        selected.require_transaction_v1(&one).unwrap();
        assert!(selected.require_transaction_v1(&extra).is_err());
        assert!(CreateStoppedTerminalTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &applying, &effect).is_err());
        assert!(CreateStoppedPreAckTransactionDataV1::from_data_v1(
            OPERATION, PROJECT, SANDBOX, &terminal, &effect,
            projection.desired_key(), projection.desired_value()).is_err());
    }

}
