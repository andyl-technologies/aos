//! Dormant lifecycle protected-journal ownership and cold replay.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{ObjectDigest, OperationId, ResourceId, Revision, SandboxId};
#[cfg(target_os = "linux")]
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::protected_journal::{
    AppliedLifecycleJournalTransactionV1, LifecycleJournalCommitOutcomeV1,
    LifecycleJournalOutcomeUnknownV1, LifecycleJournalRecoveryV1, LifecycleProtectedJournalErrorV1,
    LifecycleProtectedJournalKeyV1, LifecycleProtectedJournalProjectionV1,
    LifecycleProtectedJournalSchemaV1, LifecycleProtectedJournalV1, LifecycleProtectedRecordKindV1,
    LifecycleReducerRecordV1, PreparedLifecycleJournalTransactionV1,
    claim_lifecycle_protected_journal_v1, lifecycle_reducer_envelope_v1,
};
use super::protected_journal_adapter::{
    ProtectedCurrentRecordCandidateV1, decode_reducer_payload_with_validator,
    protected_current_record_candidates_v1,
};
use super::{
    CurrentLifecycleBootDomainInventoriesV1, CurrentLifecycleBootInventoryV1,
    CurrentLifecycleCoordinationV1, CurrentLifecycleOperationV1, CurrentLifecycleRetentionLedgerV1,
    CurrentLifecycleRuntimeLivenessV1, CurrentLifecycleSuspendObservationV1,
    CurrentLifecycleTargetAssignmentV1, LifecycleAttemptStateV1, LifecycleAuxiliaryPayloadV1,
    LifecycleAuxiliaryRecordV1, LifecycleBootDomainInventoryV1, LifecycleBootDomainV1,
    LifecycleBootInventoryDomainsV1, LifecycleBootInventoryV1, LifecycleCoordinationTransactionV1,
    LifecycleDatasetTransactionDigestV1, LifecycleDeferredEffectCursorV1,
    LifecycleDependencyEdgeV1, LifecycleEffectDomainV1, LifecycleEffectObservationV1,
    LifecycleInventoryDigestV1, LifecycleJournalVerifierV1, LifecycleOperationV1,
    LifecycleProtectedCoordinationV1, LifecycleProtectedRetentionLedgerV1,
    LifecycleQuiesceDigestV1, LifecycleRecordDigestV1, LifecycleResourceV1,
    LifecycleRetentionLedgerEntryV1, LifecycleRetentionLedgerV1, LifecycleRetentionPurposeV1,
    LifecycleSnapshotManifestDigestV1, LifecycleStepResultDigestV1,
    LifecycleSuspendObservationDigestV1, LifecycleSuspendObservationV1,
    LifecycleThawCompensationDigestV1, LifecycleTimeV1, LifecycleTransactionIdV1,
    LifecycleWriterFenceDigestV1, LiveRuntimeFenceV1, ResourceExpectedStateV1,
    bind_lifecycle_atomic_join_v1, decode_lifecycle_auxiliary_record_v1,
    decode_operation_record_v1, encode_lifecycle_auxiliary_record_v1, encode_operation_record_v1,
};

/// Holds one exact lifecycle progress transaction before protected mutation.
#[must_use = "prepared lifecycle progress must be committed or deliberately discarded"]
pub struct PreparedLifecycleProgressV1 {
    prepared: PreparedLifecycleJournalTransactionV1,
}

/// Retains the exact transaction after an indeterminate lifecycle progress commit.
#[must_use = "ambiguous lifecycle progress must be recovered after protected reopen"]
pub struct LifecycleProgressOutcomeUnknownV1 {
    pending: LifecycleJournalOutcomeUnknownV1,
}

/// Distinguishes exact lifecycle progress from an outcome requiring reopen.
#[must_use = "lifecycle progress outcomes must be applied or retained for recovery"]
pub enum LifecycleProgressCommitOutcomeV1 {
    /// The successor was committed and read back exactly.
    Applied(AppliedLifecycleJournalTransactionV1),
    /// Durability is unknown and the exact CAS transaction remains retained.
    OutcomeUnknown {
        /// Retains the exact predecessor and successor bytes.
        pending: LifecycleProgressOutcomeUnknownV1,
        /// Reports the underlying journal durability failure.
        cause: crate::journal::JournalError,
    },
}

/// Classifies protected-reopen recovery of an ambiguous progress transaction.
#[must_use = "recovered lifecycle progress must be retried, applied, or quarantined"]
pub enum LifecycleProgressRecoveryV1 {
    /// Reopen found the exact successor.
    Applied(AppliedLifecycleJournalTransactionV1),
    /// Reopen found the exact predecessor and retained the sole retry.
    Retry(PreparedLifecycleProgressV1),
    /// Reopen found mixed or substituted state and retains the exact evidence.
    Diverged(LifecycleProgressOutcomeUnknownV1),
}

/// Reports first admission or exact idempotent replay of a lifecycle operation.
#[must_use = "lifecycle admission outcomes must be retained through durability recovery"]
pub enum LifecycleOperationAdmissionV1 {
    /// The first protected operation record was committed or became ambiguous.
    Admitted {
        /// Names the admitted operation's current protected record.
        key: LifecycleProtectedJournalKeyV1,
        /// Retains exact durable success or outcome-unknown recovery custody.
        outcome: LifecycleProgressCommitOutcomeV1,
    },
    /// The same caller/project/method/key/request is already durable.
    Replay(LifecycleProtectedJournalKeyV1),
}

/// Reports a protected normal-source auxiliary publication.
#[must_use = "current auxiliary authority or retained recovery custody must be consumed"]
pub enum LifecycleCurrentAuxiliaryPublicationV1<Current> {
    /// The append is durable and the returned capability is current.
    Current(Current),
    /// Durability remains unknown and exact recovery custody is retained.
    OutcomeUnknown {
        /// Retains the exact predecessor and successor bytes.
        pending: LifecycleProgressOutcomeUnknownV1,
        /// Reports the protected journal failure.
        cause: crate::journal::JournalError,
    },
    /// Reopen found substituted or mixed state and retained custody.
    Diverged(LifecycleProgressOutcomeUnknownV1),
}

enum SettledAuxiliaryPublicationV1 {
    Current,
    OutcomeUnknown {
        pending: LifecycleProgressOutcomeUnknownV1,
        cause: crate::journal::JournalError,
    },
    Diverged(LifecycleProgressOutcomeUnknownV1),
}

fn intent_snapshot_resource(
    intent: &super::LifecycleIntentV1,
) -> Option<aos_sandbox_core::SnapshotId> {
    match intent {
        super::LifecycleIntentV1::Fork { source, .. } => Some(*source),
        super::LifecycleIntentV1::Restore { snapshot, .. }
        | super::LifecycleIntentV1::Hibernate { snapshot, .. }
        | super::LifecycleIntentV1::Snapshot { snapshot, .. }
        | super::LifecycleIntentV1::DeleteSnapshot { snapshot, .. } => Some(*snapshot),
        super::LifecycleIntentV1::Resume {
            source: super::LifecycleResumeSourceV1::Hibernated { snapshot, .. },
            ..
        } => Some(*snapshot),
        _ => None,
    }
}

fn operation_live_fence(
    operation: &LifecycleOperationV1,
) -> Result<LiveRuntimeFenceV1, LifecycleProtectedJournalErrorV1> {
    if let Some(fence) = operation
        .method_semantic_commit()
        .and_then(|commit| commit.evidence().incarnation())
        .map(|fact| fact.fence())
    {
        return Ok(fence);
    }
    let fence = match operation.intent() {
        super::LifecycleIntentV1::Stop { fence, .. }
        | super::LifecycleIntentV1::SuspendMemory { fence, .. }
        | super::LifecycleIntentV1::Hibernate { fence, .. }
        | super::LifecycleIntentV1::Snapshot { fence, .. }
        | super::LifecycleIntentV1::CreateExecution { fence, .. }
        | super::LifecycleIntentV1::CancelExecution { fence, .. }
        | super::LifecycleIntentV1::AttachView { fence, .. }
        | super::LifecycleIntentV1::ReplaceAttachment { fence, .. }
        | super::LifecycleIntentV1::DetachView { fence, .. } => *fence,
        super::LifecycleIntentV1::Resume {
            source: super::LifecycleResumeSourceV1::Memory { fence },
            ..
        } => *fence,
        _ => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
    };
    Ok(fence)
}

fn latest_applied_post_commit_step(
    operation: &LifecycleOperationV1,
) -> Result<u32, LifecycleProtectedJournalErrorV1> {
    operation
        .steps()
        .iter()
        .rev()
        .find(|step| {
            step.class() == super::LifecycleStepClassV1::PostCommitForward
                && step.state() == super::LifecycleStepStateV1::Applied
        })
        .map(super::LifecycleStepV1::index)
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
}

/// Owns a cold-replayed, dormant lifecycle adapter and its custody verifier.
pub struct LifecycleProtectedJournalOwnerV1<'journal> {
    journal: LifecycleProtectedJournalV1<'journal>,
    verifier: LifecycleJournalVerifierV1,
}

impl<'journal> LifecycleProtectedJournalOwnerV1<'journal> {
    /// Cold-replays actual current records and claims the lifecycle adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed protected records, failed typed replay,
    /// or absent protected provenance.
    pub fn claim(
        journal_owner: &'journal mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<Self, LifecycleProtectedJournalErrorV1> {
        let journal = journal_owner.journal();
        let verifier = recover_lifecycle_journal_verifier_v1(journal)?;
        let claimed = claim_lifecycle_protected_journal_v1(journal, verifier.clone())?;
        claimed.replay()?;
        Ok(Self {
            journal: claimed,
            verifier,
        })
    }

    /// Replays the complete current lifecycle projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed journal is unhealthy or any
    /// current record fails full typed validation.
    pub fn replay(
        &self,
    ) -> Result<LifecycleProtectedJournalProjectionV1, LifecycleProtectedJournalErrorV1> {
        self.journal.replay()
    }

    /// Admits one accepted lifecycle operation into protected source custody.
    ///
    /// Idempotency is resolved from replayed typed operation records before a
    /// write is planned. Exact replay returns the current operation-bearing key
    /// even after that operation has advanced to another protected record
    /// family. A conflicting request or operation identity fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error unless `operation` is a canonical first revision in
    /// the Accepted phase, or when protected replay, idempotency resolution,
    /// compare-and-swap planning, or durable commit fails.
    pub fn admit_operation(
        &mut self,
        operation: LifecycleOperationV1,
    ) -> Result<LifecycleOperationAdmissionV1, LifecycleProtectedJournalErrorV1> {
        if operation.phase() != super::LifecyclePhaseV1::Accepted
            || operation.record_revision().get() != 1
            || operation.predecessor_digest().is_some()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let projection = self.journal.replay()?;
        for envelope in projection.records().iter().filter(|envelope| {
            matches!(
                envelope.key().kind(),
                LifecycleProtectedRecordKindV1::Intent
                    | LifecycleProtectedRecordKindV1::Operation
                    | LifecycleProtectedRecordKindV1::Effect
            )
        }) {
            let reducer =
                decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
                    envelope.key(),
                    envelope.payload(),
                    &self.verifier,
                )?;
            let current = decode_operation_record_v1(reducer.body())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
            if current.caller() != operation.caller()
                || current.project() != operation.project()
                || current.intent().method() != operation.intent().method()
                || current.idempotency() != operation.idempotency()
            {
                continue;
            }
            if current.normalized_request() == operation.normalized_request()
                && current.operation_id() == operation.operation_id()
            {
                return Ok(LifecycleOperationAdmissionV1::Replay(
                    envelope.key().clone(),
                ));
            }
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let subject = aos_sandbox_core::ResourceId::from_bytes(
            super::protected_journal::lifecycle_journal_subject(operation.intent()),
        );
        let key = super::lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Intent,
            operation.project(),
            subject,
            operation.operation_id(),
        )?;
        let envelope = lifecycle_reducer_envelope_v1(
            key.clone(),
            1,
            None,
            LifecycleReducerRecordV1::Operation(&operation),
            &self.verifier,
        )?;
        let prepared = self
            .journal
            .plan(operation.operation_id().into_bytes(), vec![envelope])?;
        let outcome = self.commit_effect_progress(PreparedLifecycleProgressV1 { prepared })?;

        Ok(LifecycleOperationAdmissionV1::Admitted { key, outcome })
    }

    /// Mints a one-shot challenge for the absent initial boot-inventory root.
    ///
    /// The nonce is kernel-generated and bound to the current operation,
    /// projection, and kernel boot. The fixed Host and Storage BSA owners must
    /// authenticate their fresh inventory pairs against it before bootstrap.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation is current, the boot-inventory
    /// key is absent, kernel entropy succeeds, and the kernel boot is stable.
    #[cfg(target_os = "linux")]
    pub fn begin_boot_inventory_bootstrap(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<super::LifecycleBootInventoryBootstrapChallengeV1, LifecycleProtectedJournalErrorV1>
    {
        if self
            .current_boot_inventory(boot_inventory_key)?
            .is_some_and(|current| current.inventory().host_boot() != [0; 16])
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            .into_bytes();
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        super::LifecycleBootInventoryBootstrapChallengeV1::from_protected_absence(
            nonce,
            current.operation().operation_id(),
            current.record(),
            current.projection_root(),
            boot_after,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
    }

    /// Mints a fresh challenge for rechecking an existing boot root.
    ///
    /// # Errors
    ///
    /// Returns an error unless both the operation and boot root are current
    /// and bound to the same projection and kernel boot.
    #[cfg(target_os = "linux")]
    pub fn begin_boot_inventory_recheck(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<super::LifecycleBootInventoryBootstrapChallengeV1, LifecycleProtectedJournalErrorV1>
    {
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let boot = self
            .current_boot_inventory(boot_inventory_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let host_boot = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            .into_bytes();
        if boot.inventory().operation() != current.operation().operation_id()
            || boot.inventory().operation_record() != current.record()
            || boot.projection_root() != current.projection_root()
            || boot.inventory().host_boot() != host_boot
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        super::LifecycleBootInventoryBootstrapChallengeV1::from_protected_absence(
            nonce,
            current.operation().operation_id(),
            current.record(),
            current.projection_root(),
            host_boot,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
    }

    /// Publishes the initial coordination admission from protected current state.
    ///
    /// The dependency closure is derived from the current operation's complete
    /// expectation set. The manifest, retention, and thaw-plan commitments are
    /// consequently not caller-selected auxiliary evidence.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation and retention ledger are current,
    /// the operation is a snapshot barrier, and protected append/recovery
    /// reaches one unambiguous current state.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_coordination_admission<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        retention_key: &LifecycleProtectedJournalKeyV1,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        coordination_lineage: ResourceId,
        coordination_transaction: ResourceId,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleCoordinationV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(
            coordination_key,
            operation.operation(),
            coordination_lineage,
        )?;
        if self.current_coordination(coordination_key)?.is_some() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let retention = self
            .current_retention_ledger(retention_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if operation.projection_root() != retention.projection_root() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let (sandbox, snapshot) = match operation.operation().intent() {
            super::LifecycleIntentV1::Snapshot {
                sandbox, snapshot, ..
            }
            | super::LifecycleIntentV1::Hibernate {
                sandbox, snapshot, ..
            } => (*sandbox, *snapshot),
            _ => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
        };
        let fence = operation_live_fence(operation.operation())?;
        let operation_record = operation.record();
        let projection_root = operation.projection_root();
        let retention_record = retention.retention().record();

        let root = LifecycleResourceV1::Sandbox(sandbox);
        let mut dependencies = operation
            .operation()
            .expectations()
            .iter()
            .map(|expectation| expectation.resource())
            .collect::<Vec<_>>();
        dependencies.push(root);
        dependencies.sort_unstable();
        dependencies.dedup();
        let mut edges = dependencies
            .iter()
            .copied()
            .filter(|resource| *resource != root)
            .map(|resource| LifecycleDependencyEdgeV1::new(resource, root))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        edges.sort_unstable();
        let mut postorder = dependencies
            .iter()
            .copied()
            .filter(|resource| *resource != root)
            .collect::<Vec<_>>();
        postorder.push(root);

        let manifest = LifecycleSnapshotManifestDigestV1::commit(
            &Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.protected-manifest-source.v1\0")
                .chain_update(operation_record.digest().as_bytes())
                .chain_update(projection_root.as_bytes())
                .chain_update(snapshot.as_bytes())
                .finalize(),
        );
        let thaw = LifecycleThawCompensationDigestV1::commit(
            &Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.protected-thaw-source.v1\0")
                .chain_update(operation_record.digest().as_bytes())
                .chain_update(fence.incarnation().as_bytes())
                .chain_update(projection_root.as_bytes())
                .finalize(),
        );
        let snapshot = self
            .verifier
            .issue_dependency_snapshot(
                sandbox,
                fence,
                dependencies,
                edges,
                postorder,
                manifest,
                retention_record,
            )
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let coordination = LifecycleCoordinationTransactionV1::from_controller_snapshot(
            LifecycleTransactionIdV1::new(coordination_transaction)
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
            &snapshot,
            thaw,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = self.prepare_coordination_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            coordination_lineage,
            coordination,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_coordination(coordination_key)?)
    }

    /// Publishes the exact coordination successor proved by one adjacent effect.
    ///
    /// # Errors
    ///
    /// Returns an error unless the current transaction, operation, effect
    /// ordinal/direction, and evidence select exactly one valid adjacent phase.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_coordination_observation<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        coordination_lineage: ResourceId,
        observation: LifecycleEffectObservationV1,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleCoordinationV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(
            coordination_key,
            operation.operation(),
            coordination_lineage,
        )?;
        require_current_succeeded_observation(operation.operation(), observation)?;
        let current = self
            .current_coordination(coordination_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if current.projection_root() != operation.projection_root() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let transaction = current.coordination().transaction();
        let request = observation.request();
        let evidence = [observation.result(), observation.inventory()];
        let successor = match (
            transaction.phase(),
            request.domain(),
            request.ordinal(),
            request.direction(),
        ) {
            (
                super::LifecycleCoordinationPhaseV1::Admitted,
                LifecycleEffectDomainV1::Runtime,
                3,
                super::LifecycleEffectDirectionV1::Forward,
            ) => transaction.successor(
                Some(LifecycleQuiesceDigestV1::commit(evidence[0].as_bytes())),
                Some(LifecycleWriterFenceDigestV1::commit(evidence[1].as_bytes())),
                None,
                super::LifecycleCoordinationPhaseV1::Frozen,
            ),
            (
                super::LifecycleCoordinationPhaseV1::Frozen,
                LifecycleEffectDomainV1::Storage,
                4,
                super::LifecycleEffectDirectionV1::Forward,
            ) => transaction.successor(
                transaction.quiesce(),
                transaction.writer_fence(),
                Some(LifecycleDatasetTransactionDigestV1::commit(
                    &[
                        evidence[0].as_bytes().as_slice(),
                        evidence[1].as_bytes().as_slice(),
                    ]
                    .concat(),
                )),
                super::LifecycleCoordinationPhaseV1::DatasetCommitted,
            ),
            (
                super::LifecycleCoordinationPhaseV1::DatasetCommitted,
                LifecycleEffectDomainV1::Runtime,
                6,
                super::LifecycleEffectDirectionV1::Forward,
            ) => transaction.successor(
                transaction.quiesce(),
                transaction.writer_fence(),
                transaction.dataset_transaction(),
                super::LifecycleCoordinationPhaseV1::Thawed,
            ),
            (
                super::LifecycleCoordinationPhaseV1::Frozen
                | super::LifecycleCoordinationPhaseV1::DatasetCommitted,
                LifecycleEffectDomainV1::Runtime,
                6,
                super::LifecycleEffectDirectionV1::Compensation,
            ) => transaction.successor(
                transaction.quiesce(),
                transaction.writer_fence(),
                transaction.dataset_transaction(),
                super::LifecycleCoordinationPhaseV1::Compensated,
            ),
            _ => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
        }
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = self.prepare_coordination_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            coordination_lineage,
            successor,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_coordination(coordination_key)?)
    }

    /// Rebinds dataset-committed coordination to the exact successor ledger.
    ///
    /// # Errors
    ///
    /// Returns an error unless the protected ledger is the adjacent complete
    /// successor of the ledger frozen into the current coordination record.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_coordination_retention<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        retention_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        coordination_lineage: ResourceId,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleCoordinationV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(
            coordination_key,
            operation.operation(),
            coordination_lineage,
        )?;
        let coordination = self
            .current_coordination(coordination_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let retention = self
            .current_retention_ledger(retention_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if coordination.projection_root() != operation.projection_root()
            || retention.projection_root() != operation.projection_root()
            || retention.retention().ledger().predecessor()
                != Some(
                    coordination
                        .coordination()
                        .transaction()
                        .retention_ledger()
                        .digest(),
                )
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let successor = coordination
            .coordination()
            .transaction()
            .retention_successor(retention.retention().record())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = self.prepare_coordination_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            coordination_lineage,
            successor,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_coordination(coordination_key)?)
    }

    /// Publishes the exact canonical post-snapshot manifest commitment.
    ///
    /// # Errors
    ///
    /// Returns an error unless the grouped dataset transaction is committed,
    /// every canonical snapshot claim is acknowledged by the current protected
    /// ledger, and the manifest is the adjacent refinement of that transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_coordination_manifest<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        retention_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        coordination_lineage: ResourceId,
        snapshot: &super::LifecycleValidatedSnapshotV1,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleCoordinationV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(
            coordination_key,
            operation.operation(),
            coordination_lineage,
        )?;
        let expected_snapshot = intent_snapshot_resource(operation.operation().intent())
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let coordination = self
            .current_coordination(coordination_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let retention = self
            .current_retention_ledger(retention_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let transaction = coordination.coordination().transaction();
        let intent_manifest = LifecycleSnapshotManifestDigestV1::commit(
            &Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.protected-manifest-source.v1\0")
                .chain_update(operation.record().digest().as_bytes())
                .chain_update(operation.projection_root().as_bytes())
                .chain_update(expected_snapshot.as_bytes())
                .finalize(),
        );
        if coordination.projection_root() != operation.projection_root()
            || retention.projection_root() != operation.projection_root()
            || transaction.phase() != super::LifecycleCoordinationPhaseV1::DatasetCommitted
            || transaction.dataset_transaction().is_none()
            || transaction.manifest() != intent_manifest
            || transaction.retention_ledger() != retention.retention().record()
            || snapshot.acknowledgements().is_empty()
            || snapshot.acknowledgements().iter().any(|acknowledgement| {
                acknowledgement.snapshot() != expected_snapshot
                    || !acknowledgement.is_bound_to(retention.retention())
            })
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let successor = transaction
            .manifest_successor(snapshot.manifest())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = self.prepare_coordination_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            coordination_lineage,
            successor,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_coordination(coordination_key)?)
    }

    /// Publishes the absent initial empty retention ledger for the current operation.
    ///
    /// This one-shot source derives the ledger entirely from protected absence;
    /// later effect observations may replace it with adjacent complete revisions.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation is current, the ledger is absent,
    /// and protected append/recovery reaches one unambiguous current state.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_initial_retention_ledger<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        retention_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        retention_lineage: ResourceId,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleRetentionLedgerV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(retention_key, operation.operation(), retention_lineage)?;
        if self.current_retention_ledger(retention_key)?.is_some() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let ledger = LifecycleRetentionLedgerV1::new(Revision::new(1), None, Vec::new())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = self.prepare_retention_ledger_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            retention_lineage,
            ledger,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_retention_ledger(retention_key)?)
    }

    /// Publishes a complete retention-ledger successor from one exact effect observation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the observation names the exact succeeded
    /// CommitRetention attempt and the current coordination and ledger heads
    /// select its complete protected dependency set.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_retention_observation<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        coordination_key: &LifecycleProtectedJournalKeyV1,
        retention_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        retention_lineage: ResourceId,
        observation: LifecycleEffectObservationV1,
        mut acknowledgements: Vec<super::LifecycleProtectedRetentionAcknowledgementV1>,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleRetentionLedgerV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(retention_key, operation.operation(), retention_lineage)?;
        require_current_succeeded_observation(operation.operation(), observation)?;
        let request = observation.request();
        let (sandbox, snapshot) = match operation.operation().intent() {
            super::LifecycleIntentV1::Snapshot {
                sandbox, snapshot, ..
            }
            | super::LifecycleIntentV1::Hibernate {
                sandbox, snapshot, ..
            } => (*sandbox, *snapshot),
            _ => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
        };
        if request.domain() != LifecycleEffectDomainV1::Controller
            || request.ordinal() != 5
            || request.direction() != super::LifecycleEffectDirectionV1::Forward
            || request.target() != *sandbox.as_bytes()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let coordination = self
            .current_coordination(coordination_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let transaction = coordination.coordination().transaction();
        if coordination.projection_root() != operation.projection_root()
            || transaction.phase() != super::LifecycleCoordinationPhaseV1::DatasetCommitted
            || transaction.sandbox() != sandbox
            || request.prerequisite() != transaction.retention_ledger().digest()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let mut resources = transaction
            .dependencies()
            .iter()
            .copied()
            .filter(|resource| *resource != LifecycleResourceV1::Sandbox(sandbox))
            .collect::<Vec<_>>();
        resources.sort_unstable();
        acknowledgements.sort_unstable_by_key(|acknowledgement| acknowledgement.binding().3);
        let holder = ResourceId::from_bytes(*snapshot.as_bytes());
        if resources.is_empty()
            || acknowledgements.len() != resources.len()
            || acknowledgements
                .iter()
                .zip(&resources)
                .any(|(acknowledgement, resource)| {
                    acknowledgement.binding()
                        != (
                            operation.operation().operation_id(),
                            operation.operation().project(),
                            operation.projection_root(),
                            *resource,
                            holder,
                        )
                })
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let projection_root = operation.projection_root();
        let current_retention = self
            .current_retention_ledger(retention_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if current_retention.projection_root() != projection_root
            || current_retention.retention().record() != transaction.retention_ledger()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let current_ledger = current_retention.retention().ledger();
        let revision = current_ledger
            .revision()
            .checked_next()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let predecessor = Some(current_retention.retention().record().digest());
        let mut entries = current_ledger.entries().to_vec();
        entries.retain(|entry| {
            entry.holder() != holder || entry.purpose() != LifecycleRetentionPurposeV1::Snapshot
        });
        for (resource, acknowledgement) in resources.into_iter().zip(acknowledgements) {
            entries.push(
                LifecycleRetentionLedgerEntryV1::new(
                    resource,
                    holder,
                    LifecycleRetentionPurposeV1::Snapshot,
                    acknowledgement.ledger_receipt(),
                )
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
            );
        }
        entries.sort_unstable();
        let ledger = LifecycleRetentionLedgerV1::new(revision, predecessor, entries)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = self.prepare_retention_ledger_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            retention_lineage,
            ledger,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_retention_ledger(retention_key)?)
    }

    /// Publishes terminal memory-suspension evidence from protected current state.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation is a successful terminal
    /// `SuspendMemory`, the Runtime observation is its exact succeeded effect,
    /// and the boot root remains current in the same projection.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_suspend_observation<'current>(
        &'current mut self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &LifecycleProtectedJournalKeyV1,
        observation_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        observation_lineage: ResourceId,
        observation: LifecycleEffectObservationV1,
    ) -> Result<
        LifecycleCurrentAuxiliaryPublicationV1<CurrentLifecycleSuspendObservationV1<'current>>,
        LifecycleProtectedJournalErrorV1,
    > {
        let operation = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        require_auxiliary_key(observation_key, operation.operation(), observation_lineage)?;
        require_current_succeeded_observation(operation.operation(), observation)?;
        let request = observation.request();
        let (sandbox, fence) = match operation.operation().intent() {
            super::LifecycleIntentV1::SuspendMemory { sandbox, fence } => (*sandbox, *fence),
            _ => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
        };
        if request.domain() != LifecycleEffectDomainV1::Runtime
            || request.target() != *sandbox.as_bytes()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let boot = self
            .current_boot_inventory(boot_inventory_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if boot.projection_root() != operation.projection_root()
            || boot.inventory().operation() != operation.operation().operation_id()
            || boot.inventory().operation_record() != operation.record()
            || boot.inventory().fence() != fence
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let observed_at = operation
            .operation()
            .finished_at()
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let digest = LifecycleSuspendObservationDigestV1::commit(
            &Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.protected-suspend-source.v1\0")
                .chain_update(request.payload().as_bytes())
                .chain_update(observation.result().as_bytes())
                .chain_update(observation.inventory().as_bytes())
                .chain_update(observation.inventory_generation().to_be_bytes())
                .chain_update(observation.inventory_source().as_bytes())
                .chain_update(observation.inventory_session().as_bytes())
                .finalize(),
        );
        let prepared = self.prepare_suspend_observation_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            observation_lineage,
            fence,
            boot.inventory().host_boot(),
            digest,
            observed_at,
        )?;
        let settled = self.settle_auxiliary_append(prepared)?;
        auxiliary_publication(settled, self.current_suspend_observation(observation_key)?)
    }

    /// Plans a protected Coordination projection joined to the exact operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation is current, both lineages are
    /// distinct, and the coordination value is the canonical successor for
    /// its retained lineage.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_coordination_append(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        coordination_lineage: ResourceId,
        coordination: LifecycleCoordinationTransactionV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        self.prepare_auxiliary_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            coordination_lineage,
            LifecycleAuxiliaryPayloadV1::Coordination(coordination),
        )
    }

    /// Plans a protected RetentionLedger projection joined to the exact operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation and retained ledger predecessor
    /// are current and the replacement is its exact adjacent revision.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_retention_ledger_append(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        retention_lineage: ResourceId,
        ledger: LifecycleRetentionLedgerV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        self.prepare_auxiliary_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            retention_lineage,
            LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger),
        )
    }

    /// Plans a protected suspend observation derived from the current operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the current operation is a successful terminal
    /// memory suspension and the live fence, boot, and observation are exact.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_suspend_observation_append(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        observation_lineage: ResourceId,
        fence: LiveRuntimeFenceV1,
        host_boot: [u8; 16],
        observation: LifecycleSuspendObservationDigestV1,
        observed_at: LifecycleTimeV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        let current = self.current_operation_value(operation_key)?;
        let observation = LifecycleSuspendObservationV1::from_operation(
            &current,
            fence,
            host_boot,
            observation,
            observed_at,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        self.prepare_auxiliary_append_for_current(
            transaction_id,
            atomic_join,
            operation_lineage,
            observation_lineage,
            current,
            LifecycleAuxiliaryPayloadV1::SuspendObservation(observation),
        )
    }

    /// Plans a protected six-domain boot inventory from the current operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the operation has committed the named applied
    /// post-commit step and all inventory fields form one canonical live boot.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_boot_inventory_append(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        inventory_lineage: ResourceId,
        step: u32,
        fence: LiveRuntimeFenceV1,
        host_boot: [u8; 16],
        domains: LifecycleBootInventoryDomainsV1,
        resources: Vec<LifecycleResourceV1>,
        observed_at: LifecycleTimeV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        let current = self.current_operation_value(operation_key)?;
        let inventory = LifecycleBootInventoryV1::from_operation(
            &current,
            step,
            fence,
            host_boot,
            domains,
            resources,
            observed_at,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        self.prepare_auxiliary_append_for_current(
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            current,
            LifecycleAuxiliaryPayloadV1::BootInventory(inventory),
        )
    }

    /// Plans the absent first boot root from a challenge-authenticated owner join.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_boot_inventory_bootstrap(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        inventory_lineage: ResourceId,
        source: super::LifecycleBootInventoryBootstrapSourceV1,
        observed_at: LifecycleTimeV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        if self
            .current_boot_inventory(boot_inventory_key)?
            .is_some_and(|current| current.inventory().host_boot() != [0; 16])
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let challenge = source.challenge();
        if challenge.operation() != current.operation().operation_id()
            || challenge.operation_record() != current.record()
            || challenge.projection_root() != current.projection_root()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let step = latest_applied_post_commit_step(current.operation())?;
        let fence = operation_live_fence(current.operation())?;
        let mut physical = source.into_physical();
        if physical
            .domain_commitments()
            .iter()
            .any(|value| value.as_bytes() == &[0; 32])
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let authorities = physical.storage_authorities();
        let storage_resources = self.authenticated_storage_resource_map(&authorities)?;
        let desired = super::LifecycleAuthenticatedBootDesiredV1::from_protected_operation(
            current.operation(),
            current.record(),
            current.projection_root(),
            fence.desired().resource(),
            storage_resources,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        physical
            .resolve_storage_resources(&desired)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let commitments = physical.domain_commitments();
        let domains = LifecycleBootInventoryDomainsV1::new(
            commitments[0],
            commitments[1],
            commitments[2],
            commitments[3],
            commitments[4],
            commitments[5],
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let mut resources = physical
            .resources()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        resources.extend(desired.logical_resources());
        resources.sort_unstable();
        resources.dedup();
        if resources.is_empty() || resources.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        self.prepare_boot_inventory_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            step,
            fence,
            challenge.host_boot(),
            domains,
            resources,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_boot_inventory_refresh(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        inventory_lineage: ResourceId,
        host_boot: [u8; 16],
        source: super::LifecycleBootInventoryRefreshSourceV1,
        observed_at: LifecycleTimeV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let previous = self
            .current_boot_inventory(boot_inventory_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let previous_inventory = previous.inventory();
        if previous.projection_root() != current.projection_root()
            || source.operation() != current.operation().operation_id()
            || source.projection_root() != current.projection_root()
            || previous_inventory.operation() != current.operation().operation_id()
            || previous_inventory.operation_record() != current.record()
            || previous_inventory.host_boot() != host_boot
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let mut physical = source.into_physical();
        let authorities = physical.storage_authorities();
        let storage_resources = self.authenticated_storage_resource_map(&authorities)?;
        let desired = super::LifecycleAuthenticatedBootDesiredV1::from_protected_operation(
            current.operation(),
            current.record(),
            current.projection_root(),
            previous_inventory.fence().desired().resource(),
            storage_resources,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        physical
            .resolve_storage_resources(&desired)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let commitments = physical.domain_commitments();
        let domains = LifecycleBootInventoryDomainsV1::new(
            commitments[0],
            commitments[1],
            commitments[2],
            commitments[3],
            commitments[4],
            commitments[5],
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let mut resources = physical
            .resources()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        resources.extend(desired.logical_resources());
        resources.sort_unstable();
        resources.dedup();
        if resources.is_empty() || resources.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        self.prepare_boot_inventory_append(
            operation_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            previous_inventory.step(),
            previous_inventory.fence(),
            host_boot,
            domains,
            resources,
            observed_at,
        )
    }

    fn prepare_auxiliary_append(
        &self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        value_lineage: ResourceId,
        payload: LifecycleAuxiliaryPayloadV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        let current = self.current_operation_value(operation_key)?;
        self.prepare_auxiliary_append_for_current(
            transaction_id,
            atomic_join,
            operation_lineage,
            value_lineage,
            current,
            payload,
        )
    }

    fn prepare_auxiliary_append_for_current(
        &self,
        transaction_id: [u8; 16],
        atomic_join: ResourceId,
        operation_lineage: ResourceId,
        value_lineage: ResourceId,
        current: LifecycleOperationV1,
        payload: LifecycleAuxiliaryPayloadV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        if transaction_id == [0; 16]
            || atomic_join.as_bytes() == &[0; 16]
            || operation_lineage == value_lineage
            || payload.kind() == super::LifecycleAuxiliaryKindV1::Operation
            || payload
                .operation()
                .is_some_and(|payload_operation| payload_operation != current.operation_id())
            || !auxiliary_payload_matches_operation(&payload, &current)
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let project = current.project();
        let operation = current.operation_id();
        let operation_key = super::lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Auxiliary,
            project,
            operation_lineage,
            operation,
        )?;
        let value_key = super::lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Auxiliary,
            project,
            value_lineage,
            operation,
        )?;
        let projection = self.journal.replay()?;
        let operation_body = encode_operation_record_v1(&current)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let operation_record = LifecycleRecordDigestV1::commit(&operation_body);
        let operation_member = self.auxiliary_proposal(
            &projection,
            &operation_key,
            &current,
            operation_record,
            atomic_join,
            LifecycleAuxiliaryPayloadV1::Operation(current.clone()),
        )?;
        let value_member = self.auxiliary_proposal(
            &projection,
            &value_key,
            &current,
            operation_record,
            atomic_join,
            payload,
        )?;
        let records = bind_lifecycle_atomic_join_v1(vec![operation_member, value_member])
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;

        let mut envelopes = Vec::with_capacity(records.len());
        for record in &records {
            let key = if record.kind() == super::LifecycleAuxiliaryKindV1::Operation {
                operation_key.clone()
            } else {
                value_key.clone()
            };
            let previous = projection
                .records()
                .iter()
                .find(|entry| entry.key() == &key);
            let revision = match previous {
                Some(entry) => entry
                    .revision()
                    .checked_add(1)
                    .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
                None => 1,
            };
            envelopes.push(lifecycle_reducer_envelope_v1(
                key,
                revision,
                previous.map(|entry| entry.digest()),
                LifecycleReducerRecordV1::Auxiliary(record),
                &self.verifier,
            )?);
        }
        let prepared = self.journal.plan(transaction_id, envelopes)?;
        Ok(PreparedLifecycleProgressV1 { prepared })
    }

    fn auxiliary_proposal(
        &self,
        projection: &LifecycleProtectedJournalProjectionV1,
        key: &LifecycleProtectedJournalKeyV1,
        current: &LifecycleOperationV1,
        operation_record: LifecycleRecordDigestV1,
        atomic_join: ResourceId,
        payload: LifecycleAuxiliaryPayloadV1,
    ) -> Result<LifecycleAuxiliaryRecordV1, LifecycleProtectedJournalErrorV1> {
        let previous = self.current_auxiliary_record(projection, key)?;
        let (revision, predecessor) = match previous {
            Some(previous) => (
                previous
                    .revision()
                    .checked_next()
                    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
                Some(previous.complete_digest()),
            ),
            None => (Revision::new(1), None),
        };
        LifecycleAuxiliaryRecordV1::proposal(
            current.project(),
            current.operation_id(),
            current.record_revision(),
            operation_record,
            ResourceId::from_bytes(
                key.identity()[16..32]
                    .try_into()
                    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
            ),
            revision,
            predecessor,
            payload,
            atomic_join,
            None,
            self.verifier.replay(),
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
    }

    fn current_operation_value(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<LifecycleOperationV1, LifecycleProtectedJournalErrorV1> {
        self.current_operation(key)?
            .map(|current| current.operation().clone())
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
    }

    /// Plans the atomic refinement of one persisted effect and its next cursor.
    ///
    /// `successor` must be the unique canonical successor of the current
    /// operation. It must refine the observed reserved attempt to success and
    /// must atomically reserve the exact adjacent attempt unless it persists a
    /// method-specific terminal disposition. Consequently a crash exposes
    /// either the old reissuable attempt, the complete new cursor, or a
    /// canonical terminal witness, never an in-memory-only intermediate state.
    ///
    /// # Errors
    ///
    /// Returns an error for stale lineage, a substituted observation, a
    /// non-monotone operation successor, or a successor with an ambiguous or
    /// otherwise invalid next cursor.
    pub fn prepare_effect_progress(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        observation: LifecycleEffectObservationV1,
        successor: LifecycleOperationV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        if !matches!(
            key.kind(),
            LifecycleProtectedRecordKindV1::Operation | LifecycleProtectedRecordKindV1::Effect
        ) {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let projection = self.journal.replay()?;
        let current_envelope = projection
            .records()
            .iter()
            .find(|record| record.key() == key)
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
            current_envelope.key(),
            current_envelope.payload(),
            &self.verifier,
        )?;
        let current = decode_operation_record_v1(reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if !super::format::operation_record_matches_canonical_encoding(&current, reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            || !effect_progress_is_exact(
                &current,
                super::format::record_digest(reducer.body())
                    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
                &successor,
                observation,
            )?
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let revision = current_envelope
            .revision()
            .checked_add(1)
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let envelope = lifecycle_reducer_envelope_v1(
            key.clone(),
            revision,
            Some(current_envelope.digest()),
            LifecycleReducerRecordV1::Operation(&successor),
            &self.verifier,
        )?;
        let prepared = self.journal.plan(transaction_id, vec![envelope])?;
        Ok(PreparedLifecycleProgressV1 { prepared })
    }

    /// Plans the atomic readmission of one exact durable Residual cursor.
    ///
    /// The successor must append one Reserved attempt to the same failed step.
    /// No local deletion cursor is cleared until this transaction is committed
    /// and read back, or its retained ambiguity is resolved as applied.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale record, substituted failure reason/action,
    /// changed full method plan, or any successor other than the exact admitted
    /// same-step retry.
    pub fn prepare_deferred_retry(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
        transaction_id: [u8; 16],
        deferred: LifecycleDeferredEffectCursorV1,
        successor: LifecycleOperationV1,
    ) -> Result<PreparedLifecycleProgressV1, LifecycleProtectedJournalErrorV1> {
        if !matches!(
            key.kind(),
            LifecycleProtectedRecordKindV1::Operation | LifecycleProtectedRecordKindV1::Effect
        ) {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let projection = self.journal.replay()?;
        let current_envelope = projection
            .records()
            .iter()
            .find(|record| record.key() == key)
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
            current_envelope.key(),
            current_envelope.payload(),
            &self.verifier,
        )?;
        let current = decode_operation_record_v1(reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let current_record = super::format::record_digest(reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if !super::format::operation_record_matches_canonical_encoding(&current, reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            || !deferred_retry_is_exact(&current, current_record, &successor, deferred)?
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }

        let revision = current_envelope
            .revision()
            .checked_add(1)
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let envelope = lifecycle_reducer_envelope_v1(
            key.clone(),
            revision,
            Some(current_envelope.digest()),
            LifecycleReducerRecordV1::Operation(&successor),
            &self.verifier,
        )?;
        let prepared = self.journal.plan(transaction_id, vec![envelope])?;
        Ok(PreparedLifecycleProgressV1 { prepared })
    }

    /// Commits one exact lifecycle progress transaction with CAS and readback.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected projection changed before commit or
    /// the fixed journal is unhealthy.
    pub fn commit_effect_progress(
        &mut self,
        prepared: PreparedLifecycleProgressV1,
    ) -> Result<LifecycleProgressCommitOutcomeV1, LifecycleProtectedJournalErrorV1> {
        match self.journal.commit(prepared.prepared)? {
            LifecycleJournalCommitOutcomeV1::Applied(applied) => {
                Ok(LifecycleProgressCommitOutcomeV1::Applied(applied))
            }
            LifecycleJournalCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(LifecycleProgressCommitOutcomeV1::OutcomeUnknown {
                    pending: LifecycleProgressOutcomeUnknownV1 { pending },
                    cause,
                })
            }
        }
    }

    /// Commits a prepared normal auxiliary append with exact CAS/readback.
    ///
    /// # Errors
    ///
    /// Returns an error when protected currentness changed before commit or
    /// the fixed journal became unhealthy. An indeterminate write retains the
    /// exact recovery token in the returned outcome.
    pub fn commit_auxiliary_append(
        &mut self,
        prepared: PreparedLifecycleProgressV1,
    ) -> Result<LifecycleProgressCommitOutcomeV1, LifecycleProtectedJournalErrorV1> {
        self.commit_effect_progress(prepared)
    }

    /// Resolves one indeterminate progress commit from exact retained bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when cold replay is unhealthy or canonical lifecycle
    /// validation fails. Mixed state is returned as `Diverged` and never
    /// converted into retry authority.
    pub fn recover_effect_progress(
        &self,
        unknown: LifecycleProgressOutcomeUnknownV1,
    ) -> Result<LifecycleProgressRecoveryV1, LifecycleProtectedJournalErrorV1> {
        match self.journal.recover(unknown.pending)? {
            LifecycleJournalRecoveryV1::Applied(applied) => {
                Ok(LifecycleProgressRecoveryV1::Applied(applied))
            }
            LifecycleJournalRecoveryV1::Retry(prepared) => Ok(LifecycleProgressRecoveryV1::Retry(
                PreparedLifecycleProgressV1 { prepared },
            )),
            LifecycleJournalRecoveryV1::Diverged(pending) => {
                Ok(LifecycleProgressRecoveryV1::Diverged(
                    LifecycleProgressOutcomeUnknownV1 { pending },
                ))
            }
        }
    }

    /// Recovers an indeterminate normal auxiliary append after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when cold replay or typed validation fails. Mixed
    /// predecessor/successor state remains `Diverged` and never becomes retry
    /// authority.
    pub fn recover_auxiliary_append(
        &self,
        unknown: LifecycleProgressOutcomeUnknownV1,
    ) -> Result<LifecycleProgressRecoveryV1, LifecycleProtectedJournalErrorV1> {
        self.recover_effect_progress(unknown)
    }

    fn settle_auxiliary_append(
        &mut self,
        prepared: PreparedLifecycleProgressV1,
    ) -> Result<SettledAuxiliaryPublicationV1, LifecycleProtectedJournalErrorV1> {
        let outcome = self.commit_auxiliary_append(prepared)?;
        let pending = match outcome {
            LifecycleProgressCommitOutcomeV1::Applied(_) => {
                return Ok(SettledAuxiliaryPublicationV1::Current);
            }
            LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => pending,
        };
        match self.recover_auxiliary_append(pending)? {
            LifecycleProgressRecoveryV1::Applied(_) => Ok(SettledAuxiliaryPublicationV1::Current),
            LifecycleProgressRecoveryV1::Retry(prepared) => {
                match self.commit_auxiliary_append(prepared)? {
                    LifecycleProgressCommitOutcomeV1::Applied(_) => {
                        Ok(SettledAuxiliaryPublicationV1::Current)
                    }
                    LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                        Ok(SettledAuxiliaryPublicationV1::OutcomeUnknown { pending, cause })
                    }
                }
            }
            LifecycleProgressRecoveryV1::Diverged(pending) => {
                Ok(SettledAuxiliaryPublicationV1::Diverged(pending))
            }
        }
    }

    /// Borrows one fully decoded operation from the current fixed projection.
    ///
    /// The returned value is lifetime-bound to this owner. Callers must obtain
    /// a new value after any journal mutation before deriving another inert
    /// lower-domain handoff.
    ///
    /// # Errors
    ///
    /// Returns an error when replay is unhealthy, the key does not name an
    /// operation-bearing kind, or canonical typed decoding disagrees with the
    /// protected envelope.
    pub fn current_operation(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<Option<CurrentLifecycleOperationV1<'_>>, LifecycleProtectedJournalErrorV1> {
        if !matches!(
            key.kind(),
            LifecycleProtectedRecordKindV1::Intent
                | LifecycleProtectedRecordKindV1::Operation
                | LifecycleProtectedRecordKindV1::Effect
        ) {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let projection = self.journal.replay()?;
        let Some(envelope) = projection
            .records()
            .iter()
            .find(|record| record.key() == key)
        else {
            return Ok(None);
        };
        let reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
            envelope.key(),
            envelope.payload(),
            &self.verifier,
        )?;
        let operation = decode_operation_record_v1(reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if !super::format::operation_record_matches_canonical_encoding(&operation, reducer.body())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        Ok(Some(CurrentLifecycleOperationV1::from_protected_current(
            operation,
            super::format::record_digest(reducer.body())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
            projection.root(),
        )))
    }

    /// Borrows one current verifier-owned memory-suspend observation.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-auxiliary key, unhealthy replay, malformed
    /// canonical payload, or an auxiliary member of another family.
    pub fn current_suspend_observation(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<Option<CurrentLifecycleSuspendObservationV1<'_>>, LifecycleProtectedJournalErrorV1>
    {
        let projection = self.journal.replay()?;
        let Some(record) = self.current_auxiliary_record(&projection, key)? else {
            return Ok(None);
        };
        let LifecycleAuxiliaryPayloadV1::SuspendObservation(observation) = record.payload() else {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        };
        Ok(Some(
            CurrentLifecycleSuspendObservationV1::from_protected_current(
                *observation,
                projection.root(),
            ),
        ))
    }

    /// Resolves one current verifier-owned coordination transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for unhealthy replay, malformed canonical payload, or
    /// an auxiliary key that does not name coordination state.
    pub fn current_coordination(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<Option<CurrentLifecycleCoordinationV1<'_>>, LifecycleProtectedJournalErrorV1> {
        let projection = self.journal.replay()?;
        let Some(record) = self.current_auxiliary_record(&projection, key)? else {
            return Ok(None);
        };
        let LifecycleAuxiliaryPayloadV1::Coordination(transaction) = record.payload() else {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        };
        Ok(Some(
            CurrentLifecycleCoordinationV1::from_protected_current(
                LifecycleProtectedCoordinationV1::from_authoritative(transaction.clone()),
                projection.root(),
            ),
        ))
    }

    /// Resolves one current verifier-owned retention ledger.
    ///
    /// # Errors
    ///
    /// Returns an error for unhealthy replay, malformed canonical payload, or
    /// an auxiliary key that does not name retention-ledger state.
    pub fn current_retention_ledger(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<Option<CurrentLifecycleRetentionLedgerV1<'_>>, LifecycleProtectedJournalErrorV1>
    {
        let projection = self.journal.replay()?;
        let Some(record) = self.current_auxiliary_record(&projection, key)? else {
            return Ok(None);
        };
        let LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger) = record.payload() else {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        };
        Ok(Some(
            CurrentLifecycleRetentionLedgerV1::from_protected_current(
                LifecycleProtectedRetentionLedgerV1::from_authoritative(ledger.clone()),
                projection.root(),
            ),
        ))
    }

    /// Borrows one current verifier-owned aggregate boot inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-auxiliary key, unhealthy replay, malformed
    /// canonical payload, or an auxiliary member of another family.
    pub fn current_boot_inventory(
        &self,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<Option<CurrentLifecycleBootInventoryV1<'_>>, LifecycleProtectedJournalErrorV1> {
        let projection = self.journal.replay()?;
        let Some(record) = self.current_auxiliary_record(&projection, key)? else {
            return Ok(None);
        };
        let LifecycleAuxiliaryPayloadV1::BootInventory(inventory) = record.payload() else {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        };
        Ok(Some(
            CurrentLifecycleBootInventoryV1::from_protected_current(
                inventory.clone(),
                projection.root(),
            ),
        ))
    }

    /// Binds a freshly rechecked controller assignment to the current operation.
    pub(crate) fn bind_current_target_assignment<'current>(
        &'current self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        assignment: &'current crate::runtime_scope::CurrentAssignmentTarget,
        target: SandboxId,
    ) -> Result<CurrentLifecycleTargetAssignmentV1<'current>, LifecycleProtectedJournalErrorV1>
    {
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let expected = current
            .operation()
            .expectations()
            .iter()
            .find(|expectation| expectation.resource() == LifecycleResourceV1::Sandbox(target))
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let ResourceExpectedStateV1::Present {
            revision,
            state_digest,
        } = expected.expected()
        else {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        };
        let manifest = assignment.binding().manifest().manifest();
        if assignment.sandbox() != target
            || manifest.desired_generation().get() != revision.get()
            || assignment.binding().assignment_digest() != state_digest.digest()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        Ok(CurrentLifecycleTargetAssignmentV1::from_protected_current(
            target,
            manifest.epoch(),
            manifest.namespace_generation(),
            assignment.binding().assignment_digest(),
            current.operation().operation_id(),
            current.record(),
            current.projection_root(),
        ))
    }

    /// Binds a freshly rechecked Host runtime and kernel boot to current Resume.
    pub(crate) fn bind_current_runtime_liveness<'current>(
        &'current self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        runtime: &'current crate::runtime_scope::CurrentRuntimeScope,
        host_boot: [u8; 16],
    ) -> Result<CurrentLifecycleRuntimeLivenessV1<'current>, LifecycleProtectedJournalErrorV1> {
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let expected_fence = match current.operation().intent() {
            super::LifecycleIntentV1::Resume {
                source: super::LifecycleResumeSourceV1::Memory { fence },
                ..
            } => *fence,
            _ => return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
        };
        let binding = runtime.binding();
        let manifest = binding.manifest().manifest();
        let observed = runtime.observed().fence();
        if host_boot == [0; 16]
            || binding.sandbox() != expected_fence.sandbox()
            || manifest.incarnation() != expected_fence.incarnation()
            || manifest.epoch() != expected_fence.assignment_epoch()
            || manifest.namespace_generation() != expected_fence.namespace_generation()
            || observed.sandbox_id() != expected_fence.sandbox().as_bytes()
            || observed.incarnation_id() != expected_fence.incarnation().as_bytes()
            || observed.assignment_epoch() != expected_fence.assignment_epoch().get()
            || observed.desired_generation() != expected_fence.desired().resource_revision().get()
            || observed.assignment_digest() != binding.assignment_digest().as_bytes()
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let inventory = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.current-runtime-liveness.v1\0")
                .chain_update(host_boot)
                .chain_update(binding.assignment_digest().as_bytes())
                .chain_update(runtime.observed().runtime_handle())
                .chain_update(runtime.observed().payload_scope_handle())
                .finalize()
                .into(),
        );
        Ok(CurrentLifecycleRuntimeLivenessV1::from_protected_current(
            expected_fence,
            host_boot,
            inventory,
            current.operation().operation_id(),
            current.record(),
            current.projection_root(),
        ))
    }

    /// Binds six freshly rechecked domain owners to one current boot record.
    pub(crate) fn bind_current_boot_domains<'current>(
        &'current self,
        operation_key: &LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &LifecycleProtectedJournalKeyV1,
        host_boot: [u8; 16],
        commitments: [ObjectDigest; 6],
        mut physical: super::LifecycleFreshPhysicalInventoryV1,
    ) -> Result<CurrentLifecycleBootDomainInventoriesV1<'current>, LifecycleProtectedJournalErrorV1>
    {
        let current = self
            .current_operation(operation_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let boot = self
            .current_boot_inventory(boot_inventory_key)?
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let inventory = boot.inventory();
        let expected = inventory.domains();
        if host_boot == [0; 16]
            || boot.projection_root() != current.projection_root()
            || inventory.operation() != current.operation().operation_id()
            || inventory.operation_revision() != current.operation().record_revision()
            || inventory.operation_record() != current.record()
            || inventory.host_boot() != host_boot
            || physical.domain_commitments() != commitments
            || commitments
                != [
                    expected.runtime(),
                    expected.mounts(),
                    expected.storage(),
                    expected.network(),
                    expected.cache(),
                    expected.transfers(),
                ]
        {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let domains = [
            LifecycleBootDomainInventoryV1::from_protected_current(
                LifecycleBootDomainV1::Runtime,
                commitments[0],
            ),
            LifecycleBootDomainInventoryV1::from_protected_current(
                LifecycleBootDomainV1::Mount,
                commitments[1],
            ),
            LifecycleBootDomainInventoryV1::from_protected_current(
                LifecycleBootDomainV1::Storage,
                commitments[2],
            ),
            LifecycleBootDomainInventoryV1::from_protected_current(
                LifecycleBootDomainV1::Network,
                commitments[3],
            ),
            LifecycleBootDomainInventoryV1::from_protected_current(
                LifecycleBootDomainV1::Cache,
                commitments[4],
            ),
            LifecycleBootDomainInventoryV1::from_protected_current(
                LifecycleBootDomainV1::Transfer,
                commitments[5],
            ),
        ];
        let mut closed = Vec::with_capacity(domains.len());
        for domain in domains {
            closed.push(domain.map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?);
        }
        let domains: [LifecycleBootDomainInventoryV1; 6] = closed
            .try_into()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let storage_authorities = physical.storage_authorities();
        let storage_resources = self.authenticated_storage_resource_map(&storage_authorities)?;
        let desired = super::LifecycleAuthenticatedBootDesiredV1::from_protected_operation(
            current.operation(),
            current.record(),
            current.projection_root(),
            inventory.fence().desired().resource(),
            storage_resources,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        physical
            .resolve_storage_resources(&desired)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        Ok(
            CurrentLifecycleBootDomainInventoriesV1::from_protected_current(
                domains,
                physical,
                desired,
                inventory.operation(),
                inventory.operation_record(),
                inventory.inventory().digest(),
                boot.projection_root(),
            ),
        )
    }

    fn authenticated_storage_resource_map(
        &self,
        authorities: &BTreeSet<OperationId>,
    ) -> Result<BTreeMap<OperationId, LifecycleResourceV1>, LifecycleProtectedJournalErrorV1> {
        let projection = self.journal.replay()?;
        let mut resources = BTreeMap::new();
        for envelope in projection.records() {
            if !matches!(
                envelope.key().kind(),
                LifecycleProtectedRecordKindV1::Intent
                    | LifecycleProtectedRecordKindV1::Operation
                    | LifecycleProtectedRecordKindV1::Effect
            ) {
                continue;
            }
            let reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
                envelope.key(),
                envelope.payload(),
                &self.verifier,
            )?;
            let operation = decode_operation_record_v1(reducer.body())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
            let Some(snapshot) = intent_snapshot_resource(operation.intent()) else {
                continue;
            };
            let operation_id = operation.operation_id();
            if !authorities.contains(&operation_id) {
                continue;
            }
            let resource = LifecycleResourceV1::Snapshot(snapshot);
            if resources
                .insert(operation_id, resource)
                .is_some_and(|prior| prior != resource)
            {
                return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
            }
        }
        Ok(resources)
    }

    fn current_auxiliary_record(
        &self,
        projection: &LifecycleProtectedJournalProjectionV1,
        key: &LifecycleProtectedJournalKeyV1,
    ) -> Result<Option<LifecycleAuxiliaryRecordV1>, LifecycleProtectedJournalErrorV1> {
        if key.kind() != LifecycleProtectedRecordKindV1::Auxiliary {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let Some(envelope) = projection
            .records()
            .iter()
            .find(|record| record.key() == key)
        else {
            return Ok(None);
        };
        let reducer = decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
            envelope.key(),
            envelope.payload(),
            &self.verifier,
        )?;
        let record = decode_lifecycle_auxiliary_record_v1(reducer.body(), self.verifier.replay())
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let encoded = encode_lifecycle_auxiliary_record_v1(&record)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if encoded.as_slice() != reducer.body() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        Ok(Some(record))
    }
}

fn auxiliary_payload_matches_operation(
    payload: &LifecycleAuxiliaryPayloadV1,
    operation: &LifecycleOperationV1,
) -> bool {
    match payload {
        LifecycleAuxiliaryPayloadV1::Coordination(coordination) => matches!(
            operation.intent(),
            super::LifecycleIntentV1::Snapshot { sandbox, .. }
                | super::LifecycleIntentV1::Hibernate { sandbox, .. }
                if *sandbox == coordination.sandbox()
        ),
        LifecycleAuxiliaryPayloadV1::RetentionLedger(_) => matches!(
            operation.intent().method(),
            super::LifecycleMethodV1::Snapshot
                | super::LifecycleMethodV1::Hibernate
                | super::LifecycleMethodV1::DeleteSnapshot
        ),
        LifecycleAuxiliaryPayloadV1::SuspendObservation(observation) => {
            observation.operation_revision() == operation.record_revision()
        }
        LifecycleAuxiliaryPayloadV1::BootInventory(inventory) => {
            inventory.operation_revision() == operation.record_revision()
        }
        LifecycleAuxiliaryPayloadV1::Operation(_)
        | LifecycleAuxiliaryPayloadV1::Cancellation(_) => false,
    }
}

pub(crate) fn recover_lifecycle_journal_verifier_v1(
    journal: &Journal,
) -> Result<LifecycleJournalVerifierV1, LifecycleProtectedJournalErrorV1> {
    let candidates =
        protected_current_record_candidates_v1::<LifecycleProtectedJournalSchemaV1>(journal)?;
    let authority = protected_lifecycle_authority(&candidates);
    let provisional = super::LifecycleReplayVerificationV1::from_verified_authority(
        authority,
        Vec::new(),
        Vec::new(),
    )
    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let mut accepted_records = Vec::new();
    for candidate in &candidates {
        if candidate.key().kind() != LifecycleProtectedRecordKindV1::Auxiliary {
            continue;
        }
        let record = super::decode_lifecycle_auxiliary_record_from_protected_envelope_v1(
            candidate.body(),
            &provisional,
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        accepted_records.push(record.complete_digest());
    }
    let mut accepted_checkpoints = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == LifecycleProtectedRecordKindV1::Checkpoint)
        .map(ProtectedCurrentRecordCandidateV1::envelope_digest)
        .collect::<Vec<_>>();
    accepted_records.sort_unstable();
    accepted_checkpoints.sort_unstable();
    LifecycleJournalVerifierV1::from_verified_authority(
        authority,
        accepted_records,
        accepted_checkpoints,
    )
    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
}

fn protected_lifecycle_authority(
    candidates: &[ProtectedCurrentRecordCandidateV1<LifecycleProtectedJournalSchemaV1>],
) -> ObjectDigest {
    let mut retained = None;
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == LifecycleProtectedRecordKindV1::Auxiliary)
    {
        let Ok(authority) =
            super::durable::lifecycle_auxiliary_replay_authority_v1(candidate.body())
        else {
            return ObjectDigest::from_bytes([0; 32]);
        };
        if retained.is_some_and(|current| current != authority) {
            return ObjectDigest::from_bytes([0; 32]);
        }
        retained = Some(authority);
    }
    retained.unwrap_or_else(|| {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.fixed-protected-owner.v2\0")
                .chain_update(b"/var/lib/aos/sandbox/source-domains\0")
                .chain_update(b"source-domains-v1.journal\0")
                .finalize()
                .into(),
        )
    })
}

fn deferred_retry_is_exact(
    current: &LifecycleOperationV1,
    current_record: LifecycleRecordDigestV1,
    successor: &LifecycleOperationV1,
    deferred: LifecycleDeferredEffectCursorV1,
) -> Result<bool, LifecycleProtectedJournalErrorV1> {
    let rebuilt = current
        .successor(
            current_record,
            successor.phase(),
            successor.forward_progress(),
            successor.compensation_progress(),
            successor.steps().to_vec(),
            successor.method_semantic_commit().cloned(),
            successor.failure(),
            successor.retry(),
            successor.terminal_result(),
            successor.finished_at(),
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    if &rebuilt != successor
        || deferred.operation() != current.operation_id()
        || deferred.operation_record() != current_record
        || deferred.method_plan() != super::phase6::method_plan_commitment_for_operation(current)
        || deferred.method_plan() != super::phase6::method_plan_commitment_for_operation(successor)
        || successor.phase() == super::LifecyclePhaseV1::Terminal
    {
        return Ok(false);
    }
    let index = usize::try_from(deferred.step())
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let old = current
        .steps()
        .get(index)
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let new = successor
        .steps()
        .get(index)
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let old_attempts = match deferred.direction() {
        super::LifecycleEffectDirectionV1::Forward => old.forward_attempts(),
        super::LifecycleEffectDirectionV1::Compensation => old.compensation_attempts(),
    };
    let new_attempts = match deferred.direction() {
        super::LifecycleEffectDirectionV1::Forward => new.forward_attempts(),
        super::LifecycleEffectDirectionV1::Compensation => new.compensation_attempts(),
    };
    let Some(failed) = old_attempts.last() else {
        return Ok(false);
    };
    let Some(reserved) = new_attempts.last() else {
        return Ok(false);
    };
    let failure_matches = old.state() == super::LifecycleStepStateV1::Residual
        && old.plan().digest() == deferred.plan()
        && failed.state() == LifecycleAttemptStateV1::Failed
        && failed.number() == deferred.failed_attempt()
        && failed.direction() == deferred.direction()
        && failed
            .failure()
            .is_some_and(|failure| failure.detail().digest() == deferred.reason())
        && failed
            .retry()
            .is_some_and(|retry| retry.attempt() == deferred.retry_attempt());
    let retry_matches = new_attempts.len() == old_attempts.len() + 1
        && &new_attempts[..old_attempts.len()] == old_attempts
        && reserved.number() == deferred.retry_attempt()
        && reserved.direction() == deferred.direction()
        && reserved.request() == failed.request()
        && reserved.body() == failed.body()
        && reserved.plan() == failed.plan()
        && reserved.state() == LifecycleAttemptStateV1::Reserved
        && reserved.result().is_none()
        && reserved.failure().is_none()
        && reserved.inventory().is_none()
        && reserved.retry().is_none()
        && reserved.observed_at().is_none();
    let other_attempts_match = match deferred.direction() {
        super::LifecycleEffectDirectionV1::Forward => {
            new.compensation_attempts() == old.compensation_attempts()
        }
        super::LifecycleEffectDirectionV1::Compensation => {
            new.forward_attempts() == old.forward_attempts()
        }
    };
    let aggregate_matches = new.result() == old.result()
        && new.compensation_result() == old.compensation_result()
        && new.inventory().is_none()
        && new.failure().is_none()
        && new.retry().is_none()
        && matches!(
            (deferred.direction(), new.state()),
            (
                super::LifecycleEffectDirectionV1::Forward,
                super::LifecycleStepStateV1::Applying
            ) | (
                super::LifecycleEffectDirectionV1::Compensation,
                super::LifecycleStepStateV1::Compensating
            )
        );
    let changed_steps = current
        .steps()
        .iter()
        .zip(successor.steps())
        .filter(|(old, new)| old != new)
        .count()
        == 1;
    let cursor = super::phase6::persisted_effect_cursor_for_operation(successor)
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let cursor_matches = cursor.is_some_and(|cursor| {
        cursor.step() == deferred.step()
            && cursor.direction() == deferred.direction()
            && cursor.attempt() == deferred.retry_attempt()
            && cursor.state() == LifecycleAttemptStateV1::Reserved
            && cursor.plan() == deferred.plan()
    });
    Ok(deferred.action() != 0
        && failure_matches
        && retry_matches
        && other_attempts_match
        && aggregate_matches
        && changed_steps
        && cursor_matches)
}

fn effect_progress_is_exact(
    current: &LifecycleOperationV1,
    current_record: LifecycleRecordDigestV1,
    successor: &LifecycleOperationV1,
    observation: LifecycleEffectObservationV1,
) -> Result<bool, LifecycleProtectedJournalErrorV1> {
    let request = observation.request();
    let rebuilt = current
        .successor(
            current_record,
            successor.phase(),
            successor.forward_progress(),
            successor.compensation_progress(),
            successor.steps().to_vec(),
            successor.method_semantic_commit().cloned(),
            successor.failure(),
            successor.retry(),
            successor.terminal_result(),
            successor.finished_at(),
        )
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    if &rebuilt != successor
        || request.operation() != current.operation_id()
        || request.operation_revision() != current.record_revision()
    {
        return Ok(false);
    }

    let old_step = current
        .steps()
        .get(
            usize::try_from(request.step())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
        )
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let new_step = successor
        .steps()
        .get(
            usize::try_from(request.step())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
        )
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let (old_attempt, new_attempt) = match request.direction() {
        super::LifecycleEffectDirectionV1::Forward => (
            old_step.forward_attempts().last(),
            new_step.forward_attempts().last(),
        ),
        super::LifecycleEffectDirectionV1::Compensation => (
            old_step.compensation_attempts().last(),
            new_step.compensation_attempts().last(),
        ),
    };
    let (Some(old_attempt), Some(new_attempt)) = (old_attempt, new_attempt) else {
        return Ok(false);
    };
    let old_matches = old_attempt.number() == request.attempt()
        && old_attempt.direction() == request.direction()
        && old_attempt.admission().digest() == request.admission()
        && old_attempt.plan().digest() == request.plan()
        && old_attempt.state() == LifecycleAttemptStateV1::Reserved;
    let exact_result = LifecycleStepResultDigestV1::commit(observation.result().as_bytes());
    let exact_inventory = LifecycleInventoryDigestV1::commit(observation.inventory().as_bytes());
    let refinement_matches = new_attempt.number() == old_attempt.number()
        && new_attempt.direction() == old_attempt.direction()
        && new_attempt.request() == old_attempt.request()
        && new_attempt.body() == old_attempt.body()
        && new_attempt.plan() == old_attempt.plan()
        && new_attempt.admission() == old_attempt.admission()
        && new_attempt.started_at() == old_attempt.started_at()
        && new_attempt.state() == LifecycleAttemptStateV1::Succeeded
        && new_attempt.result() == Some(exact_result)
        && new_attempt.inventory() == Some(exact_inventory)
        && new_attempt.failure().is_none()
        && new_attempt.retry().is_none();
    let exact_observed_step = match request.direction() {
        super::LifecycleEffectDirectionV1::Forward => {
            old_step.forward_attempts().len() == new_step.forward_attempts().len()
                && old_step.forward_attempts()[..old_step.forward_attempts().len() - 1]
                    == new_step.forward_attempts()[..new_step.forward_attempts().len() - 1]
                && old_step.compensation_attempts() == new_step.compensation_attempts()
                && new_step.state() == super::LifecycleStepStateV1::Applied
                && new_step.result() == Some(exact_result)
                && new_step.inventory() == Some(exact_inventory)
                && new_step.compensation_result() == old_step.compensation_result()
        }
        super::LifecycleEffectDirectionV1::Compensation => {
            old_step.compensation_attempts().len() == new_step.compensation_attempts().len()
                && old_step.compensation_attempts()[..old_step.compensation_attempts().len() - 1]
                    == new_step.compensation_attempts()
                        [..new_step.compensation_attempts().len() - 1]
                && old_step.forward_attempts() == new_step.forward_attempts()
                && new_step.state() == super::LifecycleStepStateV1::Compensated
                && new_step.compensation_result() == Some(exact_result)
                && new_step.inventory() == Some(exact_inventory)
                && new_step.result() == old_step.result()
        }
    };

    let next_cursor = super::phase6::persisted_effect_cursor_for_operation(successor)
        .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    if super::phase6::method_plan_commitment_for_operation(current)
        != super::phase6::method_plan_commitment_for_operation(successor)
    {
        return Ok(false);
    }
    let terminal_disposition = super::phase6::persisted_completion_for_operation(successor);
    let expected_next_step = match request.direction() {
        super::LifecycleEffectDirectionV1::Forward => request.step().checked_add(1),
        super::LifecycleEffectDirectionV1::Compensation => request.step().checked_sub(1),
    };
    let next_is_durable = match next_cursor {
        Some(cursor) => {
            successor.phase() != super::LifecyclePhaseV1::Terminal
                && terminal_disposition.is_none()
                && cursor.state() == LifecycleAttemptStateV1::Reserved
                && cursor.direction() == request.direction()
                && Some(cursor.step()) == expected_next_step
        }
        None => {
            terminal_disposition.is_some()
                && expected_next_step.is_none_or(|step| {
                    usize::try_from(step)
                        .ok()
                        .is_none_or(|index| index >= successor.steps().len())
                })
        }
    };
    let changed_steps = current
        .steps()
        .iter()
        .zip(successor.steps())
        .filter_map(|(old, new)| (old != new).then_some(new.index()))
        .collect::<Vec<_>>();
    let exact_changed_set = match next_cursor {
        Some(cursor) if cursor.step() != request.step() => {
            let cursor_index = usize::try_from(cursor.step())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
            changed_steps.len() == 2
                && changed_steps.contains(&request.step())
                && changed_steps.contains(&cursor.step())
                && exact_reserved_successor(
                    current
                        .steps()
                        .get(cursor_index)
                        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
                    successor
                        .steps()
                        .get(cursor_index)
                        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
                    cursor.direction(),
                )
        }
        None => {
            terminal_disposition.is_some()
                && changed_steps.len() == 1
                && changed_steps[0] == request.step()
        }
        Some(_) => false,
    };
    Ok(old_matches
        && refinement_matches
        && exact_observed_step
        && next_is_durable
        && exact_changed_set)
}

fn require_current_succeeded_observation(
    operation: &LifecycleOperationV1,
    observation: LifecycleEffectObservationV1,
) -> Result<(), LifecycleProtectedJournalErrorV1> {
    let request = observation.request();
    if request.operation() != operation.operation_id()
        || request
            .operation_revision()
            .checked_next()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            != operation.record_revision()
    {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let step = operation
        .steps()
        .get(
            usize::try_from(request.step())
                .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?,
        )
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let attempts = match request.direction() {
        super::LifecycleEffectDirectionV1::Forward => step.forward_attempts(),
        super::LifecycleEffectDirectionV1::Compensation => step.compensation_attempts(),
    };
    let attempt = attempts
        .iter()
        .copied()
        .find(|attempt| attempt.number() == request.attempt())
        .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    let exact_result = LifecycleStepResultDigestV1::commit(observation.result().as_bytes());
    let exact_inventory = LifecycleInventoryDigestV1::commit(observation.inventory().as_bytes());
    if attempt.direction() != request.direction()
        || attempt.request().digest() != request.logical_request().digest()
        || attempt.plan().digest() != request.plan()
        || attempt.admission().digest() != request.admission()
        || attempt.state() != LifecycleAttemptStateV1::Succeeded
        || attempt.result() != Some(exact_result)
        || attempt.inventory() != Some(exact_inventory)
        || attempt.failure().is_some()
        || attempt.retry().is_some()
    {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}

fn require_auxiliary_key(
    key: &LifecycleProtectedJournalKeyV1,
    operation: &LifecycleOperationV1,
    lineage: ResourceId,
) -> Result<(), LifecycleProtectedJournalErrorV1> {
    let expected = super::lifecycle_protected_key_v1(
        LifecycleProtectedRecordKindV1::Auxiliary,
        operation.project(),
        lineage,
        operation.operation_id(),
    )?;
    if key != &expected {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}

fn auxiliary_publication<Current>(
    settled: SettledAuxiliaryPublicationV1,
    current: Option<Current>,
) -> Result<LifecycleCurrentAuxiliaryPublicationV1<Current>, LifecycleProtectedJournalErrorV1> {
    match settled {
        SettledAuxiliaryPublicationV1::Current => current
            .map(LifecycleCurrentAuxiliaryPublicationV1::Current)
            .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord),
        SettledAuxiliaryPublicationV1::OutcomeUnknown { pending, cause } => {
            Ok(LifecycleCurrentAuxiliaryPublicationV1::OutcomeUnknown { pending, cause })
        }
        SettledAuxiliaryPublicationV1::Diverged(pending) => {
            Ok(LifecycleCurrentAuxiliaryPublicationV1::Diverged(pending))
        }
    }
}

fn exact_reserved_successor(
    old: &super::LifecycleStepV1,
    new: &super::LifecycleStepV1,
    direction: super::LifecycleEffectDirectionV1,
) -> bool {
    let immutable = old.index() == new.index()
        && old.class() == new.class()
        && old.domain() == new.domain()
        && old.request() == new.request()
        && old.request_body() == new.request_body()
        && old.plan() == new.plan()
        && old.compensation_request() == new.compensation_request()
        && old.compensation_body() == new.compensation_body()
        && old.compensation_plan() == new.compensation_plan();
    let attempt = match direction {
        super::LifecycleEffectDirectionV1::Forward => {
            if new.forward_attempts().len() != old.forward_attempts().len() + 1
                || &new.forward_attempts()[..old.forward_attempts().len()] != old.forward_attempts()
                || new.compensation_attempts() != old.compensation_attempts()
            {
                return false;
            }
            new.forward_attempts().last()
        }
        super::LifecycleEffectDirectionV1::Compensation => {
            if new.compensation_attempts().len() != old.compensation_attempts().len() + 1
                || &new.compensation_attempts()[..old.compensation_attempts().len()]
                    != old.compensation_attempts()
                || new.forward_attempts() != old.forward_attempts()
            {
                return false;
            }
            new.compensation_attempts().last()
        }
    };
    immutable
        && attempt.is_some_and(|attempt| attempt.state() == LifecycleAttemptStateV1::Reserved)
        && new.result() == old.result()
        && new.compensation_result() == old.compensation_result()
        && new.inventory() == old.inventory()
        && new.failure() == old.failure()
        && new.retry() == old.retry()
        && matches!(
            (direction, new.state()),
            (
                super::LifecycleEffectDirectionV1::Forward,
                super::LifecycleStepStateV1::Applying
            ) | (
                super::LifecycleEffectDirectionV1::Compensation,
                super::LifecycleStepStateV1::Compensating
            )
        )
}
