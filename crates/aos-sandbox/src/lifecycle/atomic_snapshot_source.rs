//! Durable controller custody for one grouped Storage snapshot effect.
//!
//! The controller journal stores a reservation before transport and a terminal
//! join after an adjacent successor or a protected no-intervening status proof.
//! A pending reservation never grants a second dispatch. Recovery must use the
//! broker-session journal's exact signed request and outcome.
//!
//! ```text
//! AOSLSS01/AOSLSS02 | state:1 | operation:16 | operation-record:32 | projection:32 |
//! plan:32 | effect:32 | publication:32 | template:32 | request-id:16 |
//! request-body:32 | request-packet:32 | predecessor:32 |
//! predecessor-packet:32 | generation:8 | source:32 | session:32 |
//! [V2 only: historical-checkpoint:32] |
//! signed-request:32 | signed-outcome:32 | successor:32 |
//! successor-packet:32 | successor-generation:8 | program:32 | observation:32 |
//! digest:32
//! ```
//!
//! All integers are big endian. The terminal fields before `digest` are
//! zero in a pending reservation. V2 binds the broker journal's immutable
//! signed-hello/context checkpoint; V1 remains readable but cannot cold-recover
//! a historical trio. The versioned digest covers all preceding bytes.

use aos_proto::aos::sandbox::local::v1::{
    ApplyAtomicStorageSnapshotRequest, BrokerMethod, BrokerRequestEnvelope,
};
use aos_sandbox_core::{ObjectDigest, OperationId};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    CurrentLifecycleOperationV1, LifecycleAtomicDatasetSnapshotPlanV1,
    LifecycleAuthenticatedAtomicStorageSuccessorV1, LifecycleAuthenticatedStorageInventoryV1,
    LifecycleEffectObservationV1, LifecyclePhase6ErrorV1, LifecycleSnapshotBarrierV1,
    LiveRuntimeFenceV1,
};
use crate::PreparedAuthorityEffectV1;
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const NAMESPACE: RecordNamespace = RecordNamespace::LifecycleAtomicSnapshotSource;
const MAGIC_V1: &[u8; 8] = b"AOSLSS01";
const MAGIC_V2: &[u8; 8] = b"AOSLSS02";
const DIGEST_DOMAIN_V1: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source.v1\0";
const DIGEST_DOMAIN_V2: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source-transaction.v1\0";
const RECORD_BYTES_V1: usize = 8 + 1 + 16 + (18 * 32) + 16 + 8 + 8 + 32;
const RECORD_BYTES_V2: usize = RECORD_BYTES_V1 + 32;

#[derive(Clone, Copy)]
enum VerifiedRecoveryKind {
    Adjacent,
    ProtectedStatus,
}

/// Reports a stale or malformed source attempt, or protected journal failure.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleAtomicSnapshotSourceErrorV1 {
    /// The lifecycle effect, authority request, or inventory differs.
    #[error("atomic Storage snapshot source is stale or inconsistent")]
    Stale,
    /// The retained controller source record is corrupt.
    #[error("atomic Storage snapshot source record is corrupt")]
    Corrupt,
    /// The protected journal could not establish a durable result.
    #[error("atomic Storage snapshot source journal failed: {0}")]
    Journal(#[from] JournalError),
}

/// Distinguishes first reservation from exact recovery of existing custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAtomicSnapshotSourceAdmissionV1 {
    /// A new reservation is durable and its selected exact request may be sent.
    Reserved,
    /// A prior reservation must be recovered through broker-session custody.
    RecoverPending,
    /// The same grouped effect already has a durable successor join.
    RecoverComplete,
}

/// Distinguishes a new durable successor from an exact idempotent replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAtomicSnapshotSourceCompletionV1 {
    /// The authenticated successor was recorded in this call.
    Recorded(LifecycleEffectObservationV1),
    /// The exact authenticated successor was previously recorded.
    Replay(LifecycleEffectObservationV1),
}

/// Classifies a protected-reopen inspection without issuing an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAtomicSnapshotSourceRecoveryV1 {
    /// No source attempt exists for this operation.
    Absent,
    /// The exact request has a durable reservation; resume its original session.
    Pending {
        /// The original broker request ID.
        request_id: [u8; 16],
        /// The original authority request packet commitment.
        request_packet: ObjectDigest,
        /// The exact signed predecessor inventory packet commitment.
        predecessor_packet: ObjectDigest,
        /// The original authenticated Storage session binding.
        session: ObjectDigest,
        /// The immutable signed-hello and protected-context checkpoint.
        checkpoint: ObjectDigest,
    },
    /// The original request and adjacent inventory transition are durable.
    Complete {
        /// The original request whose optional signed-history archive can retire.
        request_id: [u8; 16],
        /// The signed group request commitment.
        signed_request: ObjectDigest,
        /// The whole post-effect Storage inventory commitment.
        successor: ObjectDigest,
        /// The terminal source-record commitment.
        record: ObjectDigest,
    },
}

/// Owns the controller's protected journal for one source-domain transition.
pub struct LifecycleAtomicSnapshotSourceStoreV1<'a> {
    journal: &'a mut Journal,
}

impl<'a> LifecycleAtomicSnapshotSourceStoreV1<'a> {
    /// Wraps an already opened protected controller journal.
    #[must_use]
    pub const fn new(journal: &'a mut Journal) -> Self {
        Self { journal }
    }

    /// Lists durable pending reservations before any new Storage session request.
    ///
    /// # Errors
    ///
    /// Returns an error if protected authority is absent or a source record is
    /// corrupt. Callers must not roll the broker-session history over on error.
    pub fn pending_reservations(
        &self,
    ) -> Result<
        Vec<(OperationId, LifecycleAtomicSnapshotSourceRecoveryV1)>,
        LifecycleAtomicSnapshotSourceErrorV1,
    > {
        self.journal.ensure_protected_authority()?;
        let mut pending = Vec::new();
        for (key, bytes) in self.journal.records(NAMESPACE) {
            let record = SourceRecord::decode(bytes)?;
            if key != record.operation.as_slice() {
                return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
            }
            if record.completion.is_none() {
                pending.push((
                    OperationId::from_bytes(record.operation),
                    LifecycleAtomicSnapshotSourceRecoveryV1::Pending {
                        request_id: record.request_id,
                        request_packet: ObjectDigest::from_bytes(record.request_packet),
                        predecessor_packet: ObjectDigest::from_bytes(record.predecessor_packet),
                        session: ObjectDigest::from_bytes(record.session),
                        checkpoint: ObjectDigest::from_bytes(record.checkpoint),
                    },
                ));
            }
        }
        Ok(pending)
    }

    /// Lists completed original request IDs whose temporary history may retire.
    ///
    /// # Errors
    ///
    /// Returns an error if protected authority is absent or any source record
    /// is corrupt. This never changes a source or grants dispatch authority.
    pub fn completed_request_ids(
        &self,
    ) -> Result<Vec<[u8; 16]>, LifecycleAtomicSnapshotSourceErrorV1> {
        self.journal.ensure_protected_authority()?;
        let mut completed = Vec::new();
        for (key, bytes) in self.journal.records(NAMESPACE) {
            let record = SourceRecord::decode(bytes)?;
            if key != record.operation.as_slice() {
                return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
            }
            if record.completion.is_some() {
                completed.push(record.request_id);
            }
        }
        Ok(completed)
    }

    /// Durably reserves the exact selected Storage group before broker I/O.
    ///
    /// The caller must send only after `Reserved`. Either recovery result
    /// requires resuming the broker-session journal's original exact request.
    /// A journal error may mean the commit was durable; reopen before deciding.
    ///
    /// # Errors
    ///
    /// Returns an error for changed protected lifecycle state, a mismatched
    /// authority request, corrupt retained bytes, or uncertain journal I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        authority: &PreparedAuthorityEffectV1,
    ) -> Result<LifecycleAtomicSnapshotSourceAdmissionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        self.reserve_inner(
            current,
            barrier,
            plan,
            predecessor,
            predecessor_outcome,
            fence,
            authority,
            None,
        )
    }

    /// Reserves a group bound to the broker journal's immutable hello checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero checkpoint, stale lifecycle authority, or
    /// uncertain protected journal commit. The caller must not dispatch then.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_with_checkpoint(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        authority: &PreparedAuthorityEffectV1,
        checkpoint: ObjectDigest,
    ) -> Result<LifecycleAtomicSnapshotSourceAdmissionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        if checkpoint.as_bytes() == &[0; 32] {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        self.reserve_inner(
            current,
            barrier,
            plan,
            predecessor,
            predecessor_outcome,
            fence,
            authority,
            Some(checkpoint),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_inner(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        authority: &PreparedAuthorityEffectV1,
        checkpoint: Option<ObjectDigest>,
    ) -> Result<LifecycleAtomicSnapshotSourceAdmissionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        self.journal.ensure_protected_authority()?;
        let mut candidate = reservation(
            current,
            barrier,
            plan,
            predecessor,
            predecessor_outcome,
            fence,
            authority,
        )?;
        if let Some(checkpoint) = checkpoint {
            candidate.version = 2;
            candidate.checkpoint = *checkpoint.as_bytes();
        }
        match self.load(candidate.operation)? {
            Some(retained) if retained.same_reservation(&candidate) => {
                Ok(if retained.completion.is_some() {
                    LifecycleAtomicSnapshotSourceAdmissionV1::RecoverComplete
                } else {
                    LifecycleAtomicSnapshotSourceAdmissionV1::RecoverPending
                })
            }
            Some(_) => Err(LifecycleAtomicSnapshotSourceErrorV1::Stale),
            None => {
                self.commit(&candidate)?;
                Ok(LifecycleAtomicSnapshotSourceAdmissionV1::Reserved)
            }
        }
    }

    /// Records the exact signed group result and attested adjacent successor.
    ///
    /// The successor is minted by the fixed Storage endpoint attestation and
    /// proves every member changed in one whole-catalog generation. The
    /// reservation still must match the current lifecycle effect and original
    /// authority request. A journal error requires protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or changed reservation, a different signed
    /// group request or receipt, an invalid successor, or journal I/O failure.
    #[allow(clippy::too_many_arguments)]
    pub fn complete(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        authority: &PreparedAuthorityEffectV1,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        successor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        successor: LifecycleAuthenticatedAtomicStorageSuccessorV1,
    ) -> Result<LifecycleAtomicSnapshotSourceCompletionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        self.journal.ensure_protected_authority()?;
        let mut candidate = reservation(
            current,
            barrier,
            plan,
            predecessor,
            predecessor_outcome,
            fence,
            authority,
        )?;
        let retained = self
            .load(candidate.operation)?
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        candidate.version = retained.version;
        candidate.checkpoint = retained.checkpoint;
        if !retained.same_reservation(&candidate) {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }

        let effect = barrier.next_effect(current).map_err(stale_lifecycle)?;
        effect
            .validate_authenticated_atomic_storage_snapshot_request(group.request(), plan, fence)
            .map_err(stale_lifecycle)?;
        authority
            .validate_authenticated_outcome(group)
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        let expected_envelope = authority
            .broker_request()
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?
            .into_envelope();
        let expected_authorization = expected_envelope
            .authorization
            .as_option()
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        let actual_authorization = group
            .request()
            .authorization()
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if group.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            || group.request().request_id() != candidate.request_id
            || digest(group.request().exact_body()) != candidate.request_body
            || actual_authorization.broker_plan() != expected_authorization.broker_plan
            || actual_authorization.broker_plan_signature()
                != expected_authorization.broker_plan_signature
            || actual_authorization.ownership_lease() != expected_authorization.ownership_lease
            || actual_authorization.ownership_lease_signature()
                != expected_authorization.ownership_lease_signature
            || !successor.is_adjacent()
            || successor.current().session() != predecessor.session()
            || !successor.matches_exact_exchange(predecessor_outcome, group, successor_outcome)
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        };
        let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if receipt.program().as_slice() != successor.program().as_bytes()
            || receipt.observation().as_slice() != successor.observation().as_bytes()
            || !same_signed_inventory(successor_outcome, successor.current())?
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }

        let completion = SourceCompletion {
            signed_request: group.request().signed_request_digest(),
            signed_outcome: digest(group.canonical_packet()),
            successor: *successor.current().commitment().as_bytes(),
            successor_packet: digest(successor_outcome.canonical_packet()),
            successor_generation: successor.current().generation(),
            program: *successor.program().as_bytes(),
            observation: *successor.observation().as_bytes(),
        };
        let observation = effect
            .observe_atomic_dataset_snapshot(plan, successor)
            .map_err(stale_lifecycle)?;
        if let Some(existing) = retained.completion {
            return if existing == completion {
                Ok(LifecycleAtomicSnapshotSourceCompletionV1::Replay(
                    observation,
                ))
            } else {
                Err(LifecycleAtomicSnapshotSourceErrorV1::Stale)
            };
        }

        self.commit(&SourceRecord {
            completion: Some(completion),
            ..retained
        })?;
        Ok(LifecycleAtomicSnapshotSourceCompletionV1::Recorded(
            observation,
        ))
    }

    /// Completes a checkpointed reservation from fully reauthenticated history.
    ///
    /// The original unsigned authority envelope is recovered from the signed
    /// group request, not reminted from a current publication. Its exact digest
    /// must equal the one made durable before the original Apply. The successor
    /// must already carry the fixed-endpoint attestation over this exact trio.
    ///
    /// # Errors
    ///
    /// Returns an error for a legacy or changed reservation, a different
    /// original authority envelope, invalid adjacent successor, or journal I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_verified_history(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        checkpoint: ObjectDigest,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        successor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        successor: LifecycleAuthenticatedAtomicStorageSuccessorV1,
    ) -> Result<LifecycleAtomicSnapshotSourceCompletionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        self.complete_verified_recovery(
            current,
            barrier,
            plan,
            predecessor,
            predecessor_outcome,
            fence,
            checkpoint,
            group,
            successor_outcome,
            successor,
            VerifiedRecoveryKind::Adjacent,
        )
    }

    /// Completes an original group from its protected no-intervening status.
    ///
    /// This path requires the historical signed request and result, the source
    /// reservation checkpoint, and a distinct fixed-endpoint status proof. It
    /// never creates or dispatches a replacement Storage effect.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed source reservation, a non-status
    /// successor, an original request mismatch, or journal I/O failure.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_verified_status(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        checkpoint: ObjectDigest,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        successor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        successor: LifecycleAuthenticatedAtomicStorageSuccessorV1,
    ) -> Result<LifecycleAtomicSnapshotSourceCompletionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        self.complete_verified_recovery(
            current,
            barrier,
            plan,
            predecessor,
            predecessor_outcome,
            fence,
            checkpoint,
            group,
            successor_outcome,
            successor,
            VerifiedRecoveryKind::ProtectedStatus,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_verified_recovery(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &LifecycleAuthenticatedStorageInventoryV1,
        predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        fence: LiveRuntimeFenceV1,
        checkpoint: ObjectDigest,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        successor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        successor: LifecycleAuthenticatedAtomicStorageSuccessorV1,
        recovery: VerifiedRecoveryKind,
    ) -> Result<LifecycleAtomicSnapshotSourceCompletionV1, LifecycleAtomicSnapshotSourceErrorV1>
    {
        self.journal.ensure_protected_authority()?;
        let operation = current.operation().operation_id().into_bytes();
        let retained = self
            .load(operation)?
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        let effect = barrier.next_effect(current).map_err(stale_lifecycle)?;
        if retained.version != 2
            || retained.checkpoint == [0; 32]
            || retained.checkpoint != *checkpoint.as_bytes()
            || retained.operation_record != *current.record().digest().as_bytes()
            || retained.projection != *current.projection_root().as_bytes()
            || retained.plan != *plan.commitment().as_bytes()
            || retained.effect != *effect.payload().as_bytes()
            || barrier
                .atomic_dataset_snapshot_plan(current, predecessor)
                .map_err(stale_lifecycle)?
                != *plan
            || retained.predecessor != *predecessor.commitment().as_bytes()
            || retained.predecessor_packet != digest(predecessor_outcome.canonical_packet())
            || retained.generation != predecessor.generation()
            || retained.source != *predecessor.source().as_bytes()
            || retained.session != *predecessor.session().as_bytes()
            || !same_signed_inventory(predecessor_outcome, predecessor)?
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }

        effect
            .validate_authenticated_atomic_storage_snapshot_request(group.request(), plan, fence)
            .map_err(stale_lifecycle)?;
        if group.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            || group.request().request_id() != retained.request_id
            || digest(group.request().exact_body()) != retained.request_body
            || original_authority_packet_digest(group.request().canonical_packet())?
                != retained.request_packet
            || match recovery {
                VerifiedRecoveryKind::Adjacent => {
                    !successor.is_adjacent()
                        || successor.current().session() != predecessor.session()
                }
                VerifiedRecoveryKind::ProtectedStatus => !successor.is_status_attested(),
            }
            || !successor.matches_exact_exchange(predecessor_outcome, group, successor_outcome)
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        };
        let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if receipt.program().as_slice() != successor.program().as_bytes()
            || receipt.observation().as_slice() != successor.observation().as_bytes()
            || !same_signed_inventory(successor_outcome, successor.current())?
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }

        let completion = SourceCompletion {
            signed_request: group.request().signed_request_digest(),
            signed_outcome: digest(group.canonical_packet()),
            successor: *successor.current().commitment().as_bytes(),
            successor_packet: digest(successor_outcome.canonical_packet()),
            successor_generation: successor.current().generation(),
            program: *successor.program().as_bytes(),
            observation: *successor.observation().as_bytes(),
        };
        let observation = effect
            .observe_atomic_dataset_snapshot(plan, successor)
            .map_err(stale_lifecycle)?;
        if let Some(existing) = retained.completion {
            return if existing == completion {
                Ok(LifecycleAtomicSnapshotSourceCompletionV1::Replay(
                    observation,
                ))
            } else {
                Err(LifecycleAtomicSnapshotSourceErrorV1::Stale)
            };
        }

        self.commit(&SourceRecord {
            completion: Some(completion),
            ..retained
        })?;
        Ok(LifecycleAtomicSnapshotSourceCompletionV1::Recorded(
            observation,
        ))
    }

    /// Inspects the durable source record after reopening protected history.
    ///
    /// This view grants no new dispatch authority. `Pending` means the
    /// original broker-session request must be recovered by its exact ID and
    /// packet commitment; it never permits creating a replacement request.
    ///
    /// # Errors
    ///
    /// Returns an error for an unprotected journal or corrupt retained bytes.
    pub fn recover(
        &self,
        operation: OperationId,
    ) -> Result<LifecycleAtomicSnapshotSourceRecoveryV1, LifecycleAtomicSnapshotSourceErrorV1> {
        self.journal.ensure_protected_authority()?;
        let Some(record) = self.load(operation.into_bytes())? else {
            return Ok(LifecycleAtomicSnapshotSourceRecoveryV1::Absent);
        };
        match record.completion {
            Some(completion) => Ok(LifecycleAtomicSnapshotSourceRecoveryV1::Complete {
                request_id: record.request_id,
                signed_request: ObjectDigest::from_bytes(completion.signed_request),
                successor: ObjectDigest::from_bytes(completion.successor),
                record: ObjectDigest::from_bytes(record.digest()),
            }),
            None => Ok(LifecycleAtomicSnapshotSourceRecoveryV1::Pending {
                request_id: record.request_id,
                request_packet: ObjectDigest::from_bytes(record.request_packet),
                predecessor_packet: ObjectDigest::from_bytes(record.predecessor_packet),
                session: ObjectDigest::from_bytes(record.session),
                checkpoint: ObjectDigest::from_bytes(record.checkpoint),
            }),
        }
    }

    /// Reconstructs lifecycle progress from an already durable terminal join.
    ///
    /// The source record was written only after the exact three signed
    /// exchanges passed the fixed Storage attestation. Recovery checks the
    /// same operation revision and reserved effect before replaying progress.
    ///
    /// # Errors
    ///
    /// Returns an error for absent, pending, corrupt, or stale source custody.
    pub fn recover_complete_observation(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
        barrier: &LifecycleSnapshotBarrierV1,
    ) -> Result<LifecycleEffectObservationV1, LifecycleAtomicSnapshotSourceErrorV1> {
        self.journal.ensure_protected_authority()?;
        let retained = self
            .load(current.operation().operation_id().into_bytes())?
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        let completion = retained
            .completion
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        let effect = barrier.next_effect(current).map_err(stale_lifecycle)?;
        if retained.operation_record != *current.record().digest().as_bytes()
            || retained.projection != *current.projection_root().as_bytes()
            || retained.effect != *effect.payload().as_bytes()
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        LifecycleEffectObservationV1::from_authenticated_readback(
            effect.request(),
            ObjectDigest::from_bytes(completion.observation),
            ObjectDigest::from_bytes(completion.successor),
            completion.successor_generation,
            ObjectDigest::from_bytes(retained.source),
            ObjectDigest::from_bytes(completion.program),
        )
        .map_err(stale_lifecycle)
    }

    fn load(
        &self,
        operation: [u8; 16],
    ) -> Result<Option<SourceRecord>, LifecycleAtomicSnapshotSourceErrorV1> {
        self.journal
            .get(NAMESPACE, &operation)
            .map(SourceRecord::decode)
            .transpose()
            .and_then(|record| match record {
                Some(record) if record.operation != operation => {
                    Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)
                }
                other => Ok(other),
            })
    }

    fn commit(
        &mut self,
        record: &SourceRecord,
    ) -> Result<(), LifecycleAtomicSnapshotSourceErrorV1> {
        let bytes = record.encode();
        let transaction_digest: [u8; 32] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        let transaction_id = transaction_digest[..16]
            .try_into()
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                NAMESPACE,
                record.operation.to_vec(),
                bytes,
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceCompletion {
    signed_request: [u8; 32],
    signed_outcome: [u8; 32],
    successor: [u8; 32],
    successor_packet: [u8; 32],
    successor_generation: u64,
    program: [u8; 32],
    observation: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceRecord {
    version: u8,
    operation: [u8; 16],
    operation_record: [u8; 32],
    projection: [u8; 32],
    plan: [u8; 32],
    effect: [u8; 32],
    publication: [u8; 32],
    template: [u8; 32],
    request_id: [u8; 16],
    request_body: [u8; 32],
    request_packet: [u8; 32],
    predecessor: [u8; 32],
    predecessor_packet: [u8; 32],
    generation: u64,
    source: [u8; 32],
    session: [u8; 32],
    checkpoint: [u8; 32],
    completion: Option<SourceCompletion>,
}

impl SourceRecord {
    fn same_reservation(&self, candidate: &Self) -> bool {
        Self {
            completion: None,
            ..*self
        } == *candidate
    }

    fn body(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(if self.version == 2 {
            RECORD_BYTES_V2
        } else {
            RECORD_BYTES_V1
        });
        bytes.extend_from_slice(if self.version == 2 {
            MAGIC_V2
        } else {
            MAGIC_V1
        });
        bytes.push(u8::from(self.completion.is_some()));
        bytes.extend_from_slice(&self.operation);
        for field in [
            self.operation_record,
            self.projection,
            self.plan,
            self.effect,
            self.publication,
            self.template,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.request_id);
        for field in [
            self.request_body,
            self.request_packet,
            self.predecessor,
            self.predecessor_packet,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.session);
        if self.version == 2 {
            bytes.extend_from_slice(&self.checkpoint);
        }
        let completion = self.completion.unwrap_or(SourceCompletion {
            signed_request: [0; 32],
            signed_outcome: [0; 32],
            successor: [0; 32],
            successor_packet: [0; 32],
            successor_generation: 0,
            program: [0; 32],
            observation: [0; 32],
        });
        bytes.extend_from_slice(&completion.signed_request);
        bytes.extend_from_slice(&completion.signed_outcome);
        bytes.extend_from_slice(&completion.successor);
        bytes.extend_from_slice(&completion.successor_packet);
        bytes.extend_from_slice(&completion.successor_generation.to_be_bytes());
        bytes.extend_from_slice(&completion.program);
        bytes.extend_from_slice(&completion.observation);
        bytes
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(if self.version == 2 {
                DIGEST_DOMAIN_V2
            } else {
                DIGEST_DOMAIN_V1
            })
            .chain_update(self.body())
            .finalize()
            .into()
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body();
        bytes.extend_from_slice(&self.digest());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, LifecycleAtomicSnapshotSourceErrorV1> {
        let version = match bytes.len() {
            RECORD_BYTES_V1 if bytes.get(..8) == Some(MAGIC_V1.as_slice()) => 1,
            RECORD_BYTES_V2 if bytes.get(..8) == Some(MAGIC_V2.as_slice()) => 2,
            _ => return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt),
        };
        let mut input = bytes;
        let _magic = take::<8>(&mut input)?;
        let state = take::<1>(&mut input)?[0];
        if state > 1 {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
        }
        let operation = take(&mut input)?;
        let operation_record = take(&mut input)?;
        let projection = take(&mut input)?;
        let plan = take(&mut input)?;
        let effect = take(&mut input)?;
        let publication = take(&mut input)?;
        let template = take(&mut input)?;
        let request_id = take(&mut input)?;
        let request_body = take(&mut input)?;
        let request_packet = take(&mut input)?;
        let predecessor = take(&mut input)?;
        let predecessor_packet = take(&mut input)?;
        let generation = u64::from_be_bytes(take(&mut input)?);
        let source = take(&mut input)?;
        let session = take(&mut input)?;
        let checkpoint = if version == 2 {
            take(&mut input)?
        } else {
            [0; 32]
        };
        let completion = SourceCompletion {
            signed_request: take(&mut input)?,
            signed_outcome: take(&mut input)?,
            successor: take(&mut input)?,
            successor_packet: take(&mut input)?,
            successor_generation: u64::from_be_bytes(take(&mut input)?),
            program: take(&mut input)?,
            observation: take(&mut input)?,
        };
        let retained_digest = take::<32>(&mut input)?;
        let record = Self {
            version,
            operation,
            operation_record,
            projection,
            plan,
            effect,
            publication,
            template,
            request_id,
            request_body,
            request_packet,
            predecessor,
            predecessor_packet,
            generation,
            source,
            session,
            checkpoint,
            completion: (state == 1).then_some(completion),
        };
        let mandatory = [
            operation_record,
            projection,
            plan,
            effect,
            publication,
            template,
            request_body,
            request_packet,
            predecessor,
            predecessor_packet,
            source,
            session,
        ];
        let terminal = [
            completion.signed_request,
            completion.signed_outcome,
            completion.successor,
            completion.successor_packet,
            completion.program,
            completion.observation,
        ];
        if operation == [0; 16]
            || request_id == [0; 16]
            || generation == 0
            || (version == 2 && checkpoint == [0; 32])
            || mandatory.contains(&[0; 32])
            || (state == 0 && (terminal != [[0; 32]; 6] || completion.successor_generation != 0))
            || (state == 1 && (terminal.contains(&[0; 32]) || completion.successor_generation == 0))
            || retained_digest != record.digest()
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
        }
        Ok(record)
    }
}

#[allow(clippy::too_many_arguments)]
fn reservation(
    current: &CurrentLifecycleOperationV1<'_>,
    barrier: &LifecycleSnapshotBarrierV1,
    plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    predecessor: &LifecycleAuthenticatedStorageInventoryV1,
    predecessor_outcome: &AuthenticatedBrokerMethodOutcomeV1,
    fence: LiveRuntimeFenceV1,
    authority: &PreparedAuthorityEffectV1,
) -> Result<SourceRecord, LifecycleAtomicSnapshotSourceErrorV1> {
    if &barrier
        .atomic_dataset_snapshot_plan(current, predecessor)
        .map_err(stale_lifecycle)?
        != plan
    {
        return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
    }
    let effect = barrier.next_effect(current).map_err(stale_lifecycle)?;
    let request = authority
        .broker_request()
        .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    let body = ApplyAtomicStorageSnapshotRequest::decode_from_slice(authority.attempt().body())
        .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    let desired = fence.desired();
    let wire_fence = body
        .fence
        .as_option()
        .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
        || !body.__buffa_unknown_fields.is_empty()
        || body.encode_to_vec() != authority.attempt().body()
        || body.canonical_plan != plan.canonical_wire_bytes().map_err(stale_lifecycle)?
        || request.request_id() == [0; 16]
        || plan.target_sandbox() != fence.sandbox()
        || wire_fence.sandbox_id.as_slice() != fence.sandbox().as_bytes()
        || wire_fence.incarnation_id.as_slice() != fence.incarnation().as_bytes()
        || wire_fence.assignment_epoch != fence.assignment_epoch().get()
        || wire_fence.desired_generation != desired.expected_generation().get()
        || wire_fence.assignment_digest.as_slice() != desired.resource_state().digest().as_bytes()
        || predecessor.commitment() != plan.inventory()
        || predecessor.generation() != plan.inventory_generation()
        || predecessor.source() != plan.inventory_source()
        || !same_signed_inventory(predecessor_outcome, predecessor)?
    {
        return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
    }
    Ok(SourceRecord {
        version: 1,
        operation: current.operation().operation_id().into_bytes(),
        operation_record: *current.record().digest().as_bytes(),
        projection: *current.projection_root().as_bytes(),
        plan: *plan.commitment().as_bytes(),
        effect: *effect.payload().as_bytes(),
        publication: *authority.publication_digest().as_bytes(),
        template: *authority.attempt().template_digest().as_bytes(),
        request_id: request.request_id(),
        request_body: digest(authority.attempt().body()),
        request_packet: digest(authority.attempt().packet()),
        predecessor: *predecessor.commitment().as_bytes(),
        predecessor_packet: digest(predecessor_outcome.canonical_packet()),
        generation: predecessor.generation(),
        source: *predecessor.source().as_bytes(),
        session: *predecessor.session().as_bytes(),
        checkpoint: [0; 32],
        completion: None,
    })
}

fn same_signed_inventory(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    expected: &LifecycleAuthenticatedStorageInventoryV1,
) -> Result<bool, LifecycleAtomicSnapshotSourceErrorV1> {
    let observed = LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(outcome)
        .map_err(stale_lifecycle)?;
    Ok(observed.commitment() == expected.commitment()
        && observed.generation() == expected.generation()
        && observed.source() == expected.source()
        && observed.session() == expected.session()
        && observed.client_generation() == expected.client_generation()
        && observed.broker_generation() == expected.broker_generation())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn original_authority_packet_digest(
    signed_request_packet: &[u8],
) -> Result<[u8; 32], LifecycleAtomicSnapshotSourceErrorV1> {
    let mut envelope = BrokerRequestEnvelope::decode_from_slice(signed_request_packet)
        .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    envelope.signed_session_request.clear();
    envelope.semantic_bindings = Default::default();
    Ok(digest(&envelope.encode_to_vec()))
}

fn stale_lifecycle(_: LifecyclePhase6ErrorV1) -> LifecycleAtomicSnapshotSourceErrorV1 {
    LifecycleAtomicSnapshotSourceErrorV1::Stale
}

fn take<const N: usize>(
    input: &mut &[u8],
) -> Result<[u8; N], LifecycleAtomicSnapshotSourceErrorV1> {
    let (field, remaining) = input
        .split_first_chunk::<N>()
        .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
    *input = remaining;
    Ok(*field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation() -> SourceRecord {
        SourceRecord {
            version: 1,
            operation: [1; 16],
            operation_record: [2; 32],
            projection: [3; 32],
            plan: [4; 32],
            effect: [5; 32],
            publication: [6; 32],
            template: [7; 32],
            request_id: [8; 16],
            request_body: [9; 32],
            request_packet: [10; 32],
            predecessor: [11; 32],
            predecessor_packet: [12; 32],
            generation: 13,
            source: [14; 32],
            session: [15; 32],
            checkpoint: [0; 32],
            completion: None,
        }
    }

    #[test]
    fn source_record_replay_rejects_corrupt_and_partial_completion() {
        let pending = reservation();
        assert_eq!(SourceRecord::decode(&pending.encode()).unwrap(), pending);

        let checkpointed = SourceRecord {
            version: 2,
            checkpoint: [22; 32],
            ..pending
        };
        assert_eq!(
            SourceRecord::decode(&checkpointed.encode()).unwrap(),
            checkpointed
        );
        let missing_checkpoint = SourceRecord {
            checkpoint: [0; 32],
            ..checkpointed
        };
        assert!(SourceRecord::decode(&missing_checkpoint.encode()).is_err());

        let complete = SourceRecord {
            completion: Some(SourceCompletion {
                signed_request: [16; 32],
                signed_outcome: [17; 32],
                successor: [18; 32],
                successor_packet: [19; 32],
                successor_generation: 14,
                program: [20; 32],
                observation: [21; 32],
            }),
            ..pending
        };
        assert_eq!(SourceRecord::decode(&complete.encode()).unwrap(), complete);

        let mut corrupted = complete.encode();
        corrupted[35] ^= 1;
        assert!(SourceRecord::decode(&corrupted).is_err());

        let partial = SourceRecord {
            completion: Some(SourceCompletion {
                successor_packet: [0; 32],
                ..complete.completion.unwrap()
            }),
            ..pending
        };
        assert!(SourceRecord::decode(&partial.encode()).is_err());
    }

    #[test]
    fn signed_group_packet_recovers_original_authority_envelope_digest() {
        use aos_proto::aos::sandbox::local::v1::BrokerSemanticBindingsV1;

        let original = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT.into(),
            body: vec![1, 2, 3],
            ..Default::default()
        };
        let mut signed = original.clone();
        signed.signed_session_request = vec![4, 5, 6];
        signed.semantic_bindings = Some(BrokerSemanticBindingsV1 {
            storage_catalog_generation: 1,
            storage_catalog_digest: vec![7; 32],
            ..Default::default()
        })
        .into();

        assert_ne!(
            digest(&signed.encode_to_vec()),
            digest(&original.encode_to_vec())
        );
        assert_eq!(
            original_authority_packet_digest(&signed.encode_to_vec()).unwrap(),
            digest(&original.encode_to_vec())
        );
    }
}
