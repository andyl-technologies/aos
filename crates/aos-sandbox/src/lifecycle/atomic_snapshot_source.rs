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
use aos_sandbox_core::{ObjectDigest, OperationId, RawPairedClockSample};
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
    CurrentLifecycleCoordinationV1,
};
use crate::PreparedAuthorityEffectV1;
use crate::lifecycle_authority::{DerivedSourceRecordV3, SnapshotSourceOriginalV3};
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const NAMESPACE: RecordNamespace = RecordNamespace::LifecycleAtomicSnapshotSource;
const MAGIC_V1: &[u8; 8] = b"AOSLSS01";
const MAGIC_V2: &[u8; 8] = b"AOSLSS02";
const DIGEST_DOMAIN_V1: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source.v1\0";
const DIGEST_DOMAIN_V2: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source-transaction.v1\0";
const RECORD_BYTES_V1: usize = 8 + 1 + 16 + (18 * 32) + 16 + 8 + 8 + 32;
const RECORD_BYTES_V2: usize = RECORD_BYTES_V1 + 32;
const MAGIC_V3: &[u8; 8] = b"AOSLSS03";
const DIGEST_DOMAIN_V3: &[u8] = b"aos.sandbox.lifecycle.atomic-snapshot-source.v3\0";
const TRANSACTION_DOMAIN_V3: &[u8] = b"aos.sandbox.lifecycle.snapshot-derived-transaction.v3\0";
const FIXED_BYTES_V3: usize = 616;

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
    /// Selected original custody is debt, not a legacy dispatch reservation.
    OriginalPrerequisite {
        /// Closed unsigned, signed, reserved or terminal stage (0 through 3).
        stage: u8,
        /// Digest of the complete retained canonical original record.
        record: ObjectDigest,
    },
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
    pub(crate) fn same_original_inventory_v3(
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        expected: &LifecycleAuthenticatedStorageInventoryV1,
    ) -> Result<bool, LifecycleAtomicSnapshotSourceErrorV1> {
        same_signed_inventory(outcome, expected)
    }

    pub(crate) fn capture_original_v3(
        current: &CurrentLifecycleOperationV1<'_>,
        coordination: &CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<SnapshotSourceOriginalV3, LifecycleAtomicSnapshotSourceErrorV1> {
        capture_snapshot_source_original_v3(current, coordination)
    }

    // Fully encoded, nonissuing future shapes enter the SAME ordered native
    // preflight. Real signatures, group receipts and predecessor membership
    // are still required and repriced at each eventual actual append.
    pub(crate) fn derived_suffix_v3(
        journal: &Journal,
        unsigned: &DerivedSourceRecordV3,
        body: &[u8],
        packet: &[u8],
    ) -> Result<Vec<JournalTransaction>, LifecycleAtomicSnapshotSourceErrorV1> {
        let seed = if unsigned.stage == 0 { unsigned.digest() } else { unsigned.original };
        let mut transactions = vec![unsigned.transaction(seed)?];
        let mut signed = DerivedSourceRecordV3::decode(&unsigned.encode())?;
        if unsigned.stage == 0 {
            signed.stage = 1;
            signed.original = seed;
            signed.request_id = [1; 16];
            signed.sections[9] = body.to_vec();
            signed.sections[10] = packet.to_vec();
        } else if unsigned.stage != 1 || signed.sections[9] != body || signed.sections[10] != packet {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        checked_derived_length(journal, &signed.sections.each_ref().map(Vec::as_slice))?;
        if unsigned.stage == 0 { transactions.push(signed.transaction(seed)?); }
        let group = LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&signed.sections[1])
            .map_err(stale_lifecycle)?;
        let common = SourceRecord {
            version: 2, operation: signed.operation, operation_record: signed.digests[0],
            projection: seed, plan: signed.digests[7], effect: seed,
            publication: signed.digests[5], template: seed, request_id: signed.request_id,
            request_body: digest(body), request_packet: digest(packet),
            predecessor: signed.digests[8], predecessor_packet: digest(&signed.sections[2]),
            generation: group.inventory_generation(), source: *group.inventory_source().as_bytes(),
            session: signed.digests[9], checkpoint: signed.digests[10], completion: None,
        };
        signed.stage = 2;
        signed.sections[11] = common.encode();
        checked_derived_length(journal, &signed.sections.each_ref().map(Vec::as_slice))?;
        signed.validate()?;
        transactions.push(signed.transaction(seed)?);
        signed.stage = 3;
        signed.sections[11] = SourceRecord {
            completion: Some(SourceCompletion {
                signed_request: seed, signed_outcome: seed, successor: seed,
                successor_packet: seed, successor_generation: group.inventory_generation()
                    .checked_add(1).ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?,
                program: seed, observation: seed,
            }),
            ..common
        }.encode();
        signed.validate()?;
        transactions.push(signed.transaction(seed)?);
        Ok(transactions)
    }

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
            if bytes.starts_with(MAGIC_V3) {
                let record = DerivedSourceRecordV3::decode(bytes)?;
                if key != record.operation.as_slice() {
                    return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
                }
                pending.push((OperationId::from_bytes(record.operation),
                    LifecycleAtomicSnapshotSourceRecoveryV1::OriginalPrerequisite {
                        stage: record.stage, record: ObjectDigest::from_bytes(record.digest()),
                    }));
                continue;
            }
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
            if bytes.starts_with(MAGIC_V3) {
                let record = DerivedSourceRecordV3::decode(bytes)?;
                if key != record.operation.as_slice() {
                    return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
                }
                // Terminal prerequisite custody is not archive-retirement
                // permission. The full Snapshot producer owns that join.
                continue;
            }
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
        if let Some(bytes) = self.journal.get(NAMESPACE, operation.as_bytes()) {
            if bytes.starts_with(MAGIC_V3) {
                let record = DerivedSourceRecordV3::decode(bytes)?;
                if &record.operation != operation.as_bytes() {
                    return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
                }
                return Ok(LifecycleAtomicSnapshotSourceRecoveryV1::OriginalPrerequisite {
                    stage: record.stage, record: ObjectDigest::from_bytes(record.digest()),
                });
            }
        }
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
        ).map_err(JournalError::from)?;
        self.journal.commit(&transaction)?;
        Ok(())
    }
}

pub(crate) fn capture_snapshot_source_original_v3(
    current: &CurrentLifecycleOperationV1<'_>,
    coordination: &CurrentLifecycleCoordinationV1<'_>,
) -> Result<SnapshotSourceOriginalV3, LifecycleAtomicSnapshotSourceErrorV1> {
    let transaction = coordination.coordination().transaction();
    let source = transaction.admitted_source()
        .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    source.require_current(transaction, current.operation())
        .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    if coordination.projection_root() != current.projection_root() {
        return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
    }
    source.encoded_length().map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    let admitted_operation = super::encode_operation_record_v1(source.original())
        .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
    let mut digests = [[0; 32]; 11];
    digests[0] = *current.record().digest().as_bytes();
    digests[1] = *source.record().digest().as_bytes();
    digests[2] = *source.projection_root().as_bytes();
    digests[3] = *source.commitment().as_bytes();
    Ok(SnapshotSourceOriginalV3 {
        operation: current.operation().operation_id().into_bytes(),
        digests, admitted_operation,
    })
}

impl SnapshotSourceOriginalV3 {
    pub(crate) fn require_current(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
        coordination: &CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<(), LifecycleAtomicSnapshotSourceErrorV1> {
        let transaction = coordination.coordination().transaction();
        let source = transaction.admitted_source()
            .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        source.require_current(transaction, current.operation())
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if self.operation != current.operation().operation_id().into_bytes()
            || self.digests[0] != *current.record().digest().as_bytes()
            || self.digests[1] != *source.record().digest().as_bytes()
            || self.digests[2] != *source.projection_root().as_bytes()
            || self.digests[3] != *source.commitment().as_bytes()
            || coordination.projection_root() != current.projection_root()
            || self.admitted_operation != super::encode_operation_record_v1(source.original())
                .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        Ok(())
    }
}

impl DerivedSourceRecordV3 {
    pub(crate) fn new(
        journal: &Journal,
        original: &SnapshotSourceOriginalV3,
        clock: RawPairedClockSample,
        deadline: u64,
        sections: [&[u8]; 12],
    ) -> Result<Self, LifecycleAtomicSnapshotSourceErrorV1> {
        checked_derived_length(journal, &sections)?;
        let record = Self {
            stage: 0, operation: original.operation, digests: original.digests,
            request_id: [0; 16], clock, deadline, original: [0; 32],
            sections: sections.map(<[u8]>::to_vec),
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn retain_signed_original(
        &mut self,
        journal: &Journal,
        request_id: [u8; 16],
        body: &[u8],
        packet: &[u8],
    ) -> Result<(), LifecycleAtomicSnapshotSourceErrorV1> {
        if self.stage != 0 || request_id == [0; 16] {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }

        let mut sections = self.sections.each_ref().map(Vec::as_slice);
        sections[9] = body;
        sections[10] = packet;
        checked_derived_length(journal, &sections)?;

        self.original = self.digest();
        self.stage = 1;
        self.request_id = request_id;
        self.sections[9] = body.to_vec();
        self.sections[10] = packet.to_vec();
        Ok(())
    }

    fn validate(&self) -> Result<(), LifecycleAtomicSnapshotSourceErrorV1> {
        use aos_sandbox_core::format::{decode_broker_authorization_plan, decode_ownership_lease,
            decode_signature, decode_signature_statement};
        use aos_sandbox_core::{BrokerAudience, BrokerGrantTarget, BrokerVerb, DecodeLimits,
            ProtocolId, SignaturePurpose};
        if self.operation == [0; 16] || self.stage > 3
            || self.digests.contains(&[0; 32])
            || self.deadline <= self.clock.boottime_nanoseconds()
            || self.sections[..9].iter().any(Vec::is_empty)
            || (self.stage == 0 && (self.request_id != [0; 16]
                || self.sections[9..].iter().any(|section| !section.is_empty())
                || self.original != [0; 32]))
            || (self.stage > 0 && (self.request_id == [0; 16]
                || self.sections[9..11].iter().any(Vec::is_empty)
                || self.original == [0; 32]))
            || (self.stage <= 1 && !self.sections[11].is_empty())
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
        }
        let operation = super::decode_operation_record_v1(&self.sections[0])
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if operation.operation_id().as_bytes() != &self.operation
            || super::format::record_digest(&self.sections[0]).map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Stale)?
                .digest().as_bytes() != &self.digests[1]
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
        }
        let group = LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&self.sections[1])
            .map_err(stale_lifecycle)?;
        let plan = decode_broker_authorization_plan(&self.sections[3], DecodeLimits::default())
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let statement = decode_signature_statement(&self.sections[4], DecodeLimits::default())
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let lease = decode_ownership_lease(&self.sections[5], DecodeLimits::default())
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let lease_signature = decode_signature(&self.sections[6], DecodeLimits::default())
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let receipt = crate::ownership_authority::OwnershipTransactionReceiptV1::from_canonical_bytes(&self.sections[7])
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let receipt_signature = decode_signature(&self.sections[8], DecodeLimits::default())
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let [grant] = plan.grants() else { return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt); };
        if group.commitment().as_bytes() != &self.digests[7]
            || group.inventory().as_bytes() != &self.digests[8]
            || group.target_sandbox() != plan.assignment().sandbox()
            || plan.audience() != BrokerAudience::Storage || plan.protocol() != ProtocolId::StorageBroker
            || grant.verb() != BrokerVerb::StorageAtomicSnapshot || grant.target() != BrokerGrantTarget::Assignment
            || grant.maximum_descriptors() != 0
            || grant.argument_commitment() != aos_sandbox_core::BrokerArgumentCommitment::for_canonical_bytes(&self.sections[1])
            || statement.purpose() != SignaturePurpose::BrokerAuthorization
            || statement.subject().digest().as_bytes() != &digest(&self.sections[3])
            || statement.issued_seconds() != plan.issued_seconds()
            || statement.expires_seconds() != Some(plan.expires_seconds())
            || lease.assignment().sandbox() != plan.assignment().sandbox()
            || lease.assignment().incarnation() != plan.assignment().incarnation()
            || lease.assignment().epoch() != plan.assignment().epoch()
            || lease.assignment().digest() != plan.assignment().digest() || lease.node() != plan.node()
            || lease_signature.statement().purpose() != SignaturePurpose::OwnershipLease
            || lease_signature.statement().subject().digest().as_bytes() != &digest(&self.sections[5])
            || lease_signature.statement().signer() != plan.ownership_authority()
            || receipt.lease_descriptor().digest().as_bytes() != &digest(&self.sections[5])
            || receipt_signature.statement().subject().digest().as_bytes() != &digest(&self.sections[7])
        {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
        }
        if self.stage > 0 {
            let template = ApplyAtomicStorageSnapshotRequest::decode_from_slice(&self.sections[9])
                .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            let envelope = aos_sandbox_protocol::decode_request_envelope(&self.sections[10], ProtocolId::StorageBroker, 0)
                .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            let body = ApplyAtomicStorageSnapshotRequest::decode_from_slice(envelope.body())
                .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            let artifacts = envelope.authorization().ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            let signature = decode_signature(artifacts.broker_plan_signature(), DecodeLimits::default())
                .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            let header = body.header.as_option().ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            let template_header = template.header.as_option().ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            if envelope.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                || !envelope.descriptors().is_empty()
                || template.encode_to_vec() != self.sections[9] || body.encode_to_vec() != envelope.body()
                || template_header.request_id.as_slice() != self.request_id
                || header.request_id.as_slice() != self.request_id
                || header.deadline_boottime_nanoseconds != self.deadline
                || template_header.deadline_boottime_nanoseconds != 0
                || body.canonical_plan != self.sections[1] || template.canonical_plan != self.sections[1]
                || body.fence != template.fence || body.header.as_option().map(|h| h.audience) != template.header.as_option().map(|h| h.audience)
                || artifacts.broker_plan() != self.sections[3]
                || signature.statement() != &statement
                || artifacts.ownership_lease() != self.sections[5]
                || artifacts.ownership_lease_signature() != self.sections[6]
            { return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt); }
        }
        if self.stage >= 2 {
            let common = SourceRecord::decode(&self.sections[11])?;
            if common.version != 2 || common.operation != self.operation
                || common.request_id != self.request_id
                || common.operation_record != self.digests[0]
                || common.plan != self.digests[7]
                || common.predecessor != self.digests[8]
                || common.session != self.digests[9]
                || common.checkpoint != self.digests[10]
                || common.completion.is_some() != (self.stage == 3)
            {
                return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
            }
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_BYTES_V3 - 32
            + self.sections.iter().map(Vec::len).sum::<usize>());
        bytes.extend_from_slice(MAGIC_V3);
        bytes.extend_from_slice(&3u16.to_be_bytes());
        bytes.push(self.stage);
        bytes.extend_from_slice(&[0; 5]);
        bytes.extend_from_slice(&self.operation);
        for digest in self.digests { bytes.extend_from_slice(&digest); }
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.clock.host_boot_id());
        bytes.extend_from_slice(&self.clock.provenance().as_bytes());
        bytes.extend_from_slice(&self.clock.wall_seconds().to_be_bytes());
        bytes.extend_from_slice(&self.clock.boottime_nanoseconds().to_be_bytes());
        bytes.extend_from_slice(&self.deadline.to_be_bytes());
        bytes.extend_from_slice(&self.original);
        for section in &self.sections {
            bytes.extend_from_slice(&(section.len() as u64).to_be_bytes());
        }
        for section in &self.sections { bytes.extend_from_slice(section); }
        bytes
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::new().chain_update(DIGEST_DOMAIN_V3).chain_update(self.body()).finalize().into()
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body();
        let digest: [u8; 32] = Sha256::new().chain_update(DIGEST_DOMAIN_V3)
            .chain_update(&bytes).finalize().into();
        bytes.extend_from_slice(&digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, LifecycleAtomicSnapshotSourceErrorV1> {
        if bytes.len() < FIXED_BYTES_V3 { return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt); }
        let mut input = bytes;
        if take::<8>(&mut input)? != *MAGIC_V3 || take::<2>(&mut input)? != 3u16.to_be_bytes() {
            return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt);
        }
        let stage = take::<1>(&mut input)?[0];
        if take::<5>(&mut input)? != [0; 5] { return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt); }
        let operation = take(&mut input)?;
        let mut digests = [[0; 32]; 11];
        for digest in &mut digests { *digest = take(&mut input)?; }
        let request_id = take(&mut input)?;
        let boot = take(&mut input)?;
        let provenance = aos_sandbox_core::RawClockProvenance::new_untrusted(take(&mut input)?)
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let clock = RawPairedClockSample::new_untrusted(provenance, boot,
            i64::from_be_bytes(take(&mut input)?), u64::from_be_bytes(take(&mut input)?))
            .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        let deadline = u64::from_be_bytes(take(&mut input)?);
        let original = take(&mut input)?;
        let mut lengths = [0usize; 12];
        let mut total = FIXED_BYTES_V3;
        for length in &mut lengths {
            *length = usize::try_from(u64::from_be_bytes(take(&mut input)?))
                .map_err(|_| LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
            total = total.checked_add(*length).ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
        }
        if total != bytes.len() { return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt); }
        let mut sections = std::array::from_fn(|_| Vec::new());
        for (section, length) in sections.iter_mut().zip(lengths) {
            *section = input.get(..length).ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?.to_vec();
            input = &input[length..];
        }
        let checksum = take::<32>(&mut input)?;
        let record = Self { stage, operation, digests, request_id, clock, deadline, original, sections };
        record.validate()?;

        // The structural checks preserve the canonical body bytes exactly.
        // Reuse that resident body instead of allocating another serialization.
        let expected: [u8; 32] = Sha256::new().chain_update(DIGEST_DOMAIN_V3)
            .chain_update(&bytes[..bytes.len() - 32]).finalize().into();
        if checksum != expected { return Err(LifecycleAtomicSnapshotSourceErrorV1::Corrupt); }
        Ok(record)
    }

    pub(crate) fn transaction(&self, original: [u8; 32]) -> Result<JournalTransaction, JournalError> {
        let digest = Sha256::new().chain_update(TRANSACTION_DOMAIN_V3)
            .chain_update(original).chain_update(self.operation).chain_update([self.stage])
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        JournalTransaction::new(id, vec![JournalRecord::put(NAMESPACE, self.operation.to_vec(), self.encode())])
            .map_err(JournalError::from)
    }

    pub(crate) fn append(
        &self,
        journal: &mut Journal,
    ) -> Result<crate::journal::CommitResult, LifecycleAtomicSnapshotSourceErrorV1> {
        journal.ensure_protected_authority()?;
        self.validate()?;
        checked_derived_length(journal, &self.sections.each_ref().map(Vec::as_slice))?;
        let prior = journal.get(NAMESPACE, &self.operation);
        if self.stage == 0 {
            if prior.is_some() { return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale); }
        } else {
            let prior = DerivedSourceRecordV3::decode(prior.ok_or(LifecycleAtomicSnapshotSourceErrorV1::Stale)?)?;
            if prior.stage.checked_add(1) != Some(self.stage)
                || prior.operation != self.operation || prior.digests != self.digests
                || prior.clock != self.clock || prior.deadline != self.deadline
                || prior.sections[..9] != self.sections[..9]
                || (self.stage == 1 && prior.digest() != self.original)
                || (self.stage > 1 && (prior.original != self.original
                    || prior.request_id != self.request_id || prior.sections[9..11] != self.sections[9..11]))
            {
                return Err(LifecycleAtomicSnapshotSourceErrorV1::Stale);
            }
        }
        if self.stage == 1 {
            let remaining = LifecycleAtomicSnapshotSourceStoreV1::derived_suffix_v3(
                journal, self, &self.sections[9], &self.sections[10],
            )?;
            journal.preflight_transactions(&remaining)?;
        }
        Ok(journal.commit(&self.transaction(if self.stage == 0 { self.digest() } else { self.original })?)?)
    }
}

fn checked_derived_length(
    journal: &Journal,
    sections: &[&[u8]; 12],
) -> Result<usize, LifecycleAtomicSnapshotSourceErrorV1> {
    let length = sections.iter().try_fold(FIXED_BYTES_V3,
        |total, section| total.checked_add(section.len()))
        .ok_or(LifecycleAtomicSnapshotSourceErrorV1::Corrupt)?;
    if length.checked_add(23).is_none_or(|bytes| bytes > journal.configured_limits().maximum_record_bytes) {
        return Err(JournalError::LimitExceeded("Snapshot original record bytes").into());
    }
    Ok(length)
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
