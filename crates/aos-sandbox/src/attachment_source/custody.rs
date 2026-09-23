//! Stores append-only source-attempt and completion custody.

use std::collections::{BTreeMap, BTreeSet};

use aos_proto::aos::sandbox::local::v1::{
    MountAction, MountLifecycle, MountSourceAcquisitionPhase,
};
use aos_sandbox_core::{ObjectDigest, OperationId, RawPairedClockSample};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, decode_historical_acquire_mount_source_request,
    decode_release_mount_source_acquisition_request,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::dispatch_custody::DispatchRecord;
use super::planning::{
    AttachmentSourceActionV1, AttachmentSourceError, CanonicalPlan, CurrentAttachmentSourcePlanV1,
};
use crate::attachment_state;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const ATTEMPT_NAMESPACE: RecordNamespace = RecordNamespace::AttachmentSourceAttempt;
const COMPLETION_NAMESPACE: RecordNamespace = RecordNamespace::AttachmentSourceCompletion;
const ATTEMPT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.attachment-source-attempt.transaction.v1\0";
const COMPLETION_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.attachment-source-completion.transaction.v1\0";
const MAXIMUM_RECORDS: usize = 65_536;
const MAXIMUM_NAMESPACE_BYTES: usize = 256 * 1024 * 1024;
const PLAN_MAGIC: &[u8; 8] = b"AOSASP01";
const PLAN_VERSION: u16 = 1;
const PLAN_ATTACHMENT_OFFSET: usize = 10;
const PLAN_DESIRED_GENERATION_OFFSET: usize = 26;
const PLAN_DESIRED_DIGEST_OFFSET: usize = 34;
const PLAN_DESIRED_PRESENCE_OFFSET: usize = 66;
const PLAN_SANDBOX_OFFSET: usize = 67;
const PLAN_INCARNATION_OFFSET: usize = 83;
const PLAN_ASSIGNMENT_EPOCH_OFFSET: usize = 99;
const PLAN_ASSIGNMENT_GENERATION_OFFSET: usize = 107;
const PLAN_ASSIGNMENT_DIGEST_OFFSET: usize = 115;
const PLAN_NAMESPACE_GENERATION_OFFSET: usize = 147;
const PLAN_ALLOCATION_DIGEST_OFFSET: usize = 155;
const PLAN_POLICY_IDENTITY_OFFSET: usize = 187;
const PLAN_ATTACHMENT_LEASE_ID_OFFSET: usize = 219;
const PLAN_LEASE_ISSUED_OFFSET: usize = 235;
const PLAN_LEASE_EXPIRES_OFFSET: usize = 243;
const PLAN_VIEW_ID_OFFSET: usize = 251;
const PLAN_VIEW_REVISION_OFFSET: usize = 267;
const PLAN_VIEW_IDENTITY_OFFSET: usize = 275;
const PLAN_BINDING_DIGEST_OFFSET: usize = 307;
const PLAN_TEMPLATE_DIGEST_OFFSET: usize = 339;
const PLAN_LEASE_SECONDS_OFFSET: usize = 371;
const PLAN_MAXIMUM_SUBMOUNTS_OFFSET: usize = 379;
const PLAN_KERNEL_COUPLED_OFFSET: usize = 383;
const PLAN_RESOURCE_SNAPSHOT_DIGEST_OFFSET: usize = 384;
const PLAN_SOURCE_SNAPSHOT_DIGEST_OFFSET: usize = 416;
const PLAN_KERNEL_BOOT_ID_OFFSET: usize = 448;
const PLAN_BROKER_INSTANCE_ID_OFFSET: usize = 464;
const PLAN_JOURNAL_SEQUENCE_OFFSET: usize = 480;
const PLAN_ACQUISITION_PRESENT_OFFSET: usize = 488;
const PLAN_ACQUISITION_ID_OFFSET: usize = 489;
const PLAN_ACQUISITION_REVISION_OFFSET: usize = 521;
const PLAN_ACQUISITION_RECORD_DIGEST_OFFSET: usize = 529;
const PLAN_ACQUISITION_PHASE_OFFSET: usize = 561;
const PLAN_RESOURCE_PRESENT_OFFSET: usize = 562;
const PLAN_RESOURCE_HANDLE_OFFSET: usize = 563;
const PLAN_RESOURCE_REVISION_OFFSET: usize = 595;
const PLAN_RESOURCE_LIFECYCLE_OFFSET: usize = 603;
const PLAN_VERIFICATION_DIGEST_OFFSET: usize = 604;
const PLAN_ACTION_OFFSET: usize = 636;

/// Identifies one source-custody operation in an attachment lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttachmentSourceAttemptKindV1 {
    /// Requests one exact Mount source acquisition.
    Acquire = 1,
    /// Custodies an exact successful detached-create receipt that consumed it.
    Consume = 2,
    /// Requests release after every exact Mount resource has drained.
    Release = 3,
}

impl AttachmentSourceAttemptKindV1 {
    pub(super) fn from_byte(value: u8) -> Result<Self, AttachmentSourceError> {
        match value {
            1 => Ok(Self::Acquire),
            2 => Ok(Self::Consume),
            3 => Ok(Self::Release),
            _ => Err(AttachmentSourceError::CorruptState),
        }
    }
}

/// Reports whether one exact attempt was recorded or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentSourceAttemptOutcomeV1 {
    /// The attempt became durable in this call.
    Recorded,
    /// The exact operation and plan were already durable.
    Replay,
}

/// Reports whether one exact completion was recorded or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentSourceCompletionOutcomeV1 {
    /// The completion became durable in this call.
    Recorded,
    /// The exact completion was already durable.
    Replay,
}

/// Retains a durable, nonauthorizing attachment-source attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAttachmentSourceAttemptV1 {
    pub(super) record: AttemptRecord,
    outcome: AttachmentSourceAttemptOutcomeV1,
}

impl DurableAttachmentSourceAttemptV1 {
    /// Returns whether this call recorded or replayed the attempt.
    #[must_use]
    pub const fn outcome(&self) -> AttachmentSourceAttemptOutcomeV1 {
        self.outcome
    }

    /// Returns the immutable source-custody operation.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        OperationId::from_bytes(self.record.operation_id)
    }

    /// Returns the closed custody milestone.
    #[must_use]
    pub const fn kind(&self) -> AttachmentSourceAttemptKindV1 {
        self.record.kind
    }

    /// Returns the expected acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.acquisition_id)
    }

    /// Returns the exact durable record digest.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns the exact Mount request body, empty only for Consume custody.
    #[must_use]
    pub fn exact_request_body(&self) -> &[u8] {
        &self.record.request_body
    }

    /// Returns the exact request or Mount-completion digest bound at admission.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.request_digest)
    }

    /// Returns the preceding source-custody completion, when one exists.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        match self.record.predecessor {
            Some(value) => Some(ObjectDigest::from_bytes(value)),
            None => None,
        }
    }
}

/// Retains exact evidence that closed one source-custody attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAttachmentSourceCompletionV1 {
    record: CompletionRecord,
    outcome: AttachmentSourceCompletionOutcomeV1,
}

impl DurableAttachmentSourceCompletionV1 {
    /// Returns whether this call recorded or replayed the completion.
    #[must_use]
    pub const fn outcome(&self) -> AttachmentSourceCompletionOutcomeV1 {
        self.outcome
    }

    /// Returns the completed source-custody operation.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        OperationId::from_bytes(self.record.operation_id)
    }

    /// Returns the exact predecessor used by the next attempt.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AttemptRecord {
    pub(super) kind: AttachmentSourceAttemptKindV1,
    pub(super) operation_id: [u8; 16],
    pub(super) request_digest: [u8; 32],
    pub(super) attachment_id: [u8; 16],
    pub(super) desired_generation: u64,
    pub(super) desired_digest: [u8; 32],
    pub(super) acquisition_id: [u8; 32],
    pub(super) predecessor: Option<[u8; 32]>,
    pub(super) mount_completion_digest: Option<[u8; 32]>,
    pub(super) plan_digest: [u8; 32],
    pub(super) request_body: Vec<u8>,
    pub(super) plan_bytes: Vec<u8>,
    pub(super) digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompletionRecord {
    pub(super) kind: AttachmentSourceAttemptKindV1,
    pub(super) operation_id: [u8; 16],
    pub(super) attempt_digest: [u8; 32],
    pub(super) predecessor: Option<[u8; 32]>,
    pub(super) attachment_id: [u8; 16],
    pub(super) desired_generation: u64,
    pub(super) acquisition_id: [u8; 32],
    pub(super) acquisition_revision: u64,
    pub(super) acquisition_record_digest: [u8; 32],
    pub(super) acquisition_phase: MountSourceAcquisitionPhase,
    pub(super) resource_snapshot_digest: [u8; 32],
    pub(super) source_snapshot_digest: [u8; 32],
    pub(super) mount_handle: Option<[u8; 32]>,
    pub(super) resource_revision: Option<u64>,
    pub(super) resource_lifecycle: Option<MountLifecycle>,
    pub(super) mount_completion_digest: Option<[u8; 32]>,
    pub(super) verification_digest: Option<[u8; 32]>,
    pub(super) digest: [u8; 32],
}

pub(super) struct CustodyHistory {
    pub(super) attempts: BTreeMap<[u8; 16], AttemptRecord>,
    completions: BTreeMap<[u8; 16], CompletionRecord>,
    tails: BTreeMap<[u8; 16], ([u8; 16], Option<[u8; 32]>)>,
    retained_bytes: usize,
}

#[derive(Clone, Copy)]
pub(super) struct AcquisitionLineage {
    pub(super) acquisition_id: [u8; 32],
    pub(super) desired_generation: u64,
    pub(super) desired_digest: [u8; 32],
    pub(super) sandbox: [u8; 16],
    pub(super) incarnation: [u8; 16],
    pub(super) assignment_epoch: u64,
    pub(super) assignment_generation: u64,
    pub(super) assignment_digest: [u8; 32],
    pub(super) namespace_generation: u64,
    pub(super) allocation_digest: [u8; 32],
    pub(super) policy_identity: [u8; 32],
    pub(super) binding_digest: [u8; 32],
    pub(super) template_digest: [u8; 32],
    pub(super) lease_seconds: u64,
    pub(super) maximum_submounts: u32,
    pub(super) kernel_coupled: bool,
}

impl CustodyHistory {
    pub(super) fn load(journal: &mut Journal) -> Result<Self, AttachmentSourceError> {
        journal.ensure_protected_authority()?;
        let mut attempts = BTreeMap::new();
        let mut completions = BTreeMap::new();
        let mut retained_bytes = 0usize;

        for (key, value) in journal.records(ATTEMPT_NAMESPACE) {
            retained_bytes = checked_size(retained_bytes, key, value)?;
            let record = AttemptRecord::decode(value)?;
            if key != record.operation_id || attempts.insert(record.operation_id, record).is_some()
            {
                return Err(AttachmentSourceError::CorruptState);
            }
        }
        for (key, value) in journal.records(COMPLETION_NAMESPACE) {
            retained_bytes = checked_size(retained_bytes, key, value)?;
            let record = CompletionRecord::decode(value)?;
            if key != record.operation_id
                || completions.insert(record.operation_id, record).is_some()
            {
                return Err(AttachmentSourceError::CorruptState);
            }
        }
        if attempts.len().saturating_add(completions.len()) > MAXIMUM_RECORDS {
            return Err(AttachmentSourceError::Capacity);
        }
        let mut acquisition_ids = BTreeSet::new();
        if attempts.values().any(|attempt| {
            attempt.kind == AttachmentSourceAttemptKindV1::Acquire
                && !acquisition_ids.insert((attempt.attachment_id, attempt.acquisition_id))
        }) {
            return Err(AttachmentSourceError::CorruptState);
        }

        let mut completion_digests = BTreeMap::new();
        for completion in completions.values() {
            let _validated_attempt = attempts
                .get(&completion.operation_id)
                .filter(|attempt| {
                    attempt.digest == completion.attempt_digest
                        && attempt.kind == completion.kind
                        && attempt.attachment_id == completion.attachment_id
                        && attempt.desired_generation == completion.desired_generation
                        && attempt.acquisition_id == completion.acquisition_id
                        && attempt.predecessor == completion.predecessor
                })
                .ok_or(AttachmentSourceError::CorruptState)?;
            if completion_digests
                .insert(completion.digest, completion)
                .is_some()
            {
                return Err(AttachmentSourceError::CorruptState);
            }
        }

        let mut tails = BTreeMap::new();
        let attachment_ids = attempts
            .values()
            .map(|attempt| attempt.attachment_id)
            .collect::<BTreeSet<_>>();
        for attachment_id in attachment_ids {
            let rows = attempts
                .values()
                .filter(|attempt| attempt.attachment_id == attachment_id)
                .collect::<Vec<_>>();
            let roots = rows
                .iter()
                .filter(|attempt| attempt.predecessor.is_none())
                .collect::<Vec<_>>();
            if roots.len() != 1 {
                return Err(AttachmentSourceError::CorruptState);
            }
            let mut current = roots[0];
            if current.kind != AttachmentSourceAttemptKindV1::Acquire {
                return Err(AttachmentSourceError::CorruptState);
            }
            let mut visited = BTreeSet::new();
            loop {
                if !visited.insert(current.operation_id) {
                    return Err(AttachmentSourceError::CorruptState);
                }
                let completion = completions.get(&current.operation_id);
                let Some(completion) = completion else {
                    tails.insert(attachment_id, (current.operation_id, None));
                    break;
                };
                let successors = rows
                    .iter()
                    .filter(|attempt| attempt.predecessor == Some(completion.digest))
                    .collect::<Vec<_>>();
                match successors.as_slice() {
                    [] => {
                        tails.insert(
                            attachment_id,
                            (current.operation_id, Some(completion.digest)),
                        );
                        break;
                    }
                    [next] if valid_successor(current, completion, next) => current = next,
                    _ => return Err(AttachmentSourceError::CorruptState),
                }
            }
            if visited.len() != rows.len() {
                return Err(AttachmentSourceError::CorruptState);
            }
        }

        let history = Self {
            attempts,
            completions,
            tails,
            retained_bytes,
        };
        history.validate_cross_references(journal)?;
        Ok(history)
    }

    pub(super) fn matches_acquisition(
        &self,
        attachment_id: [u8; 16],
        acquisition_id: [u8; 32],
        operation_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> bool {
        self.attempts.values().any(|attempt| {
            attempt.attachment_id == attachment_id
                && attempt.acquisition_id == acquisition_id
                && attempt.kind == AttachmentSourceAttemptKindV1::Acquire
                && attempt.operation_id == operation_id
                && attempt.request_digest == request_digest
        })
    }

    pub(super) fn matches_release(
        &self,
        attachment_id: [u8; 16],
        acquisition_id: [u8; 32],
        operation_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> bool {
        self.attempts.values().any(|attempt| {
            attempt.attachment_id == attachment_id
                && attempt.acquisition_id == acquisition_id
                && attempt.kind == AttachmentSourceAttemptKindV1::Release
                && attempt.operation_id == operation_id
                && attempt.request_digest == request_digest
        })
    }

    pub(super) fn outstanding_acquisitions(&self, attachment_id: [u8; 16]) -> BTreeSet<[u8; 32]> {
        let closed = self
            .completions
            .values()
            .filter(|completion| {
                completion.attachment_id == attachment_id
                    && (completion.kind == AttachmentSourceAttemptKindV1::Release
                        || completion.is_cancelled_acquire())
            })
            .map(|completion| completion.acquisition_id)
            .collect::<BTreeSet<_>>();
        self.attempts
            .values()
            .filter(|attempt| {
                attempt.attachment_id == attachment_id
                    && attempt.kind == AttachmentSourceAttemptKindV1::Acquire
                    && !closed.contains(&attempt.acquisition_id)
            })
            .map(|attempt| attempt.acquisition_id)
            .collect()
    }

    pub(super) fn was_cancelled(&self, attachment_id: [u8; 16], acquisition_id: [u8; 32]) -> bool {
        self.completions.values().any(|completion| {
            completion.attachment_id == attachment_id
                && completion.acquisition_id == acquisition_id
                && completion.is_cancelled_acquire()
        })
    }

    pub(super) fn open_current_acquire(
        &self,
        attachment_id: [u8; 16],
        desired_generation: u64,
        desired_digest: [u8; 32],
    ) -> Option<[u8; 32]> {
        self.open_attempt(attachment_id)
            .filter(|attempt| {
                attempt.kind == AttachmentSourceAttemptKindV1::Acquire
                    && attempt.desired_generation == desired_generation
                    && attempt.desired_digest == desired_digest
            })
            .map(|attempt| attempt.acquisition_id)
    }

    pub(super) fn open_acquire(&self, attachment_id: [u8; 16]) -> Option<&AttemptRecord> {
        self.open_attempt(attachment_id)
            .filter(|attempt| attempt.kind == AttachmentSourceAttemptKindV1::Acquire)
    }

    pub(super) fn lineage(
        &self,
        attachment_id: [u8; 16],
        acquisition_id: [u8; 32],
    ) -> Result<AcquisitionLineage, AttachmentSourceError> {
        let attempt = self
            .attempts
            .values()
            .find(|attempt| {
                attempt.attachment_id == attachment_id
                    && attempt.acquisition_id == acquisition_id
                    && attempt.kind == AttachmentSourceAttemptKindV1::Acquire
            })
            .ok_or(AttachmentSourceError::CorruptState)?;
        let plan = PlanReferences::decode(&attempt.plan_bytes)?;
        Ok(AcquisitionLineage {
            acquisition_id,
            desired_generation: attempt.desired_generation,
            desired_digest: attempt.desired_digest,
            sandbox: plan.sandbox,
            incarnation: plan.incarnation,
            assignment_epoch: plan.assignment_epoch,
            assignment_generation: plan.assignment_generation,
            assignment_digest: plan.assignment_digest,
            namespace_generation: plan.namespace_generation,
            allocation_digest: plan.allocation_digest,
            policy_identity: plan.policy_identity,
            binding_digest: plan.binding_digest,
            template_digest: plan.template_digest,
            lease_seconds: plan.lease_seconds,
            maximum_submounts: plan.maximum_submounts,
            kernel_coupled: plan.kernel_coupled,
        })
    }

    pub(super) fn has_attempt(
        &self,
        attachment_id: [u8; 16],
        acquisition_id: [u8; 32],
        kind: AttachmentSourceAttemptKindV1,
    ) -> bool {
        self.attempts.values().any(|attempt| {
            attempt.attachment_id == attachment_id
                && attempt.acquisition_id == acquisition_id
                && attempt.kind == kind
        })
    }

    pub(super) fn has_completion(
        &self,
        attachment_id: [u8; 16],
        acquisition_id: [u8; 32],
        kind: AttachmentSourceAttemptKindV1,
    ) -> bool {
        self.completions.values().any(|completion| {
            completion.attachment_id == attachment_id
                && completion.acquisition_id == acquisition_id
                && completion.kind == kind
        })
    }

    pub(super) fn completed_mount_handle(
        &self,
        attachment_id: [u8; 16],
        acquisition_id: [u8; 32],
    ) -> Option<[u8; 32]> {
        self.completions
            .values()
            .find(|completion| {
                completion.attachment_id == attachment_id
                    && completion.acquisition_id == acquisition_id
                    && completion.kind == AttachmentSourceAttemptKindV1::Consume
            })
            .and_then(|completion| completion.mount_handle)
    }

    fn predecessor(
        &self,
        attachment_id: [u8; 16],
    ) -> Result<Option<[u8; 32]>, AttachmentSourceError> {
        match self.tails.get(&attachment_id) {
            None => Ok(None),
            Some((_, Some(completion))) => Ok(Some(*completion)),
            Some((_, None)) => Err(AttachmentSourceError::Conflict),
        }
    }

    pub(super) fn open_attempt(&self, attachment_id: [u8; 16]) -> Option<&AttemptRecord> {
        let (operation, completion) = self.tails.get(&attachment_id)?;
        if completion.is_none() {
            self.attempts.get(operation)
        } else {
            None
        }
    }

    fn validate_cross_references(
        &self,
        journal: &mut Journal,
    ) -> Result<(), AttachmentSourceError> {
        let mut mount_completions = Vec::new();
        for attempt in self.attempts.values() {
            let custody_desired = attachment_state::get_generation(
                journal,
                aos_sandbox_core::AttachmentId::from_bytes(attempt.attachment_id),
                attempt.desired_generation,
            )?
            .ok_or(AttachmentSourceError::CorruptState)?;
            let plan_digest: [u8; 32] = Sha256::new()
                .chain_update(super::planning::PLAN_DOMAIN)
                .chain_update(&attempt.plan_bytes)
                .finalize()
                .into();
            let plan = PlanReferences::decode(&attempt.plan_bytes)?;
            let plan_desired = attachment_state::get_generation(
                journal,
                aos_sandbox_core::AttachmentId::from_bytes(attempt.attachment_id),
                plan.desired_generation,
            )?
            .ok_or(AttachmentSourceError::CorruptState)?;
            let lineage_matches = match attempt.kind {
                AttachmentSourceAttemptKindV1::Acquire => {
                    plan.desired_generation == attempt.desired_generation
                        && plan.desired_digest == attempt.desired_digest
                }
                AttachmentSourceAttemptKindV1::Consume | AttachmentSourceAttemptKindV1::Release => {
                    self.attempts
                        .values()
                        .find(|candidate| {
                            candidate.attachment_id == attempt.attachment_id
                                && candidate.acquisition_id == attempt.acquisition_id
                                && candidate.kind == AttachmentSourceAttemptKindV1::Acquire
                        })
                        .and_then(|origin| PlanReferences::decode(&origin.plan_bytes).ok())
                        .is_some_and(|origin| {
                            attempt.desired_generation == origin.desired_generation
                                && attempt.desired_digest == origin.desired_digest
                                && plan.same_acquisition_contract(origin)
                        })
                }
            };
            if custody_desired.record_digest().as_bytes() != &attempt.desired_digest
                || plan_desired.record_digest().as_bytes() != &plan.desired_digest
                || plan_digest != attempt.plan_digest
                || plan.attachment_id != attempt.attachment_id
                || !lineage_matches
                || !plan.acquisition_matches(attempt)
                || !plan.action_matches(attempt.kind)
            {
                return Err(AttachmentSourceError::CorruptState);
            }
            validate_retained_request(attempt, plan, &mut mount_completions)?;
        }
        if !crate::mount_attempt::contains_completions(journal, &mount_completions)? {
            return Err(AttachmentSourceError::CorruptState);
        }
        Ok(())
    }

    fn ensure_capacity(&self, bytes: usize) -> Result<(), AttachmentSourceError> {
        if self.attempts.len().saturating_add(self.completions.len()) >= MAXIMUM_RECORDS
            || self.retained_bytes.saturating_add(bytes) > MAXIMUM_NAMESPACE_BYTES
        {
            return Err(AttachmentSourceError::Capacity);
        }
        Ok(())
    }

    fn validate_next_attempt(
        &self,
        candidate: &AttemptRecord,
    ) -> Result<(), AttachmentSourceError> {
        match candidate.predecessor {
            None if candidate.kind == AttachmentSourceAttemptKindV1::Acquire => Ok(()),
            Some(predecessor) => {
                let completion = self
                    .completions
                    .values()
                    .find(|completion| completion.digest == predecessor)
                    .ok_or(AttachmentSourceError::Conflict)?;
                let current = self
                    .attempts
                    .get(&completion.operation_id)
                    .ok_or(AttachmentSourceError::CorruptState)?;
                if completion.attachment_id == candidate.attachment_id
                    && valid_successor(current, completion, candidate)
                {
                    Ok(())
                } else {
                    Err(AttachmentSourceError::Conflict)
                }
            }
            _ => Err(AttachmentSourceError::Conflict),
        }
    }
}

fn valid_successor(
    current: &AttemptRecord,
    completion: &CompletionRecord,
    next: &AttemptRecord,
) -> bool {
    if completion.is_cancelled_acquire() {
        return next.kind == AttachmentSourceAttemptKindV1::Acquire
            && current.acquisition_id != next.acquisition_id;
    }
    match (current.kind, next.kind) {
        (AttachmentSourceAttemptKindV1::Acquire, AttachmentSourceAttemptKindV1::Consume) => {
            let consumable = match completion.acquisition_phase {
                MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE => {
                    completion.mount_handle.is_none()
                }
                MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED => {
                    completion.mount_handle.is_some()
                }
                _ => false,
            };
            consumable
                && current.acquisition_id == next.acquisition_id
                && current.desired_generation == next.desired_generation
                && current.desired_digest == next.desired_digest
        }
        (AttachmentSourceAttemptKindV1::Acquire, AttachmentSourceAttemptKindV1::Release) => {
            matches!(
            completion.acquisition_phase,
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
        ) && completion.mount_handle.is_none()
                && current.acquisition_id == next.acquisition_id
                && current.desired_generation == next.desired_generation
                && current.desired_digest == next.desired_digest
        }
        (AttachmentSourceAttemptKindV1::Consume, AttachmentSourceAttemptKindV1::Release) => {
            current.acquisition_id == next.acquisition_id
                && current.desired_generation == next.desired_generation
                && current.desired_digest == next.desired_digest
        }
        (AttachmentSourceAttemptKindV1::Release, AttachmentSourceAttemptKindV1::Acquire) => {
            current.acquisition_id != next.acquisition_id
        }
        _ => false,
    }
}

impl CompletionRecord {
    fn is_cancelled_acquire(&self) -> bool {
        self.kind == AttachmentSourceAttemptKindV1::Acquire
            && self.acquisition_revision == 0
            && self.acquisition_record_digest == [0; 32]
            && self.acquisition_phase
                == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlanReferences {
    attachment_id: [u8; 16],
    desired_generation: u64,
    desired_digest: [u8; 32],
    desired_presence: u8,
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    assignment_epoch: u64,
    assignment_generation: u64,
    assignment_digest: [u8; 32],
    namespace_generation: u64,
    allocation_digest: [u8; 32],
    policy_identity: [u8; 32],
    attachment_lease_id: [u8; 16],
    lease_issued: i64,
    lease_expires: i64,
    view_id: [u8; 16],
    view_revision: u64,
    view_identity: [u8; 32],
    binding_digest: [u8; 32],
    template_digest: [u8; 32],
    lease_seconds: u64,
    maximum_submounts: u32,
    kernel_coupled: bool,
    resource_snapshot_digest: [u8; 32],
    source_snapshot_digest: [u8; 32],
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    journal_sequence: u64,
    acquisition_id: Option<[u8; 32]>,
    acquisition_revision: Option<u64>,
    acquisition_record_digest: Option<[u8; 32]>,
    acquisition_phase: Option<MountSourceAcquisitionPhase>,
    verification_digest: Option<[u8; 32]>,
    mount_handle: Option<[u8; 32]>,
    resource_revision: Option<u64>,
    resource_lifecycle: Option<MountLifecycle>,
    action: u8,
}

impl PlanReferences {
    fn decode(bytes: &[u8]) -> Result<Self, AttachmentSourceError> {
        if bytes.len() != super::format::PLAN_BYTES
            || field::<8>(bytes, 0)? != *PLAN_MAGIC
            || u16::from_be_bytes(field(bytes, 8)?) != PLAN_VERSION
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        let (acquisition_id, acquisition_revision, acquisition_record_digest, acquisition_phase) =
            match bytes
                .get(PLAN_ACQUISITION_PRESENT_OFFSET)
                .copied()
                .ok_or(AttachmentSourceError::CorruptState)?
            {
                0 if field::<32>(bytes, PLAN_ACQUISITION_ID_OFFSET)? == [0; 32]
                    && field::<8>(bytes, PLAN_ACQUISITION_REVISION_OFFSET)? == [0; 8]
                    && field::<32>(bytes, PLAN_ACQUISITION_RECORD_DIGEST_OFFSET)? == [0; 32]
                    && bytes.get(PLAN_ACQUISITION_PHASE_OFFSET) == Some(&0) =>
                {
                    (None, None, None, None)
                }
                1 => {
                    let acquisition_id = field(bytes, PLAN_ACQUISITION_ID_OFFSET)?;
                    let revision =
                        u64::from_be_bytes(field(bytes, PLAN_ACQUISITION_REVISION_OFFSET)?);
                    let record_digest = field(bytes, PLAN_ACQUISITION_RECORD_DIGEST_OFFSET)?;
                    let phase = *bytes
                        .get(PLAN_ACQUISITION_PHASE_OFFSET)
                        .ok_or(AttachmentSourceError::CorruptState)?;
                    let pending = revision == 0 && record_digest == [0; 32] && phase == 0;
                    let observed = revision != 0 && record_digest != [0; 32] && phase != 0;
                    if acquisition_id == [0; 32] || !(pending || observed) {
                        return Err(AttachmentSourceError::CorruptState);
                    }
                    let phase = acquisition_phase(phase)?;
                    (
                        Some(acquisition_id),
                        (revision != 0).then_some(revision),
                        (record_digest != [0; 32]).then_some(record_digest),
                        Some(phase),
                    )
                }
                _ => return Err(AttachmentSourceError::CorruptState),
            };
        let kernel_coupled = match bytes
            .get(PLAN_KERNEL_COUPLED_OFFSET)
            .copied()
            .ok_or(AttachmentSourceError::CorruptState)?
        {
            0 => false,
            1 => true,
            _ => return Err(AttachmentSourceError::CorruptState),
        };
        let verification_digest = field(bytes, PLAN_VERIFICATION_DIGEST_OFFSET)?;
        let verification_digest = (verification_digest != [0; 32]).then_some(verification_digest);
        let (mount_handle, resource_revision, resource_lifecycle) = match bytes
            .get(PLAN_RESOURCE_PRESENT_OFFSET)
            .copied()
            .ok_or(AttachmentSourceError::CorruptState)?
        {
            0 if field::<41>(bytes, PLAN_RESOURCE_HANDLE_OFFSET)? == [0; 41] => (None, None, None),
            1 if field::<32>(bytes, PLAN_RESOURCE_HANDLE_OFFSET)? != [0; 32]
                && field::<8>(bytes, PLAN_RESOURCE_REVISION_OFFSET)? != [0; 8]
                && bytes
                    .get(PLAN_RESOURCE_LIFECYCLE_OFFSET)
                    .is_some_and(|value| *value != 0) =>
            {
                (
                    Some(field(bytes, PLAN_RESOURCE_HANDLE_OFFSET)?),
                    Some(u64::from_be_bytes(field(
                        bytes,
                        PLAN_RESOURCE_REVISION_OFFSET,
                    )?)),
                    Some(resource_lifecycle(bytes[PLAN_RESOURCE_LIFECYCLE_OFFSET])?),
                )
            }
            _ => return Err(AttachmentSourceError::CorruptState),
        };
        let decoded = Self {
            attachment_id: field(bytes, PLAN_ATTACHMENT_OFFSET)?,
            desired_generation: u64::from_be_bytes(field(bytes, PLAN_DESIRED_GENERATION_OFFSET)?),
            desired_digest: field(bytes, PLAN_DESIRED_DIGEST_OFFSET)?,
            desired_presence: bytes[PLAN_DESIRED_PRESENCE_OFFSET],
            sandbox: field(bytes, PLAN_SANDBOX_OFFSET)?,
            incarnation: field(bytes, PLAN_INCARNATION_OFFSET)?,
            assignment_epoch: u64::from_be_bytes(field(bytes, PLAN_ASSIGNMENT_EPOCH_OFFSET)?),
            assignment_generation: u64::from_be_bytes(field(
                bytes,
                PLAN_ASSIGNMENT_GENERATION_OFFSET,
            )?),
            assignment_digest: field(bytes, PLAN_ASSIGNMENT_DIGEST_OFFSET)?,
            namespace_generation: u64::from_be_bytes(field(
                bytes,
                PLAN_NAMESPACE_GENERATION_OFFSET,
            )?),
            allocation_digest: field(bytes, PLAN_ALLOCATION_DIGEST_OFFSET)?,
            policy_identity: field(bytes, PLAN_POLICY_IDENTITY_OFFSET)?,
            attachment_lease_id: field(bytes, PLAN_ATTACHMENT_LEASE_ID_OFFSET)?,
            lease_issued: i64::from_be_bytes(field(bytes, PLAN_LEASE_ISSUED_OFFSET)?),
            lease_expires: i64::from_be_bytes(field(bytes, PLAN_LEASE_EXPIRES_OFFSET)?),
            view_id: field(bytes, PLAN_VIEW_ID_OFFSET)?,
            view_revision: u64::from_be_bytes(field(bytes, PLAN_VIEW_REVISION_OFFSET)?),
            view_identity: field(bytes, PLAN_VIEW_IDENTITY_OFFSET)?,
            binding_digest: field(bytes, PLAN_BINDING_DIGEST_OFFSET)?,
            template_digest: field(bytes, PLAN_TEMPLATE_DIGEST_OFFSET)?,
            lease_seconds: u64::from_be_bytes(field(bytes, PLAN_LEASE_SECONDS_OFFSET)?),
            maximum_submounts: u32::from_be_bytes(field(bytes, PLAN_MAXIMUM_SUBMOUNTS_OFFSET)?),
            kernel_coupled,
            resource_snapshot_digest: field(bytes, PLAN_RESOURCE_SNAPSHOT_DIGEST_OFFSET)?,
            source_snapshot_digest: field(bytes, PLAN_SOURCE_SNAPSHOT_DIGEST_OFFSET)?,
            kernel_boot_id: field(bytes, PLAN_KERNEL_BOOT_ID_OFFSET)?,
            broker_instance_id: field(bytes, PLAN_BROKER_INSTANCE_ID_OFFSET)?,
            journal_sequence: u64::from_be_bytes(field(bytes, PLAN_JOURNAL_SEQUENCE_OFFSET)?),
            acquisition_id,
            acquisition_revision,
            acquisition_record_digest,
            acquisition_phase,
            verification_digest,
            mount_handle,
            resource_revision,
            resource_lifecycle,
            action: *bytes
                .get(PLAN_ACTION_OFFSET)
                .ok_or(AttachmentSourceError::CorruptState)?,
        };
        if !decoded.sentinels_are_valid()
            || !decoded.action_shape_is_valid()
            || decoded.encode() != bytes
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        Ok(decoded)
    }

    fn sentinels_are_valid(self) -> bool {
        self.attachment_id != [0; 16]
            && self.desired_generation != 0
            && self.desired_digest != [0; 32]
            && matches!(self.desired_presence, 1 | 2)
            && self.sandbox != [0; 16]
            && self.incarnation != [0; 16]
            && self.assignment_epoch != 0
            && self.assignment_generation != 0
            && self.assignment_digest != [0; 32]
            && self.namespace_generation != 0
            && self.allocation_digest != [0; 32]
            && self.policy_identity != [0; 32]
            && self.attachment_lease_id != [0; 16]
            && self.lease_expires > self.lease_issued
            && self.view_id != [0; 16]
            && self.view_revision != 0
            && self.view_identity != [0; 32]
            && self.binding_digest != [0; 32]
            && self.template_digest != [0; 32]
            && self.lease_seconds != 0
            && self.lease_seconds
                <= aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_LEASE_SECONDS
            && self.maximum_submounts
                <= aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_SUBMOUNTS
            && self.resource_snapshot_digest != [0; 32]
            && self.source_snapshot_digest != [0; 32]
            && self.kernel_boot_id != [0; 16]
            && self.broker_instance_id != [0; 16]
            && self.journal_sequence != 0
    }

    fn action_shape_is_valid(self) -> bool {
        let no_acquisition = self.acquisition_id.is_none();
        let pending = self.acquisition_id.is_some()
            && self.acquisition_revision.is_none()
            && self.acquisition_record_digest.is_none()
            && self.acquisition_phase
                == Some(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED);
        let observed = self.acquisition_id.is_some()
            && self.acquisition_revision.is_some()
            && self.acquisition_record_digest.is_some();
        let no_resource = self.mount_handle.is_none();
        let installed = self.resource_lifecycle == Some(MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        let released = self.resource_lifecycle == Some(MountLifecycle::MOUNT_LIFECYCLE_RELEASED);
        match self.action {
            1 | 2 | 13 => no_acquisition && no_resource && self.verification_digest.is_none(),
            3 => {
                self.acquisition_id.is_some()
                    && no_resource
                    && self.verification_digest.is_none()
                    && (pending
                        || matches!(
                            self.acquisition_phase,
                            Some(
                                MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
                                    | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
                            )
                        ))
            }
            4 | 5 => {
                observed
                    && self.acquisition_phase
                        == Some(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE)
                    && no_resource
                    && self.verification_digest.is_none()
            }
            6 => {
                observed
                    && matches!(
                        self.acquisition_phase,
                        Some(
                            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                        )
                    )
                    && !no_resource
                    && self.verification_digest.is_none()
            }
            7 => {
                observed
                    && ((self.acquisition_phase
                        == Some(
                            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED,
                        ) && installed
                        && self.verification_digest.is_some())
                        || (matches!(
                            self.acquisition_phase,
                            Some(
                                MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                                    | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                            )
                        ) && released
                            && self.verification_digest.is_none()))
            }
            8 => {
                observed
                    && self.acquisition_phase
                        == Some(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED)
                    && installed
                    && self.verification_digest.is_some()
            }
            9 => {
                observed
                    && matches!(
                        self.acquisition_phase,
                        Some(
                            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                        )
                    )
                    && !no_resource
                    && !released
                    && self.verification_digest.is_none()
            }
            10 => {
                observed
                    && matches!(
                        self.acquisition_phase,
                        Some(
                            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                        )
                    )
                    && (no_resource || released)
                    && self.verification_digest.is_none()
            }
            11 => {
                observed
                    && matches!(
                        self.acquisition_phase,
                        Some(
                            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                        )
                    )
                    && (no_resource || released)
                    && self.verification_digest.is_none()
            }
            12 => {
                observed
                    && self.acquisition_phase
                        == Some(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED)
                    && (no_resource || released)
                    && self.verification_digest.is_none()
            }
            14 => pending && no_resource && self.verification_digest.is_none(),
            _ => false,
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(super::format::PLAN_BYTES);
        bytes.extend_from_slice(PLAN_MAGIC);
        bytes.extend_from_slice(&PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.attachment_id);
        bytes.extend_from_slice(&self.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.desired_digest);
        bytes.push(self.desired_presence);
        bytes.extend_from_slice(&self.sandbox);
        bytes.extend_from_slice(&self.incarnation);
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_generation.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_digest);
        bytes.extend_from_slice(&self.namespace_generation.to_be_bytes());
        bytes.extend_from_slice(&self.allocation_digest);
        bytes.extend_from_slice(&self.policy_identity);
        bytes.extend_from_slice(&self.attachment_lease_id);
        bytes.extend_from_slice(&self.lease_issued.to_be_bytes());
        bytes.extend_from_slice(&self.lease_expires.to_be_bytes());
        bytes.extend_from_slice(&self.view_id);
        bytes.extend_from_slice(&self.view_revision.to_be_bytes());
        bytes.extend_from_slice(&self.view_identity);
        bytes.extend_from_slice(&self.binding_digest);
        bytes.extend_from_slice(&self.template_digest);
        bytes.extend_from_slice(&self.lease_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_submounts.to_be_bytes());
        bytes.push(u8::from(self.kernel_coupled));
        bytes.extend_from_slice(&self.resource_snapshot_digest);
        bytes.extend_from_slice(&self.source_snapshot_digest);
        bytes.extend_from_slice(&self.kernel_boot_id);
        bytes.extend_from_slice(&self.broker_instance_id);
        bytes.extend_from_slice(&self.journal_sequence.to_be_bytes());
        match self.acquisition_id {
            Some(acquisition_id) => {
                bytes.push(1);
                bytes.extend_from_slice(&acquisition_id);
                bytes.extend_from_slice(&self.acquisition_revision.unwrap_or(0).to_be_bytes());
                bytes.extend_from_slice(&self.acquisition_record_digest.unwrap_or([0; 32]));
                bytes.push(self.acquisition_phase.map_or(0, |phase| phase as i32 as u8));
            }
            None => bytes.extend_from_slice(&[0; 74]),
        }
        match self.mount_handle {
            Some(mount_handle) => {
                bytes.push(1);
                bytes.extend_from_slice(&mount_handle);
                bytes.extend_from_slice(&self.resource_revision.unwrap_or(0).to_be_bytes());
                bytes.push(
                    self.resource_lifecycle
                        .map_or(0, |phase| phase as i32 as u8),
                );
            }
            None => bytes.extend_from_slice(&[0; 42]),
        }
        bytes.extend_from_slice(&self.verification_digest.unwrap_or([0; 32]));
        bytes.push(self.action);
        bytes
    }

    fn action_matches(self, kind: AttachmentSourceAttemptKindV1) -> bool {
        match kind {
            AttachmentSourceAttemptKindV1::Acquire => {
                self.action == 2
                    && self.acquisition_revision.is_none()
                    && self.acquisition_record_digest.is_none()
                    && self.verification_digest.is_none()
                    && self.mount_handle.is_none()
            }
            AttachmentSourceAttemptKindV1::Consume => match self.action {
                6 | 7 => {
                    self.acquisition_revision.is_some()
                        && self.acquisition_record_digest.is_some()
                        && self.mount_handle.is_some()
                }
                _ => false,
            },
            AttachmentSourceAttemptKindV1::Release => {
                self.action == 10
                    && self.acquisition_revision.is_some()
                    && self.acquisition_record_digest.is_some()
                    && self.verification_digest.is_none()
            }
        }
    }

    fn acquisition_matches(self, attempt: &AttemptRecord) -> bool {
        match attempt.kind {
            AttachmentSourceAttemptKindV1::Acquire => self.acquisition_id.is_none(),
            AttachmentSourceAttemptKindV1::Consume | AttachmentSourceAttemptKindV1::Release => {
                self.acquisition_id == Some(attempt.acquisition_id)
            }
        }
    }

    fn same_acquisition_contract(self, origin: Self) -> bool {
        self.attachment_id == origin.attachment_id
            && self.binding_digest == origin.binding_digest
            && self.template_digest == origin.template_digest
            && self.lease_seconds == origin.lease_seconds
            && self.maximum_submounts == origin.maximum_submounts
            && self.kernel_coupled == origin.kernel_coupled
    }
}

fn acquisition_phase(value: u8) -> Result<MountSourceAcquisitionPhase, AttachmentSourceError> {
    match value {
        0 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED),
        1 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY),
        2 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED),
        3 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE),
        4 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED),
        5 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING),
        6 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED),
        7 => Ok(MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED),
        _ => Err(AttachmentSourceError::CorruptState),
    }
}

fn resource_lifecycle(value: u8) -> Result<MountLifecycle, AttachmentSourceError> {
    match value {
        1 => Ok(MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED),
        2 => Ok(MountLifecycle::MOUNT_LIFECYCLE_PREPARED),
        3 => Ok(MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING),
        4 => Ok(MountLifecycle::MOUNT_LIFECYCLE_INSTALLED),
        5 => Ok(MountLifecycle::MOUNT_LIFECYCLE_DRAINING),
        6 => Ok(MountLifecycle::MOUNT_LIFECYCLE_RELEASED),
        7 => Ok(MountLifecycle::MOUNT_LIFECYCLE_FAULTED),
        8 => Ok(MountLifecycle::MOUNT_LIFECYCLE_DETACHING),
        9 => Ok(MountLifecycle::MOUNT_LIFECYCLE_RELEASING),
        _ => Err(AttachmentSourceError::CorruptState),
    }
}

fn validate_retained_request(
    attempt: &AttemptRecord,
    plan: PlanReferences,
    mount_completions: &mut Vec<([u8; 16], [u8; 32], [u8; 32], [u8; 32])>,
) -> Result<(), AttachmentSourceError> {
    match attempt.kind {
        AttachmentSourceAttemptKindV1::Acquire => {
            let request = decode_historical_acquire_mount_source_request(&attempt.request_body)
                .map_err(|_| AttachmentSourceError::CorruptState)?;
            if request.header().request_id() != &attempt.operation_id
                || request.request_digest().as_bytes() != &attempt.request_digest
                || request.acquisition_id().as_bytes() != &attempt.acquisition_id
                || request.source_binding().digest().as_bytes() != &plan.binding_digest
                || request.prospective_mount_template_digest().as_bytes() != &plan.template_digest
                || request.requested_lease_seconds() != plan.lease_seconds
                || request.requested_maximum_submounts() != plan.maximum_submounts
                || request.kernel_coupled() != plan.kernel_coupled
                || !fence_matches_references(request.fence(), plan)
            {
                return Err(AttachmentSourceError::CorruptState);
            }
        }
        AttachmentSourceAttemptKindV1::Consume => {
            let digest = attempt
                .mount_completion_digest
                .ok_or(AttachmentSourceError::CorruptState)?;
            if attempt.request_digest != digest {
                return Err(AttachmentSourceError::CorruptState);
            }
            mount_completions.push((
                attempt.operation_id,
                digest,
                plan.mount_handle
                    .ok_or(AttachmentSourceError::CorruptState)?,
                plan.binding_digest,
            ));
        }
        AttachmentSourceAttemptKindV1::Release => {
            let request = decode_live_release(&attempt.request_body)
                .map_err(|_| AttachmentSourceError::CorruptState)?;
            if request.header().request_id() != &attempt.operation_id
                || request.request_digest().as_bytes() != &attempt.request_digest
                || request.acquisition_id().as_bytes() != &attempt.acquisition_id
                || request.expected_revision() != plan.acquisition_revision.unwrap_or(0)
                || request.expected_record_digest().as_bytes()
                    != &plan.acquisition_record_digest.unwrap_or([0; 32])
                || !fence_matches_references(request.fence(), plan)
            {
                return Err(AttachmentSourceError::CorruptState);
            }
        }
    }
    Ok(())
}

fn fence_matches_references(
    fence: &aos_sandbox_protocol::ValidatedAssignmentFence,
    plan: PlanReferences,
) -> bool {
    fence.sandbox_id() == &plan.sandbox
        && fence.incarnation_id() == &plan.incarnation
        && fence.assignment_epoch() == plan.assignment_epoch
        && fence.desired_generation() == plan.assignment_generation
        && fence.assignment_digest() == &plan.assignment_digest
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], AttachmentSourceError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .ok_or(AttachmentSourceError::CorruptState)?
        .try_into()
        .map_err(|_| AttachmentSourceError::CorruptState)
}

/// Durably records one exact source-custody attempt without dispatching it.
///
/// Acquire and Release retain the exact canonical Mount body. Consume instead
/// retains the already durable successful detached-create completion digest;
/// this makes crash recovery independent of a live receipt token.
///
/// # Errors
///
/// Rejects a stale plan, wrong action/body pairing, noncanonical Mount body,
/// an open predecessor, changed idempotency input, or capacity/durability loss.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_current_attempt<T>(
    journal: &mut Journal,
    plan: CurrentAttachmentSourcePlanV1,
    kind: AttachmentSourceAttemptKindV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    exact_request_body: Vec<u8>,
    mount_completion: Option<&crate::CompletedCurrentAttachmentMountAttemptV1>,
    expected_predecessor: Option<ObjectDigest>,
    clock: &mut T,
) -> Result<DurableAttachmentSourceAttemptV1, AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    record_current_attempt_with_dispatch(
        journal,
        &plan,
        kind,
        operation_id,
        request_digest,
        exact_request_body,
        mount_completion,
        expected_predecessor,
        None,
        clock,
    )
    .map(|(attempt, _)| attempt)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_current_attempt_with_dispatch<T>(
    journal: &mut Journal,
    plan: &CurrentAttachmentSourcePlanV1,
    kind: AttachmentSourceAttemptKindV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    exact_request_body: Vec<u8>,
    mount_completion: Option<&crate::CompletedCurrentAttachmentMountAttemptV1>,
    expected_predecessor: Option<ObjectDigest>,
    packet: Option<Vec<u8>>,
    clock: &mut T,
) -> Result<(DurableAttachmentSourceAttemptV1, Option<DispatchRecord>), AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if packet.is_some() && kind != AttachmentSourceAttemptKindV1::Acquire {
        return Err(AttachmentSourceError::Conflict);
    }
    let history = CustodyHistory::load(journal)?;
    let replay = history.attempts.contains_key(operation_id.as_bytes());
    if !replay {
        plan.recheck(journal, clock)?;
    }
    let predecessor = match history.attempts.get(operation_id.as_bytes()) {
        Some(existing) => existing.predecessor,
        None => history.predecessor(plan.plan.attachment_id)?,
    };
    if predecessor != expected_predecessor.map(|value| *value.as_bytes()) {
        return Err(AttachmentSourceError::Conflict);
    }
    let (acquisition_id, mount_completion_digest) = validate_attempt_input(
        &plan,
        kind,
        operation_id,
        request_digest,
        &exact_request_body,
        mount_completion,
    )?;
    let mut record = AttemptRecord {
        kind,
        operation_id: *operation_id.as_bytes(),
        request_digest: *request_digest.as_bytes(),
        attachment_id: plan.plan.attachment_id,
        desired_generation: plan.plan.custody_desired_generation,
        desired_digest: plan.plan.custody_desired_digest,
        acquisition_id,
        predecessor,
        mount_completion_digest,
        plan_digest: plan.plan.digest,
        request_body: exact_request_body,
        plan_bytes: plan.plan.bytes.clone(),
        digest: [0; 32],
    };
    record.digest = record.compute_digest();
    record.validate()?;
    PlanReferences::decode(&record.plan_bytes)?;
    let dispatch = packet
        .map(|packet| DispatchRecord::new(&record, packet))
        .transpose()?;

    let outcome = match history.attempts.get(&record.operation_id) {
        Some(current) if current == &record => {
            if dispatch.as_ref() != super::dispatch_custody::current(journal, &record)?.as_ref() {
                return Err(AttachmentSourceError::Conflict);
            }
            AttachmentSourceAttemptOutcomeV1::Replay
        }
        Some(_) => return Err(AttachmentSourceError::Conflict),
        None => {
            history.validate_next_attempt(&record)?;
            let added = record.encoded_len().saturating_add(16).saturating_add(
                dispatch
                    .as_ref()
                    .map_or(0, |value| value.encoded_len() + 16),
            );
            history.ensure_capacity(added)?;
            plan.recheck(journal, clock)?;
            let transaction = match dispatch.as_ref() {
                Some(dispatch) => record.transaction_with_dispatch(dispatch)?,
                None => record.transaction()?,
            };
            journal.commit(&transaction)?;
            AttachmentSourceAttemptOutcomeV1::Recorded
        }
    };
    let committed = CustodyHistory::load(journal)?;
    if committed.attempts.get(&record.operation_id) != Some(&record) {
        return Err(AttachmentSourceError::CorruptState);
    }
    if dispatch.as_ref() != super::dispatch_custody::current(journal, &record)?.as_ref() {
        return Err(AttachmentSourceError::CorruptState);
    }
    Ok((
        DurableAttachmentSourceAttemptV1 { record, outcome },
        dispatch,
    ))
}

pub(crate) fn current_predecessor(
    journal: &mut Journal,
    attachment_id: [u8; 16],
) -> Result<Option<ObjectDigest>, AttachmentSourceError> {
    CustodyHistory::load(journal)?
        .predecessor(attachment_id)
        .map(|value| value.map(ObjectDigest::from_bytes))
}

/// Records exact current evidence completing or canceling one custody attempt.
///
/// # Errors
///
/// Rejects stale or substituted attempts, an acquisition that has not reached
/// the required milestone, a source row for cancellation, missing exact
/// post-attach evidence for Consume, or a nonterminal Release observation.
pub(crate) fn record_completion<T>(
    journal: &mut Journal,
    attempt: DurableAttachmentSourceAttemptV1,
    plan: CurrentAttachmentSourcePlanV1,
    clock: &mut T,
) -> Result<DurableAttachmentSourceCompletionV1, AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let history = CustodyHistory::load(journal)?;
    if history.attempts.get(&attempt.record.operation_id) != Some(&attempt.record) {
        return Err(AttachmentSourceError::Conflict);
    }
    if let Some(current) = history.completions.get(&attempt.record.operation_id) {
        return Ok(DurableAttachmentSourceCompletionV1 {
            record: current.clone(),
            outcome: AttachmentSourceCompletionOutcomeV1::Replay,
        });
    }
    plan.recheck(journal, clock)?;
    if attempt.record.attachment_id != plan.plan.attachment_id
        || attempt.record.desired_generation != plan.plan.custody_desired_generation
        || attempt.record.desired_digest != plan.plan.custody_desired_digest
    {
        return Err(AttachmentSourceError::Conflict);
    }
    if attempt.record.acquisition_id != plan.plan.acquisition_id.unwrap_or([0; 32]) {
        return Err(AttachmentSourceError::Conflict);
    }
    validate_completion_action(&attempt.record, &plan)?;
    let cancellation = matches!(plan.action, AttachmentSourceActionV1::CancelAcquire { .. });
    let mut record = CompletionRecord {
        kind: attempt.record.kind,
        operation_id: attempt.record.operation_id,
        attempt_digest: attempt.record.digest,
        predecessor: attempt.record.predecessor,
        attachment_id: attempt.record.attachment_id,
        desired_generation: attempt.record.desired_generation,
        acquisition_id: attempt.record.acquisition_id,
        acquisition_revision: if cancellation {
            0
        } else {
            plan.plan
                .acquisition_revision
                .ok_or(AttachmentSourceError::Conflict)?
        },
        acquisition_record_digest: if cancellation {
            [0; 32]
        } else {
            plan.plan
                .acquisition_record_digest
                .ok_or(AttachmentSourceError::Conflict)?
        },
        acquisition_phase: if cancellation {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED
        } else {
            plan.plan
                .acquisition_phase
                .ok_or(AttachmentSourceError::Conflict)?
        },
        resource_snapshot_digest: plan.plan.resource_snapshot_digest,
        source_snapshot_digest: plan.plan.source_snapshot_digest,
        mount_handle: plan.plan.mount_handle,
        resource_revision: plan.plan.resource_revision,
        resource_lifecycle: plan.plan.resource_lifecycle,
        mount_completion_digest: attempt.record.mount_completion_digest,
        verification_digest: (attempt.record.kind == AttachmentSourceAttemptKindV1::Consume)
            .then_some(plan.plan.verification_digest)
            .flatten(),
        digest: [0; 32],
    };
    record.digest = record.compute_digest();
    record.validate()?;
    let outcome = match history.completions.get(&record.operation_id) {
        Some(current) if current == &record => AttachmentSourceCompletionOutcomeV1::Replay,
        Some(_) => return Err(AttachmentSourceError::Conflict),
        None => {
            history.ensure_capacity(record.encoded_len().saturating_add(16))?;
            plan.recheck(journal, clock)?;
            journal.commit(&record.transaction()?)?;
            AttachmentSourceCompletionOutcomeV1::Recorded
        }
    };
    let committed = CustodyHistory::load(journal)?;
    if committed.completions.get(&record.operation_id) != Some(&record) {
        return Err(AttachmentSourceError::CorruptState);
    }
    Ok(DurableAttachmentSourceCompletionV1 { record, outcome })
}

fn validate_attempt_input(
    plan: &CurrentAttachmentSourcePlanV1,
    kind: AttachmentSourceAttemptKindV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    body: &[u8],
    mount_completion: Option<&crate::CompletedCurrentAttachmentMountAttemptV1>,
) -> Result<([u8; 32], Option<[u8; 32]>), AttachmentSourceError> {
    if operation_id.as_bytes() == &[0; 16] || request_digest.as_bytes() == &[0; 32] {
        return Err(AttachmentSourceError::Conflict);
    }
    match (kind, plan.action) {
        (AttachmentSourceAttemptKindV1::Acquire, AttachmentSourceActionV1::Acquire) => {
            let request = decode_historical_acquire_mount_source_request(body)
                .map_err(|_| AttachmentSourceError::Protocol)?;
            if request.header().request_id() != operation_id.as_bytes()
                || request.request_digest() != request_digest
                || request.prospective_mount_template_digest().as_bytes()
                    != &plan.plan.template_digest
                || request.source_binding().digest().as_bytes() != &plan.plan.source_binding_digest
                || request.requested_lease_seconds() != plan.plan.bounds.lease_seconds()
                || request.requested_maximum_submounts() != plan.plan.bounds.maximum_submounts()
                || request.kernel_coupled() != plan.plan.bounds.kernel_coupled()
                || !fence_matches_plan(request.fence(), &plan.plan)
                || mount_completion.is_some()
            {
                return Err(AttachmentSourceError::Conflict);
            }
            Ok((*request.acquisition_id().as_bytes(), None))
        }
        (
            AttachmentSourceAttemptKindV1::Consume,
            AttachmentSourceActionV1::AwaitAttachment { acquisition_id, .. }
            | AttachmentSourceActionV1::CompleteConsume { acquisition_id, .. },
        ) => {
            let completion = mount_completion.ok_or(AttachmentSourceError::Conflict)?;
            let result = completion.completion().result();
            if !body.is_empty()
                || completion.mount_action() != MountAction::MOUNT_ACTION_CREATE_DETACHED
                || completion.desired().record_digest().as_bytes()
                    != &plan.plan.custody_desired_digest
                || completion.completion().request_id() != *operation_id.as_bytes()
                || completion.completion().record_digest() != request_digest
                || result.detached_mount_handle() != plan.plan.mount_handle.as_ref()
                || result.source_binding().is_none_or(|binding| {
                    binding.digest().as_bytes() != &plan.plan.source_binding_digest
                })
            {
                return Err(AttachmentSourceError::Conflict);
            }
            Ok((acquisition_id, Some(*request_digest.as_bytes())))
        }
        (
            AttachmentSourceAttemptKindV1::Release,
            AttachmentSourceActionV1::Release {
                acquisition_id,
                revision,
                record_digest,
            },
        ) => {
            let request = decode_live_release(body)?;
            if request.header().request_id() != operation_id.as_bytes()
                || request.request_digest() != request_digest
                || request.acquisition_id().as_bytes() != &acquisition_id
                || request.expected_revision() != revision
                || request.expected_record_digest().as_bytes() != &record_digest
                || !fence_matches_plan(request.fence(), &plan.plan)
                || mount_completion.is_some()
            {
                return Err(AttachmentSourceError::Conflict);
            }
            Ok((acquisition_id, None))
        }
        _ => Err(AttachmentSourceError::Conflict),
    }
}

fn validate_completion_action(
    attempt: &AttemptRecord,
    plan: &CurrentAttachmentSourcePlanV1,
) -> Result<(), AttachmentSourceError> {
    let matches = match (attempt.kind, plan.action) {
        (
            AttachmentSourceAttemptKindV1::Acquire,
            AttachmentSourceActionV1::CompleteAcquire { acquisition_id, .. }
            | AttachmentSourceActionV1::Consume { acquisition_id, .. }
            | AttachmentSourceActionV1::AwaitAttachment { acquisition_id, .. }
            | AttachmentSourceActionV1::Release { acquisition_id, .. }
            | AttachmentSourceActionV1::Ready { acquisition_id, .. },
        ) => acquisition_id == attempt.acquisition_id,
        (
            AttachmentSourceAttemptKindV1::Acquire,
            AttachmentSourceActionV1::CancelAcquire { acquisition_id },
        ) => acquisition_id == attempt.acquisition_id,
        (
            AttachmentSourceAttemptKindV1::Consume,
            AttachmentSourceActionV1::CompleteConsume { acquisition_id, .. },
        ) => acquisition_id == attempt.acquisition_id,
        (
            AttachmentSourceAttemptKindV1::Release,
            AttachmentSourceActionV1::CompleteRelease { acquisition_id, .. },
        ) => acquisition_id == attempt.acquisition_id,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(AttachmentSourceError::Conflict)
    }
}

fn decode_live_release(
    body: &[u8],
) -> Result<
    aos_sandbox_protocol::LiveValidatedReleaseMountSourceAcquisitionRequest,
    AttachmentSourceError,
> {
    let peer = PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    };
    let raw = aos_proto::aos::sandbox::local::v1::ReleaseMountSourceAcquisitionRequest::decode_from_slice(body)
        .map_err(|_| AttachmentSourceError::Protocol)?;
    if raw.encode_to_vec() != body {
        return Err(AttachmentSourceError::Protocol);
    }
    let now = raw
        .header
        .as_option()
        .and_then(|header| header.deadline_boottime_nanoseconds.checked_sub(1))
        .ok_or(AttachmentSourceError::Protocol)?;
    decode_release_mount_source_acquisition_request(
        body,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
    )
    .map_err(|_| AttachmentSourceError::Protocol)
}

fn fence_matches_plan(
    fence: &aos_sandbox_protocol::ValidatedAssignmentFence,
    plan: &CanonicalPlan,
) -> bool {
    fence.sandbox_id() == &plan.sandbox
        && fence.incarnation_id() == &plan.incarnation
        && fence.assignment_epoch() == plan.assignment_epoch
        && fence.desired_generation() == plan.assignment_generation
        && fence.assignment_digest() == &plan.assignment_digest
}

fn checked_size(retained: usize, key: &[u8], value: &[u8]) -> Result<usize, AttachmentSourceError> {
    retained
        .checked_add(key.len())
        .and_then(|size| size.checked_add(value.len()))
        .filter(|size| *size <= MAXIMUM_NAMESPACE_BYTES)
        .ok_or(AttachmentSourceError::Capacity)
}

impl AttemptRecord {
    fn transaction(&self) -> Result<JournalTransaction, AttachmentSourceError> {
        transaction(
            ATTEMPT_TRANSACTION_DOMAIN,
            self.digest,
            JournalRecord::put(ATTEMPT_NAMESPACE, self.operation_id.to_vec(), self.encode()),
        )
    }

    fn transaction_with_dispatch(
        &self,
        dispatch: &DispatchRecord,
    ) -> Result<JournalTransaction, AttachmentSourceError> {
        transaction_records(
            ATTEMPT_TRANSACTION_DOMAIN,
            self.digest,
            vec![
                JournalRecord::put(ATTEMPT_NAMESPACE, self.operation_id.to_vec(), self.encode()),
                dispatch.journal_record(),
            ],
        )
    }
}

impl CompletionRecord {
    fn transaction(&self) -> Result<JournalTransaction, AttachmentSourceError> {
        transaction(
            COMPLETION_TRANSACTION_DOMAIN,
            self.digest,
            JournalRecord::put(
                COMPLETION_NAMESPACE,
                self.operation_id.to_vec(),
                self.encode(),
            ),
        )
    }
}

fn transaction(
    domain: &[u8],
    digest: [u8; 32],
    record: JournalRecord,
) -> Result<JournalTransaction, AttachmentSourceError> {
    transaction_records(domain, digest, vec![record])
}

fn transaction_records(
    domain: &[u8],
    digest: [u8; 32],
    records: Vec<JournalRecord>,
) -> Result<JournalTransaction, AttachmentSourceError> {
    let mut id: [u8; 16] = Sha256::new()
        .chain_update(domain)
        .chain_update(digest)
        .finalize()[..16]
        .try_into()
        .map_err(|_| AttachmentSourceError::CorruptState)?;
    if id == [0; 16] {
        id[15] = 1;
    }
    Ok(JournalTransaction::new(id, records)?)
}

pub(crate) fn validate_attempt_namespace(
    journal: &mut Journal,
) -> Result<(), AttachmentSourceError> {
    CustodyHistory::load(journal).map(|_| ())
}

/// Recovers one exact open attempt as nonauthorizing restart evidence.
///
/// # Errors
///
/// Rejects malformed protected history or a sentinel attachment identity.
pub(crate) fn recover_open_attempt(
    journal: &mut Journal,
    attachment_id: aos_sandbox_core::AttachmentId,
) -> Result<Option<DurableAttachmentSourceAttemptV1>, AttachmentSourceError> {
    if attachment_id.as_bytes() == &[0; 16] {
        return Err(AttachmentSourceError::Conflict);
    }
    let history = CustodyHistory::load(journal)?;
    Ok(history
        .open_attempt(*attachment_id.as_bytes())
        .cloned()
        .map(|record| DurableAttachmentSourceAttemptV1 {
            record,
            outcome: AttachmentSourceAttemptOutcomeV1::Replay,
        }))
}

pub(crate) fn validate_completion_namespace(
    journal: &mut Journal,
) -> Result<(), AttachmentSourceError> {
    CustodyHistory::load(journal).map(|_| ())
}
