//! Stores generation-fenced attachment intent before any Mount effect.
//!
//! Every immutable generation carries canonical attachment semantics, the
//! operation and normalized request that committed them, and a digest-protected
//! state:
//!
//! ```text
//! AOSATD01 | state:1 | flags:1 | reserved:2 | operation-id:16 |
//! request-digest:32 | predecessor-digest:32 | intent-bytes:4 |
//! canonical-intent | digest:32
//! ```
//!
//! Replacement and release use the current record digest as their resource
//! version. A commit is accepted only while its consumer namespace target is
//! current. The durable record is desired state, not Mount authority or
//! evidence that a mount occupies the requested slot.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::model::AttachmentIntent;
use aos_sandbox_core::{
    AttachmentId, ObjectDigest, OperationId, RawPairedClockSample, decode_attachment_intent_v1,
    encode_attachment_intent_v1,
};
use sha2::{Digest as _, Sha256};

use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentNamespaceTarget, NamespaceTargetError};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSATD01";
const DOMAIN: &[u8] = b"aos.sandbox.attachment-desired.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.attachment-desired.transaction.v1\0";
const FIXED_RECORD_BYTES: usize = 128;
const FLAG_EXPECTED_PREVIOUS: u8 = 1;
const MAXIMUM_INTENT_BYTES: usize = 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = MAXIMUM_INTENT_BYTES + FIXED_RECORD_BYTES;
const MAXIMUM_ATTACHMENT_GENERATIONS: usize = 65_536;
const MAXIMUM_NAMESPACE_BYTES: usize = 256 * 1024 * 1024;

/// Selects whether an attachment generation should exist or be released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttachmentDesiredPresenceV1 {
    /// The exact view generation should occupy its declared destination slot.
    Present = 1,
    /// The prior realization should drain and become fully released.
    Released = 2,
}

impl AttachmentDesiredPresenceV1 {
    fn from_byte(value: u8) -> Result<Self, AttachmentDesiredStateError> {
        match value {
            1 => Ok(Self::Present),
            2 => Ok(Self::Released),
            _ => Err(AttachmentDesiredStateError::CorruptState),
        }
    }
}

/// Describes an atomic desired attachment generation change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentDesiredMutationV1 {
    record: Record,
}

impl AttachmentDesiredMutationV1 {
    /// Constructs a generation-fenced desired-state mutation.
    ///
    /// A first declaration supplies no expected digest. Replacement or release
    /// supplies the digest returned for the immediately preceding generation.
    /// The intent always carries the complete new generation, including for a
    /// release tombstone.
    ///
    /// # Errors
    ///
    /// Rejects zero operation or request identities and oversized canonical
    /// attachment semantics. Current-generation and transition checks occur
    /// atomically when the mutation is committed.
    pub fn new(
        presence: AttachmentDesiredPresenceV1,
        intent: AttachmentIntent,
        operation_id: OperationId,
        request_digest: ObjectDigest,
        expected_previous: Option<ObjectDigest>,
    ) -> Result<Self, AttachmentDesiredStateError> {
        if operation_id.as_bytes() == &[0; 16]
            || request_digest.as_bytes() == &[0; 32]
            || expected_previous.is_some_and(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(AttachmentDesiredStateError::InvalidMutation);
        }

        let intent_bytes = encode_attachment_intent_v1(&intent);
        if intent_bytes.is_empty() || intent_bytes.len() > MAXIMUM_INTENT_BYTES {
            return Err(AttachmentDesiredStateError::Capacity);
        }
        let mut record = Record {
            presence,
            operation_id,
            request_digest,
            expected_previous,
            intent_bytes,
            intent,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate()?;
        Ok(Self { record })
    }

    /// Returns the attachment changed by this mutation.
    #[must_use]
    pub const fn attachment_id(&self) -> AttachmentId {
        self.record.intent.id()
    }

    /// Returns the expected current resource version, if this is not creation.
    #[must_use]
    pub const fn expected_previous(&self) -> Option<ObjectDigest> {
        self.record.expected_previous
    }
}

/// Reports whether one exact desired attachment generation committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentDesiredCommitOutcomeV1 {
    /// The mutation became durable in this call.
    Recorded,
    /// The exact operation and desired bytes were already durable.
    Replay,
}

/// Exposes one validated durable desired attachment generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAttachmentDesiredStateV1 {
    record: Record,
}

impl DurableAttachmentDesiredStateV1 {
    /// Returns whether this generation should be present or released.
    #[must_use]
    pub const fn presence(&self) -> AttachmentDesiredPresenceV1 {
        self.record.presence
    }

    /// Borrows the complete canonical attachment intent.
    #[must_use]
    pub const fn intent(&self) -> &AttachmentIntent {
        &self.record.intent
    }

    /// Returns the operation that committed this desired generation.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.record.operation_id
    }

    /// Returns the normalized request digest admitted for the operation.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.record.request_digest
    }

    /// Returns the resource version required by the next mutation.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }
}

/// Retains current namespace authority beside a committed desired generation.
pub struct CommittedCurrentAttachmentDesiredStateV1 {
    target: CurrentNamespaceTarget,
    state: DurableAttachmentDesiredStateV1,
    outcome: AttachmentDesiredCommitOutcomeV1,
}

impl CommittedCurrentAttachmentDesiredStateV1 {
    /// Borrows the target that remained current across the desired-state commit.
    #[must_use]
    pub const fn target(&self) -> &CurrentNamespaceTarget {
        &self.target
    }

    /// Borrows the exact durable desired attachment state.
    #[must_use]
    pub const fn state(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.state
    }

    /// Reports whether this call recorded or replayed the exact mutation.
    #[must_use]
    pub const fn outcome(&self) -> AttachmentDesiredCommitOutcomeV1 {
        self.outcome
    }

    /// Recovers the retained target for separately authorized planning.
    #[must_use]
    pub fn into_target(self) -> CurrentNamespaceTarget {
        self.target
    }
}

/// Reports invalid attachment desired state, stale authority, or durability failure.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentDesiredStateError {
    /// A caller supplied sentinel or structurally incomplete mutation metadata.
    #[error("attachment desired mutation is invalid")]
    InvalidMutation,
    /// The expected generation, resource version, slot, or transition conflicts.
    #[error("attachment desired mutation conflicts with current state")]
    Conflict,
    /// Reserved desired-state bytes violate their closed schema or cross-record invariants.
    #[error("attachment desired state is corrupt")]
    CorruptState,
    /// Attachment count or retained bytes exceed their fixed controller ceiling.
    #[error("attachment desired-state capacity is exhausted")]
    Capacity,
    /// The consumer namespace target is no longer current.
    #[error(transparent)]
    CurrentTarget(#[from] NamespaceTargetError),
    /// The durable journal rejected the transaction.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    presence: AttachmentDesiredPresenceV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    expected_previous: Option<ObjectDigest>,
    intent_bytes: Vec<u8>,
    intent: AttachmentIntent,
    digest: [u8; 32],
}

impl Record {
    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(self.intent.id().as_bytes());
        key.extend_from_slice(&self.intent.desired_generation().get().to_be_bytes());
        key
    }

    fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES.saturating_add(self.intent_bytes.len())
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update([self.presence as u8]);
        digest.update(self.operation_id.as_bytes());
        digest.update(self.request_digest.as_bytes());
        digest.update([u8::from(self.expected_previous.is_some())]);
        digest.update(
            self.expected_previous
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        digest.update((self.intent_bytes.len() as u64).to_be_bytes());
        digest.update(&self.intent_bytes);
        digest.finalize().into()
    }

    fn validate(&self) -> Result<(), AttachmentDesiredStateError> {
        if self.operation_id.as_bytes() == &[0; 16]
            || self.request_digest.as_bytes() == &[0; 32]
            || self
                .expected_previous
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || self.intent_bytes.is_empty()
            || self.intent_bytes.len() > MAXIMUM_INTENT_BYTES
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || encode_attachment_intent_v1(&self.intent) != self.intent_bytes
            || self.compute_digest() != self.digest
        {
            return Err(AttachmentDesiredStateError::CorruptState);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.presence as u8);
        bytes.push(if self.expected_previous.is_some() {
            FLAG_EXPECTED_PREVIOUS
        } else {
            0
        });
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(self.operation_id.as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(
            &self
                .expected_previous
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        bytes.extend_from_slice(&(self.intent_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.intent_bytes);
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, AttachmentDesiredStateError> {
        if bytes.len() < FIXED_RECORD_BYTES || bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(AttachmentDesiredStateError::CorruptState);
        }
        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC {
            return Err(AttachmentDesiredStateError::CorruptState);
        }
        let presence = AttachmentDesiredPresenceV1::from_byte(take::<1>(&mut bytes)?[0])?;
        let flags = take::<1>(&mut bytes)?[0];
        if flags & !FLAG_EXPECTED_PREVIOUS != 0 || take::<2>(&mut bytes)? != [0; 2] {
            return Err(AttachmentDesiredStateError::CorruptState);
        }
        let operation_id = OperationId::from_bytes(take(&mut bytes)?);
        let request_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
        let expected_previous_bytes = take::<32>(&mut bytes)?;
        let expected_previous = match (flags & FLAG_EXPECTED_PREVIOUS != 0, expected_previous_bytes)
        {
            (false, bytes) if bytes == [0; 32] => None,
            (true, bytes) if bytes != [0; 32] => Some(ObjectDigest::from_bytes(bytes)),
            _ => return Err(AttachmentDesiredStateError::CorruptState),
        };
        let intent_length = u32::from_be_bytes(take(&mut bytes)?) as usize;
        if intent_length == 0 || intent_length > MAXIMUM_INTENT_BYTES {
            return Err(AttachmentDesiredStateError::CorruptState);
        }
        let intent_bytes = bytes
            .get(..intent_length)
            .ok_or(AttachmentDesiredStateError::CorruptState)?
            .to_vec();
        bytes = bytes
            .get(intent_length..)
            .ok_or(AttachmentDesiredStateError::CorruptState)?;
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(AttachmentDesiredStateError::CorruptState);
        }
        let intent =
            decode_attachment_intent_v1(&intent_bytes, aos_sandbox_core::DecodeLimits::default())
                .map_err(|_| AttachmentDesiredStateError::CorruptState)?;
        let record = Self {
            presence,
            operation_id,
            request_digest,
            expected_previous,
            intent_bytes,
            intent,
            digest,
        };
        record.validate()?;
        Ok(record)
    }

    fn transaction(&self) -> Result<JournalTransaction, AttachmentDesiredStateError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| AttachmentDesiredStateError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::AttachmentDesired,
                self.key(),
                self.encode(),
            )],
        )?)
    }
}

#[derive(Default)]
struct History {
    records: BTreeMap<AttachmentId, Record>,
    generations: BTreeMap<(AttachmentId, u64), Record>,
    operations: BTreeMap<OperationId, (AttachmentId, u64)>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &Journal) -> Result<Self, AttachmentDesiredStateError> {
        let mut records: BTreeMap<AttachmentId, Record> = BTreeMap::new();
        let mut generations = BTreeMap::new();
        let mut operations = BTreeMap::new();
        let mut retained_bytes = 0_usize;

        for (key, value) in journal.records(RecordNamespace::AttachmentDesired) {
            if key.len() != 24 {
                return Err(AttachmentDesiredStateError::CorruptState);
            }
            if generations.len() >= MAXIMUM_ATTACHMENT_GENERATIONS
                || value.len() > MAXIMUM_RECORD_BYTES
            {
                return Err(AttachmentDesiredStateError::Capacity);
            }
            retained_bytes = retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(AttachmentDesiredStateError::Capacity)?;
            if retained_bytes > MAXIMUM_NAMESPACE_BYTES {
                return Err(AttachmentDesiredStateError::Capacity);
            }

            let record = Record::decode(value)?;
            if key != record.key() {
                return Err(AttachmentDesiredStateError::CorruptState);
            }
            let generation = record.intent.desired_generation().get();
            let generation_key = (record.intent.id(), generation);
            if operations
                .insert(record.operation_id, generation_key)
                .is_some()
                || generations.insert(generation_key, record).is_some()
            {
                return Err(AttachmentDesiredStateError::CorruptState);
            }
        }

        for ((attachment_id, generation), record) in &generations {
            match records.get(attachment_id) {
                None if *generation == 1
                    && record.presence == AttachmentDesiredPresenceV1::Present
                    && record.expected_previous.is_none() => {}
                Some(previous)
                    if previous.intent.desired_generation().get().checked_add(1)
                        == Some(*generation)
                        && previous.presence != AttachmentDesiredPresenceV1::Released
                        && record.expected_previous
                            == Some(ObjectDigest::from_bytes(previous.digest))
                        && previous.intent.consumer() == record.intent.consumer()
                        && previous.intent.destination_slot()
                            == record.intent.destination_slot() => {}
                _ => return Err(AttachmentDesiredStateError::CorruptState),
            }
            records.insert(*attachment_id, record.clone());
        }

        let mut occupied_slots = BTreeSet::new();
        for record in records
            .values()
            .filter(|record| record.presence == AttachmentDesiredPresenceV1::Present)
        {
            let (sandbox, incarnation) = record.intent.consumer();
            let slot = (
                sandbox,
                incarnation,
                record.intent.expected_namespace_generation(),
                record.intent.destination_slot(),
            );
            if !occupied_slots.insert(slot) {
                return Err(AttachmentDesiredStateError::CorruptState);
            }
        }

        Ok(Self {
            records,
            generations,
            operations,
            retained_bytes,
        })
    }

    fn validate_mutation(
        &self,
        mutation: &AttachmentDesiredMutationV1,
    ) -> Result<AttachmentDesiredCommitOutcomeV1, AttachmentDesiredStateError> {
        let proposed = &mutation.record;
        let Some(current) = self.records.get(&proposed.intent.id()) else {
            if proposed.expected_previous.is_some()
                || proposed.presence != AttachmentDesiredPresenceV1::Present
                || proposed.intent.desired_generation().get() != 1
                || self.operations.contains_key(&proposed.operation_id)
            {
                return Err(AttachmentDesiredStateError::Conflict);
            }
            self.ensure_capacity(proposed)?;
            self.ensure_slot_available(proposed)?;
            return Ok(AttachmentDesiredCommitOutcomeV1::Recorded);
        };

        if current == proposed {
            return Ok(AttachmentDesiredCommitOutcomeV1::Replay);
        }
        if self.operations.contains_key(&proposed.operation_id) {
            return Err(AttachmentDesiredStateError::Conflict);
        }
        if proposed.expected_previous != Some(ObjectDigest::from_bytes(current.digest))
            || current.presence == AttachmentDesiredPresenceV1::Released
            || proposed.intent.desired_generation().get()
                != current
                    .intent
                    .desired_generation()
                    .get()
                    .checked_add(1)
                    .ok_or(AttachmentDesiredStateError::Capacity)?
            || current.intent.consumer() != proposed.intent.consumer()
            || current.intent.destination_slot() != proposed.intent.destination_slot()
        {
            return Err(AttachmentDesiredStateError::Conflict);
        }
        self.ensure_capacity(proposed)?;
        self.ensure_slot_available(proposed)?;
        Ok(AttachmentDesiredCommitOutcomeV1::Recorded)
    }

    fn ensure_capacity(&self, record: &Record) -> Result<(), AttachmentDesiredStateError> {
        let retained_bytes = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(AttachmentDesiredStateError::Capacity)?;
        if self.generations.len() >= MAXIMUM_ATTACHMENT_GENERATIONS
            || retained_bytes > MAXIMUM_NAMESPACE_BYTES
        {
            return Err(AttachmentDesiredStateError::Capacity);
        }
        Ok(())
    }

    fn ensure_slot_available(&self, proposed: &Record) -> Result<(), AttachmentDesiredStateError> {
        if proposed.presence == AttachmentDesiredPresenceV1::Released {
            return Ok(());
        }
        let (sandbox, incarnation) = proposed.intent.consumer();
        let conflicts = self.records.values().any(|current| {
            current.intent.id() != proposed.intent.id()
                && current.presence == AttachmentDesiredPresenceV1::Present
                && current.intent.consumer() == (sandbox, incarnation)
                && current.intent.expected_namespace_generation()
                    == proposed.intent.expected_namespace_generation()
                && current.intent.destination_slot() == proposed.intent.destination_slot()
        });
        if conflicts {
            Err(AttachmentDesiredStateError::Conflict)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn commit_current<T>(
    journal: &mut Journal,
    target: CurrentNamespaceTarget,
    mutation: AttachmentDesiredMutationV1,
    clock: &mut T,
) -> Result<CommittedCurrentAttachmentDesiredStateV1, AttachmentDesiredStateError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    target.recheck(journal, clock)?;
    validate_target(&target, &mutation.record.intent)?;

    let history = History::load(journal)?;
    let outcome = history.validate_mutation(&mutation)?;
    if outcome == AttachmentDesiredCommitOutcomeV1::Recorded {
        journal.commit(&mutation.record.transaction()?)?;
    }

    let committed = History::load(journal)?;
    if committed.records.get(&mutation.record.intent.id()) != Some(&mutation.record) {
        return Err(AttachmentDesiredStateError::CorruptState);
    }
    target.recheck(journal, clock)?;
    validate_target(&target, &mutation.record.intent)?;

    Ok(CommittedCurrentAttachmentDesiredStateV1 {
        target,
        state: DurableAttachmentDesiredStateV1 {
            record: mutation.record,
        },
        outcome,
    })
}

pub(crate) fn get(
    journal: &Journal,
    attachment_id: AttachmentId,
) -> Result<Option<DurableAttachmentDesiredStateV1>, AttachmentDesiredStateError> {
    let history = History::load(journal)?;
    Ok(history
        .records
        .get(&attachment_id)
        .cloned()
        .map(|record| DurableAttachmentDesiredStateV1 { record }))
}

pub(crate) fn validate_namespace(journal: &Journal) -> Result<(), AttachmentDesiredStateError> {
    History::load(journal).map(|_| ())
}

fn validate_target(
    target: &CurrentNamespaceTarget,
    intent: &AttachmentIntent,
) -> Result<(), AttachmentDesiredStateError> {
    let manifest = target
        .runtime_generation()
        .scope()
        .binding()
        .manifest()
        .manifest();
    if intent.consumer() != (manifest.sandbox(), manifest.incarnation())
        || intent.expected_namespace_generation().get() != target.target_generation()
    {
        return Err(AttachmentDesiredStateError::Conflict);
    }
    Ok(())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], AttachmentDesiredStateError> {
    let value = bytes
        .get(..N)
        .ok_or(AttachmentDesiredStateError::CorruptState)?
        .try_into()
        .map_err(|_| AttachmentDesiredStateError::CorruptState)?;
    *bytes = bytes
        .get(N..)
        .ok_or(AttachmentDesiredStateError::CorruptState)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        EffectFailure, EffectObservation, EffectPlan, EffectReceipt, SingleNodeEffectExecutor,
    };
    use aos_sandbox_core::model::{
        AttachmentConsistency, AttachmentLease, MountAttributes, ViewMutation,
    };
    use aos_sandbox_core::{
        AttachmentSlotId, DesiredGeneration, IncarnationId, LeaseId, MediaType,
        NamespaceGeneration, ObjectDescriptor, Revision, SandboxId, ViewId,
    };

    struct NoEffects;

    impl SingleNodeEffectExecutor for NoEffects {
        fn observe(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            panic!("attachment desired-state tests must not observe effects")
        }

        fn apply(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            panic!("attachment desired-state tests must not apply effects")
        }
    }

    fn open_journal(directory: &TempDir) -> Journal {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            Default::default(),
            std::fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap()
        .0
    }

    fn journal() -> (TempDir, Journal) {
        let directory = TempDir::new().unwrap();
        let journal = open_journal(&directory);
        (directory, journal)
    }

    fn intent(id: u8, slot: u8, generation: u64) -> AttachmentIntent {
        AttachmentIntent::new(
            AttachmentId::from_bytes([id; 16]),
            DesiredGeneration::new(generation),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(generation),
            None,
            ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.view.v1+cbor").unwrap(),
                ObjectDigest::from_bytes([7; 32]),
                8,
            ),
            AttachmentSlotId::from_bytes([slot; 16]),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadOnly,
            MountAttributes::new(true, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([9; 16]), 10, 20).unwrap(),
        )
        .unwrap()
    }

    fn mutation(
        presence: AttachmentDesiredPresenceV1,
        intent: AttachmentIntent,
        expected_previous: Option<ObjectDigest>,
    ) -> AttachmentDesiredMutationV1 {
        let operation_byte = intent.id().as_bytes()[0]
            .checked_add(u8::try_from(intent.desired_generation().get()).unwrap())
            .and_then(|value| value.checked_add(10))
            .unwrap();
        AttachmentDesiredMutationV1::new(
            presence,
            intent,
            OperationId::from_bytes([operation_byte; 16]),
            ObjectDigest::from_bytes([12; 32]),
            expected_previous,
        )
        .unwrap()
    }

    fn commit_without_target(
        journal: &mut Journal,
        mutation: &AttachmentDesiredMutationV1,
    ) -> AttachmentDesiredCommitOutcomeV1 {
        let history = History::load(journal).unwrap();
        let outcome = history.validate_mutation(mutation).unwrap();
        if outcome == AttachmentDesiredCommitOutcomeV1::Recorded {
            journal
                .commit(&mutation.record.transaction().unwrap())
                .unwrap();
        }
        outcome
    }

    #[test]
    fn declaration_replacement_release_and_replay_are_generation_fenced() {
        let (directory, mut journal) = journal();
        let first = mutation(AttachmentDesiredPresenceV1::Present, intent(1, 2, 1), None);
        assert_eq!(
            commit_without_target(&mut journal, &first),
            AttachmentDesiredCommitOutcomeV1::Recorded
        );
        assert_eq!(
            commit_without_target(&mut journal, &first),
            AttachmentDesiredCommitOutcomeV1::Replay
        );

        let first_digest = ObjectDigest::from_bytes(first.record.digest);
        let replacement = mutation(
            AttachmentDesiredPresenceV1::Present,
            intent(1, 2, 2),
            Some(first_digest),
        );
        assert_eq!(
            commit_without_target(&mut journal, &replacement),
            AttachmentDesiredCommitOutcomeV1::Recorded
        );

        let replacement_digest = ObjectDigest::from_bytes(replacement.record.digest);
        let release = mutation(
            AttachmentDesiredPresenceV1::Released,
            intent(1, 2, 3),
            Some(replacement_digest),
        );
        assert_eq!(
            commit_without_target(&mut journal, &release),
            AttachmentDesiredCommitOutcomeV1::Recorded
        );
        assert_eq!(
            get(&journal, AttachmentId::from_bytes([1; 16]))
                .unwrap()
                .unwrap()
                .presence(),
            AttachmentDesiredPresenceV1::Released
        );

        journal.compact().unwrap();
        drop(journal);
        let recovered = open_journal(&directory);
        assert_eq!(
            get(&recovered, AttachmentId::from_bytes([1; 16]))
                .unwrap()
                .unwrap()
                .presence(),
            AttachmentDesiredPresenceV1::Released
        );
    }

    #[test]
    fn stale_digest_generation_and_recreation_fail_closed() {
        let (_directory, mut journal) = journal();
        let first = mutation(AttachmentDesiredPresenceV1::Present, intent(1, 2, 1), None);
        commit_without_target(&mut journal, &first);

        let stale = mutation(
            AttachmentDesiredPresenceV1::Present,
            intent(1, 2, 2),
            Some(ObjectDigest::from_bytes([13; 32])),
        );
        assert!(matches!(
            History::load(&journal).unwrap().validate_mutation(&stale),
            Err(AttachmentDesiredStateError::Conflict)
        ));

        let skipped = mutation(
            AttachmentDesiredPresenceV1::Present,
            intent(1, 2, 3),
            Some(ObjectDigest::from_bytes(first.record.digest)),
        );
        assert!(matches!(
            History::load(&journal).unwrap().validate_mutation(&skipped),
            Err(AttachmentDesiredStateError::Conflict)
        ));

        journal
            .commit(&stale.record.transaction().unwrap())
            .unwrap();
        assert!(matches!(
            validate_namespace(&journal),
            Err(AttachmentDesiredStateError::CorruptState)
        ));
    }

    #[test]
    fn two_present_attachments_cannot_claim_one_slot() {
        let (_directory, mut journal) = journal();
        let first = mutation(AttachmentDesiredPresenceV1::Present, intent(1, 2, 1), None);
        commit_without_target(&mut journal, &first);
        let collision = mutation(AttachmentDesiredPresenceV1::Present, intent(2, 2, 1), None);

        assert!(matches!(
            History::load(&journal)
                .unwrap()
                .validate_mutation(&collision),
            Err(AttachmentDesiredStateError::Conflict)
        ));
    }

    #[test]
    fn one_operation_cannot_name_two_attachment_generations() {
        let (_directory, mut journal) = journal();
        let first = mutation(AttachmentDesiredPresenceV1::Present, intent(1, 2, 1), None);
        commit_without_target(&mut journal, &first);
        let second_intent = intent(2, 3, 1);
        let reused_operation = AttachmentDesiredMutationV1::new(
            AttachmentDesiredPresenceV1::Present,
            second_intent,
            first.record.operation_id,
            ObjectDigest::from_bytes([13; 32]),
            None,
        )
        .unwrap();

        assert!(matches!(
            History::load(&journal)
                .unwrap()
                .validate_mutation(&reused_operation),
            Err(AttachmentDesiredStateError::Conflict)
        ));
    }

    #[test]
    fn desired_generation_changes_the_mount_inventory_freshness_commitment() {
        let (_directory, mut journal) = journal();
        let before = crate::mount_attempt::mount_controller_state_digest(&mut journal).unwrap();
        let declaration = mutation(AttachmentDesiredPresenceV1::Present, intent(1, 2, 1), None);

        commit_without_target(&mut journal, &declaration);
        let after = crate::mount_attempt::mount_controller_state_digest(&mut journal).unwrap();

        assert_ne!(before, after);
    }

    #[test]
    fn reserved_prefix_corruption_blocks_replay() {
        let (_directory, mut journal) = journal();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::AttachmentDesired,
                        vec![1; 24],
                        b"corrupt".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            validate_namespace(&journal),
            Err(AttachmentDesiredStateError::CorruptState)
        ));

        let mut reconciler = crate::Reconciler::new(journal, NoEffects);
        assert!(matches!(
            reconciler.reconcile_next(),
            Err(crate::ReconcilerError::AttachmentDesired(error))
                if matches!(*error, AttachmentDesiredStateError::CorruptState)
        ));
    }
}
