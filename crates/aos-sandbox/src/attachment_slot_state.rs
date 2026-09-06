//! Persists destination slots bound to exact sandbox namespace generations.
//!
//! A destination slot is a logical, path-free attachment anchor. Its first
//! record binds the slot to one sandbox incarnation and namespace generation;
//! its optional successor is a permanent release tombstone:
//!
//! ```text
//! AOSSLT01 | presence:1 | flags:1 | reserved:2 | slot-id:16 |
//! revision:8 | sandbox-id:16 | incarnation-id:16 |
//! namespace-generation:8 | operation-id:16 | request-digest:32 |
//! predecessor-digest:32 | digest:32
//! ```
//!
//! The record contains no destination path or OS descriptor. A separately
//! authorized node-local catalog must resolve the logical slot and prove its
//! pinned kernel identity before Mount may publish into it.

use std::collections::BTreeMap;

use aos_sandbox_core::model::AttachmentIntent;
use aos_sandbox_core::{
    AttachmentSlotId, IncarnationId, ObjectDigest, OperationId, RawPairedClockSample, Revision,
    SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentNamespaceTarget, NamespaceTargetError};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSSLT01";
const DOMAIN: &[u8] = b"aos.sandbox.attachment-slot.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.attachment-slot.transaction.v1\0";
const RECORD_BYTES: usize = 188;
const FLAG_EXPECTED_PREVIOUS: u8 = 1;
const MAXIMUM_SLOT_RECORDS: usize = 65_536;
const MAXIMUM_NAMESPACE_BYTES: usize = 32 * 1024 * 1024;

/// Selects whether a destination slot is available or permanently released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttachmentSlotPresenceV1 {
    /// Allows attachments to name the exact namespace-bound slot.
    Available = 1,
    /// Permanently retires the slot after every attachment and mount drains.
    Released = 2,
}

impl AttachmentSlotPresenceV1 {
    fn from_byte(value: u8) -> Result<Self, AttachmentSlotStateError> {
        match value {
            1 => Ok(Self::Available),
            2 => Ok(Self::Released),
            _ => Err(AttachmentSlotStateError::CorruptState),
        }
    }
}

/// Describes one generation-fenced destination-slot mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentSlotMutationV1 {
    presence: AttachmentSlotPresenceV1,
    slot_id: AttachmentSlotId,
    revision: Revision,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    expected_previous: Option<ObjectDigest>,
}

impl AttachmentSlotMutationV1 {
    /// Constructs a destination-slot creation or release request.
    ///
    /// Revision one creates the slot and supplies no predecessor. Revision two
    /// releases it and supplies the exact record digest returned by creation.
    /// The controller derives the sandbox, incarnation, and namespace from a
    /// live [`CurrentNamespaceTarget`]; callers cannot supply that binding.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, revision zero, or a zero expected resource
    /// version. Transition and current-target checks occur during commit.
    pub fn new(
        presence: AttachmentSlotPresenceV1,
        slot_id: AttachmentSlotId,
        revision: Revision,
        operation_id: OperationId,
        request_digest: ObjectDigest,
        expected_previous: Option<ObjectDigest>,
    ) -> Result<Self, AttachmentSlotStateError> {
        if slot_id.as_bytes() == &[0; 16]
            || revision.get() == 0
            || operation_id.as_bytes() == &[0; 16]
            || request_digest.as_bytes() == &[0; 32]
            || expected_previous.is_some_and(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(AttachmentSlotStateError::InvalidMutation);
        }

        Ok(Self {
            presence,
            slot_id,
            revision,
            operation_id,
            request_digest,
            expected_previous,
        })
    }

    /// Returns the logical destination-slot identity.
    #[must_use]
    pub const fn slot_id(&self) -> AttachmentSlotId {
        self.slot_id
    }

    /// Returns the requested immutable slot revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the expected current resource version, if this is release.
    #[must_use]
    pub const fn expected_previous(&self) -> Option<ObjectDigest> {
        self.expected_previous
    }
}

/// Reports whether an exact destination-slot mutation committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentSlotCommitOutcomeV1 {
    /// The mutation became durable in this call.
    Recorded,
    /// The exact operation and target-bound mutation were already durable.
    Replay,
}

/// Exposes one validated durable destination-slot revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAttachmentSlotV1 {
    record: Record,
}

impl DurableAttachmentSlotV1 {
    /// Returns whether this slot is available or released.
    #[must_use]
    pub const fn presence(&self) -> AttachmentSlotPresenceV1 {
        self.record.presence
    }

    /// Returns the logical destination-slot identity.
    #[must_use]
    pub const fn slot_id(&self) -> AttachmentSlotId {
        self.record.slot_id
    }

    /// Returns this immutable slot revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.record.revision
    }

    /// Returns the sandbox that owns the slot.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.record.binding.sandbox
    }

    /// Returns the sandbox incarnation whose namespace contains the slot.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.record.binding.incarnation
    }

    /// Returns the exact namespace generation containing the slot.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.record.binding.namespace_generation
    }

    /// Returns the operation that committed this revision.
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

/// Retains current namespace authority beside a committed destination slot.
pub struct CommittedCurrentAttachmentSlotV1 {
    target: CurrentNamespaceTarget,
    slot: DurableAttachmentSlotV1,
    outcome: AttachmentSlotCommitOutcomeV1,
}

impl CommittedCurrentAttachmentSlotV1 {
    /// Borrows the target that remained current across the slot commit.
    #[must_use]
    pub const fn target(&self) -> &CurrentNamespaceTarget {
        &self.target
    }

    /// Borrows the exact durable destination-slot state.
    #[must_use]
    pub const fn slot(&self) -> &DurableAttachmentSlotV1 {
        &self.slot
    }

    /// Reports whether this call recorded or replayed the exact mutation.
    #[must_use]
    pub const fn outcome(&self) -> AttachmentSlotCommitOutcomeV1 {
        self.outcome
    }

    /// Recovers the retained target for separately authorized work.
    #[must_use]
    pub fn into_target(self) -> CurrentNamespaceTarget {
        self.target
    }
}

/// Reports invalid destination-slot state, stale authority, or durability failure.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentSlotStateError {
    /// A caller supplied sentinel or structurally incomplete mutation metadata.
    #[error("attachment-slot mutation is invalid")]
    InvalidMutation,
    /// The target, revision, resource version, or transition conflicts.
    #[error("attachment-slot mutation conflicts with current state")]
    Conflict,
    /// Reserved bytes or immutable cross-record bindings are inconsistent.
    #[error("attachment-slot state is corrupt")]
    CorruptState,
    /// Slot history exceeds its fixed record or retained-byte ceiling.
    #[error("attachment-slot state capacity is exhausted")]
    Capacity,
    /// The consumer namespace target is no longer current.
    #[error(transparent)]
    CurrentTarget(#[from] NamespaceTargetError),
    /// The durable journal rejected the transaction.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotBinding {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    namespace_generation: u64,
}

impl SlotBinding {
    fn from_target(target: &CurrentNamespaceTarget) -> Self {
        let manifest = target
            .runtime_generation()
            .scope()
            .binding()
            .manifest()
            .manifest();
        Self {
            sandbox: manifest.sandbox(),
            incarnation: manifest.incarnation(),
            namespace_generation: target.target_generation(),
        }
    }

    fn matches_intent(self, intent: &AttachmentIntent) -> bool {
        let (sandbox, incarnation) = intent.consumer();
        self.sandbox == sandbox
            && self.incarnation == incarnation
            && self.namespace_generation == intent.expected_namespace_generation().get()
    }

    fn validate(self) -> Result<(), AttachmentSlotStateError> {
        if self.sandbox.as_bytes() == &[0; 16]
            || self.incarnation.as_bytes() == &[0; 16]
            || self.namespace_generation == 0
        {
            return Err(AttachmentSlotStateError::CorruptState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    presence: AttachmentSlotPresenceV1,
    slot_id: AttachmentSlotId,
    revision: Revision,
    binding: SlotBinding,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    expected_previous: Option<ObjectDigest>,
    digest: [u8; 32],
}

impl Record {
    fn new(mutation: &AttachmentSlotMutationV1, binding: SlotBinding) -> Self {
        let mut record = Self {
            presence: mutation.presence,
            slot_id: mutation.slot_id,
            revision: mutation.revision,
            binding,
            operation_id: mutation.operation_id,
            request_digest: mutation.request_digest,
            expected_previous: mutation.expected_previous,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record
    }

    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(self.slot_id.as_bytes());
        key.extend_from_slice(&self.revision.get().to_be_bytes());
        key
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update([self.presence as u8]);
        digest.update(self.slot_id.as_bytes());
        digest.update(self.revision.get().to_be_bytes());
        digest.update(self.binding.sandbox.as_bytes());
        digest.update(self.binding.incarnation.as_bytes());
        digest.update(self.binding.namespace_generation.to_be_bytes());
        digest.update(self.operation_id.as_bytes());
        digest.update(self.request_digest.as_bytes());
        digest.update([u8::from(self.expected_previous.is_some())]);
        digest.update(
            self.expected_previous
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        digest.finalize().into()
    }

    fn validate(&self) -> Result<(), AttachmentSlotStateError> {
        self.binding.validate()?;
        if self.slot_id.as_bytes() == &[0; 16]
            || self.revision.get() == 0
            || self.operation_id.as_bytes() == &[0; 16]
            || self.request_digest.as_bytes() == &[0; 32]
            || self
                .expected_previous
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || self.compute_digest() != self.digest
        {
            return Err(AttachmentSlotStateError::CorruptState);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.presence as u8);
        bytes.push(if self.expected_previous.is_some() {
            FLAG_EXPECTED_PREVIOUS
        } else {
            0
        });
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(self.slot_id.as_bytes());
        bytes.extend_from_slice(&self.revision.get().to_be_bytes());
        bytes.extend_from_slice(self.binding.sandbox.as_bytes());
        bytes.extend_from_slice(self.binding.incarnation.as_bytes());
        bytes.extend_from_slice(&self.binding.namespace_generation.to_be_bytes());
        bytes.extend_from_slice(self.operation_id.as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(
            &self
                .expected_previous
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, AttachmentSlotStateError> {
        if bytes.len() != RECORD_BYTES {
            return Err(AttachmentSlotStateError::CorruptState);
        }

        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC {
            return Err(AttachmentSlotStateError::CorruptState);
        }
        let presence = AttachmentSlotPresenceV1::from_byte(take::<1>(&mut bytes)?[0])?;
        let flags = take::<1>(&mut bytes)?[0];
        if flags & !FLAG_EXPECTED_PREVIOUS != 0 || take::<2>(&mut bytes)? != [0; 2] {
            return Err(AttachmentSlotStateError::CorruptState);
        }
        let slot_id = AttachmentSlotId::from_bytes(take(&mut bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        let binding = SlotBinding {
            sandbox: SandboxId::from_bytes(take(&mut bytes)?),
            incarnation: IncarnationId::from_bytes(take(&mut bytes)?),
            namespace_generation: u64::from_be_bytes(take(&mut bytes)?),
        };
        let operation_id = OperationId::from_bytes(take(&mut bytes)?);
        let request_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
        let expected_previous_bytes = take::<32>(&mut bytes)?;
        let expected_previous = match (flags & FLAG_EXPECTED_PREVIOUS != 0, expected_previous_bytes)
        {
            (false, bytes) if bytes == [0; 32] => None,
            (true, bytes) if bytes != [0; 32] => Some(ObjectDigest::from_bytes(bytes)),
            _ => return Err(AttachmentSlotStateError::CorruptState),
        };
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(AttachmentSlotStateError::CorruptState);
        }

        let record = Self {
            presence,
            slot_id,
            revision,
            binding,
            operation_id,
            request_digest,
            expected_previous,
            digest,
        };
        record.validate()?;
        Ok(record)
    }

    fn transaction(&self) -> Result<JournalTransaction, AttachmentSlotStateError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| AttachmentSlotStateError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::AttachmentSlot,
                self.key(),
                self.encode(),
            )],
        )?)
    }
}

#[derive(Default)]
struct History {
    current: BTreeMap<AttachmentSlotId, Record>,
    revisions: BTreeMap<(AttachmentSlotId, u64), Record>,
    operations: BTreeMap<OperationId, (AttachmentSlotId, u64)>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &Journal) -> Result<Self, AttachmentSlotStateError> {
        let mut history = Self::default();

        for (key, value) in journal.records(RecordNamespace::AttachmentSlot) {
            if key.len() != 24 || value.len() != RECORD_BYTES {
                return Err(AttachmentSlotStateError::CorruptState);
            }
            if history.revisions.len() >= MAXIMUM_SLOT_RECORDS {
                return Err(AttachmentSlotStateError::Capacity);
            }
            history.retained_bytes = history
                .retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(AttachmentSlotStateError::Capacity)?;
            if history.retained_bytes > MAXIMUM_NAMESPACE_BYTES {
                return Err(AttachmentSlotStateError::Capacity);
            }

            let record = Record::decode(value)?;
            if key != record.key() {
                return Err(AttachmentSlotStateError::CorruptState);
            }
            let revision_key = (record.slot_id, record.revision.get());
            if history
                .operations
                .insert(record.operation_id, revision_key)
                .is_some()
                || history.revisions.insert(revision_key, record).is_some()
            {
                return Err(AttachmentSlotStateError::CorruptState);
            }
        }

        for ((slot_id, revision), record) in &history.revisions {
            match history.current.get(slot_id) {
                None if *revision == 1
                    && record.presence == AttachmentSlotPresenceV1::Available
                    && record.expected_previous.is_none() => {}
                Some(previous)
                    if *revision == 2
                        && previous.revision.get() == 1
                        && previous.presence == AttachmentSlotPresenceV1::Available
                        && record.presence == AttachmentSlotPresenceV1::Released
                        && record.binding == previous.binding
                        && record.expected_previous
                            == Some(ObjectDigest::from_bytes(previous.digest)) => {}
                _ => return Err(AttachmentSlotStateError::CorruptState),
            }
            history.current.insert(*slot_id, record.clone());
        }

        Ok(history)
    }

    fn select(
        &self,
        mutation: &AttachmentSlotMutationV1,
        binding: SlotBinding,
    ) -> Result<(Record, AttachmentSlotCommitOutcomeV1), AttachmentSlotStateError> {
        binding.validate()?;
        let proposed = Record::new(mutation, binding);
        proposed.validate()?;

        let Some(current) = self.current.get(&mutation.slot_id) else {
            if mutation.presence != AttachmentSlotPresenceV1::Available
                || mutation.revision.get() != 1
                || mutation.expected_previous.is_some()
                || self.operations.contains_key(&mutation.operation_id)
            {
                return Err(AttachmentSlotStateError::Conflict);
            }
            self.ensure_capacity()?;
            return Ok((proposed, AttachmentSlotCommitOutcomeV1::Recorded));
        };

        if current == &proposed {
            return Ok((proposed, AttachmentSlotCommitOutcomeV1::Replay));
        }
        if self.operations.contains_key(&mutation.operation_id)
            || current.binding != binding
            || current.presence != AttachmentSlotPresenceV1::Available
            || mutation.presence != AttachmentSlotPresenceV1::Released
            || mutation.revision.get() != 2
            || mutation.expected_previous != Some(ObjectDigest::from_bytes(current.digest))
        {
            return Err(AttachmentSlotStateError::Conflict);
        }
        self.ensure_capacity()?;
        Ok((proposed, AttachmentSlotCommitOutcomeV1::Recorded))
    }

    fn ensure_capacity(&self) -> Result<(), AttachmentSlotStateError> {
        let retained_bytes = self
            .retained_bytes
            .checked_add(24 + RECORD_BYTES)
            .ok_or(AttachmentSlotStateError::Capacity)?;
        if self.revisions.len() >= MAXIMUM_SLOT_RECORDS || retained_bytes > MAXIMUM_NAMESPACE_BYTES
        {
            return Err(AttachmentSlotStateError::Capacity);
        }
        Ok(())
    }
}

pub(crate) fn commit_current<T>(
    journal: &mut Journal,
    target: CurrentNamespaceTarget,
    mutation: AttachmentSlotMutationV1,
    clock: &mut T,
) -> Result<CommittedCurrentAttachmentSlotV1, AttachmentSlotStateError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    target.recheck(journal, clock)?;
    let binding = SlotBinding::from_target(&target);
    let (record, outcome) = commit_bound(journal, &mutation, binding)?;
    target.recheck(journal, clock)?;

    Ok(CommittedCurrentAttachmentSlotV1 {
        target,
        slot: DurableAttachmentSlotV1 { record },
        outcome,
    })
}

fn commit_bound(
    journal: &mut Journal,
    mutation: &AttachmentSlotMutationV1,
    binding: SlotBinding,
) -> Result<(Record, AttachmentSlotCommitOutcomeV1), AttachmentSlotStateError> {
    journal.ensure_healthy()?;
    let history = History::load(journal)?;
    let (record, outcome) = history.select(mutation, binding)?;

    #[cfg(target_os = "linux")]
    if outcome == AttachmentSlotCommitOutcomeV1::Recorded
        && record.presence == AttachmentSlotPresenceV1::Released
    {
        let (has_attachment_history, has_present_attachment) =
            crate::attachment_state::destination_slot_usage(journal, record.slot_id)
                .map_err(|_| AttachmentSlotStateError::CorruptState)?;
        if has_present_attachment
            || (has_attachment_history
                && !crate::mount_attempt::destination_slot_absent_in_fresh_inventory(
                    journal,
                    record.slot_id,
                )
                .map_err(|_| AttachmentSlotStateError::CorruptState)?)
        {
            return Err(AttachmentSlotStateError::Conflict);
        }
    }
    if outcome == AttachmentSlotCommitOutcomeV1::Recorded {
        journal.commit(&record.transaction()?)?;
    }

    let committed = History::load(journal)?;
    if committed
        .revisions
        .get(&(record.slot_id, record.revision.get()))
        != Some(&record)
    {
        return Err(AttachmentSlotStateError::CorruptState);
    }
    Ok((record, outcome))
}

#[cfg(test)]
pub(crate) fn commit_for_test(
    journal: &mut Journal,
    mutation: &AttachmentSlotMutationV1,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    namespace_generation: u64,
) -> Result<(DurableAttachmentSlotV1, AttachmentSlotCommitOutcomeV1), AttachmentSlotStateError> {
    let (record, outcome) = commit_bound(
        journal,
        mutation,
        SlotBinding {
            sandbox,
            incarnation,
            namespace_generation,
        },
    )?;
    Ok((DurableAttachmentSlotV1 { record }, outcome))
}

pub(crate) fn get_current(
    journal: &Journal,
    slot_id: AttachmentSlotId,
) -> Result<Option<DurableAttachmentSlotV1>, AttachmentSlotStateError> {
    let history = History::load(journal)?;
    Ok(history
        .current
        .get(&slot_id)
        .cloned()
        .map(|record| DurableAttachmentSlotV1 { record }))
}

pub(crate) fn validate_namespace(journal: &Journal) -> Result<(), AttachmentSlotStateError> {
    History::load(journal).map(|_| ())
}

pub(crate) fn validate_attachment_reference(
    journal: &Journal,
    intent: &AttachmentIntent,
) -> Result<(), AttachmentSlotStateError> {
    let history = History::load(journal)?;
    let slot = history
        .current
        .get(&intent.destination_slot())
        .filter(|record| {
            record.presence == AttachmentSlotPresenceV1::Available
                && record.binding.matches_intent(intent)
        })
        .ok_or(AttachmentSlotStateError::Conflict)?;
    slot.validate()?;
    Ok(())
}

pub(crate) fn validate_historical_attachment_references<'a>(
    journal: &Journal,
    intents: impl IntoIterator<Item = &'a AttachmentIntent>,
) -> Result<(), AttachmentSlotStateError> {
    let history = History::load(journal)?;
    if intents.into_iter().any(|intent| {
        history
            .revisions
            .get(&(intent.destination_slot(), 1))
            .is_none_or(|record| {
                record.presence != AttachmentSlotPresenceV1::Available
                    || !record.binding.matches_intent(intent)
            })
    }) {
        return Err(AttachmentSlotStateError::CorruptState);
    }
    Ok(())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], AttachmentSlotStateError> {
    let value = bytes
        .get(..N)
        .ok_or(AttachmentSlotStateError::CorruptState)?
        .try_into()
        .map_err(|_| AttachmentSlotStateError::CorruptState)?;
    *bytes = bytes
        .get(N..)
        .ok_or(AttachmentSlotStateError::CorruptState)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        EffectFailure, EffectObservation, EffectPlan, EffectReceipt, Reconciler,
        SingleNodeEffectExecutor,
    };

    struct NoEffects;

    impl SingleNodeEffectExecutor for NoEffects {
        fn observe(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            panic!("attachment-slot tests must not observe effects")
        }

        fn apply(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            panic!("attachment-slot tests must not apply effects")
        }
    }

    fn journal() -> (TempDir, Journal) {
        let directory = TempDir::new().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            Default::default(),
            std::fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap()
        .0;
        (directory, journal)
    }

    fn mutation(
        presence: AttachmentSlotPresenceV1,
        revision: u64,
        expected_previous: Option<ObjectDigest>,
    ) -> AttachmentSlotMutationV1 {
        let byte = u8::try_from(revision).unwrap().checked_add(10).unwrap();
        AttachmentSlotMutationV1::new(
            presence,
            AttachmentSlotId::from_bytes([1; 16]),
            Revision::new(revision),
            OperationId::from_bytes([byte; 16]),
            ObjectDigest::from_bytes([byte.checked_add(20).unwrap(); 32]),
            expected_previous,
        )
        .unwrap()
    }

    fn binding() -> SlotBinding {
        SlotBinding {
            sandbox: SandboxId::from_bytes([2; 16]),
            incarnation: IncarnationId::from_bytes([3; 16]),
            namespace_generation: 4,
        }
    }

    #[test]
    fn creation_release_and_replay_are_exactly_fenced() {
        let (directory, mut journal) = journal();
        let create = mutation(AttachmentSlotPresenceV1::Available, 1, None);
        let (first, outcome) = commit_bound(&mut journal, &create, binding()).unwrap();
        assert_eq!(outcome, AttachmentSlotCommitOutcomeV1::Recorded);
        assert_eq!(
            commit_bound(&mut journal, &create, binding()).unwrap().1,
            AttachmentSlotCommitOutcomeV1::Replay
        );

        let release = mutation(
            AttachmentSlotPresenceV1::Released,
            2,
            Some(ObjectDigest::from_bytes(first.digest)),
        );
        let (_, outcome) = commit_bound(&mut journal, &release, binding()).unwrap();
        assert_eq!(outcome, AttachmentSlotCommitOutcomeV1::Recorded);
        assert_eq!(
            get_current(&journal, AttachmentSlotId::from_bytes([1; 16]))
                .unwrap()
                .unwrap()
                .presence(),
            AttachmentSlotPresenceV1::Released
        );

        journal.compact().unwrap();
        drop(journal);
        let journal = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            Default::default(),
            std::fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap()
        .0;
        assert_eq!(
            get_current(&journal, AttachmentSlotId::from_bytes([1; 16]))
                .unwrap()
                .unwrap()
                .presence(),
            AttachmentSlotPresenceV1::Released
        );
    }

    #[test]
    fn changed_target_stale_release_and_resurrection_fail_closed() {
        let (_directory, mut journal) = journal();
        let create = mutation(AttachmentSlotPresenceV1::Available, 1, None);
        let (first, _) = commit_bound(&mut journal, &create, binding()).unwrap();

        let mut changed_binding = binding();
        changed_binding.namespace_generation += 1;
        assert!(matches!(
            commit_bound(&mut journal, &create, changed_binding),
            Err(AttachmentSlotStateError::Conflict)
        ));
        let stale = mutation(
            AttachmentSlotPresenceV1::Released,
            2,
            Some(ObjectDigest::from_bytes([9; 32])),
        );
        assert!(matches!(
            commit_bound(&mut journal, &stale, binding()),
            Err(AttachmentSlotStateError::Conflict)
        ));

        let release = mutation(
            AttachmentSlotPresenceV1::Released,
            2,
            Some(ObjectDigest::from_bytes(first.digest)),
        );
        commit_bound(&mut journal, &release, binding()).unwrap();
        let resurrection = AttachmentSlotMutationV1::new(
            AttachmentSlotPresenceV1::Available,
            AttachmentSlotId::from_bytes([1; 16]),
            Revision::new(3),
            OperationId::from_bytes([20; 16]),
            ObjectDigest::from_bytes([21; 32]),
            Some(ObjectDigest::from_bytes([22; 32])),
        )
        .unwrap();
        assert!(matches!(
            commit_bound(&mut journal, &resurrection, binding()),
            Err(AttachmentSlotStateError::Conflict)
        ));
    }

    #[test]
    fn codec_rejects_every_changed_and_truncated_byte() {
        let record = Record::new(
            &mutation(AttachmentSlotPresenceV1::Available, 1, None),
            binding(),
        );
        let encoded = record.encode();
        assert_eq!(encoded.len(), RECORD_BYTES);
        assert_eq!(Record::decode(&encoded).unwrap(), record);

        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(Record::decode(&changed).is_err(), "changed byte {index}");
            assert!(Record::decode(&encoded[..index]).is_err(), "length {index}");
        }
    }

    #[test]
    fn operation_ids_are_unique_across_slots() {
        let (_directory, mut journal) = journal();
        let first = mutation(AttachmentSlotPresenceV1::Available, 1, None);
        commit_bound(&mut journal, &first, binding()).unwrap();
        let reused = AttachmentSlotMutationV1::new(
            AttachmentSlotPresenceV1::Available,
            AttachmentSlotId::from_bytes([8; 16]),
            Revision::new(1),
            first.operation_id,
            ObjectDigest::from_bytes([9; 32]),
            None,
        )
        .unwrap();
        assert!(matches!(
            commit_bound(&mut journal, &reused, binding()),
            Err(AttachmentSlotStateError::Conflict)
        ));
    }

    #[test]
    fn malformed_slot_namespace_blocks_reconciliation_startup() {
        let (_directory, mut journal) = journal();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::AttachmentSlot,
                        vec![1; 24],
                        b"corrupt".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            validate_namespace(&journal),
            Err(AttachmentSlotStateError::CorruptState)
        ));
        let mut reconciler = Reconciler::new(journal, NoEffects);
        assert!(matches!(
            reconciler.reconcile_next(),
            Err(crate::ReconcilerError::AttachmentSlot(error))
                if matches!(*error, AttachmentSlotStateError::CorruptState)
        ));
    }
}
