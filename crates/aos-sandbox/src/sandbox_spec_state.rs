//! Persists canonical portable sandbox specifications by content identity.
//!
//! Specifications are immutable content-addressed resources. One bounded
//! journal record retains the canonical bytes, their derived descriptor, and
//! the operation metadata that admitted them:
//!
//! ```text
//! AOSSPS01 | flags:1 | reserved:3 | operation-id:16 |
//! request-digest:32 | spec-bytes:4 | canonical-spec | digest:32
//! ```
//!
//! Destination-slot creation uses this registry to prove that the exact
//! specification named by current assignment authority declared the slot.

use std::collections::BTreeMap;

use aos_sandbox_core::model::SandboxSpec;
use aos_sandbox_core::{
    AttachmentSlotId, DecodeLimits, DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest,
    OperationId, PortableMediaType, decode_sandbox_spec, descriptor_for_bytes, encode_sandbox_spec,
    validate_descriptor_role,
};
use sha2::{Digest as _, Sha256};

use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSSPS01";
const DOMAIN: &[u8] = b"aos.sandbox.specification-state.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.specification-state.transaction.v1\0";
const FIXED_RECORD_BYTES: usize = 96;
const MAXIMUM_SPEC_BYTES: usize = 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = MAXIMUM_SPEC_BYTES + FIXED_RECORD_BYTES;
const MAXIMUM_SPECIFICATIONS: usize = 16_384;
const MAXIMUM_NAMESPACE_BYTES: usize = 256 * 1024 * 1024;

/// Describes one canonical sandbox-specification publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSpecPublicationV1 {
    record: Record,
}

impl SandboxSpecPublicationV1 {
    /// Constructs a content-addressed sandbox-specification publication.
    ///
    /// The specification is encoded and decoded through the closed portable
    /// codec before its descriptor is derived. Publication does not grant
    /// runtime or broker authority.
    ///
    /// # Errors
    ///
    /// Rejects sentinel operation metadata, noncanonical in-memory semantics,
    /// or canonical specification bytes above the fixed one-MiB ceiling.
    pub fn new(
        spec: SandboxSpec,
        operation_id: OperationId,
        request_digest: ObjectDigest,
    ) -> Result<Self, SandboxSpecStateError> {
        if operation_id.as_bytes() == &[0; 16] || request_digest.as_bytes() == &[0; 32] {
            return Err(SandboxSpecStateError::InvalidPublication);
        }

        let spec_bytes = encode_sandbox_spec(&spec);
        if spec_bytes.is_empty() || spec_bytes.len() > MAXIMUM_SPEC_BYTES {
            return Err(SandboxSpecStateError::Capacity);
        }
        if !matches!(
            decode_sandbox_spec(&spec_bytes, DecodeLimits::default()),
            Ok(decoded) if decoded == spec
        ) {
            return Err(SandboxSpecStateError::InvalidPublication);
        }

        let descriptor = descriptor_for(&spec_bytes)?;
        let mut record = Record {
            operation_id,
            request_digest,
            spec_bytes,
            spec,
            descriptor,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate()?;

        Ok(Self { record })
    }

    /// Borrows the derived portable specification descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.record.descriptor
    }
}

/// Reports whether an exact sandbox-specification publication committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxSpecCommitOutcomeV1 {
    /// The immutable specification became durable in this call.
    Recorded,
    /// The exact operation and canonical specification were already durable.
    Replay,
}

/// Exposes one validated durable portable sandbox specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSandboxSpecV1 {
    record: Record,
}

impl DurableSandboxSpecV1 {
    /// Borrows the validated portable specification semantics.
    #[must_use]
    pub const fn spec(&self) -> &SandboxSpec {
        &self.record.spec
    }

    /// Borrows the exact canonical bytes from which the descriptor was derived.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.record.spec_bytes
    }

    /// Borrows the content descriptor derived from the canonical bytes.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.record.descriptor
    }

    /// Returns the operation that admitted this specification.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.record.operation_id
    }

    /// Returns the normalized publication request digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.record.request_digest
    }

    /// Returns the immutable journal record digest.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }
}

/// Reports invalid specification state, conflicts, or durability failures.
#[derive(Debug, thiserror::Error)]
pub enum SandboxSpecStateError {
    /// A caller supplied sentinel or noncanonical publication semantics.
    #[error("sandbox-specification publication is invalid")]
    InvalidPublication,
    /// A descriptor or operation conflicts with immutable retained state.
    #[error("sandbox-specification publication conflicts with current state")]
    Conflict,
    /// Stored bytes, keys, or derived descriptors violate the closed schema.
    #[error("sandbox-specification state is corrupt")]
    CorruptState,
    /// Specification count, object size, or retained bytes exceed a fixed ceiling.
    #[error("sandbox-specification state capacity is exhausted")]
    Capacity,
    /// The durable journal rejected the transaction.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    operation_id: OperationId,
    request_digest: ObjectDigest,
    spec_bytes: Vec<u8>,
    spec: SandboxSpec,
    descriptor: ObjectDescriptor,
    digest: [u8; 32],
}

impl Record {
    fn key(&self) -> Vec<u8> {
        descriptor_key(&self.descriptor)
    }

    fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES.saturating_add(self.spec_bytes.len())
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.operation_id.as_bytes());
        digest.update(self.request_digest.as_bytes());
        digest.update((self.spec_bytes.len() as u64).to_be_bytes());
        digest.update(&self.spec_bytes);
        digest.finalize().into()
    }

    fn validate(&self) -> Result<(), SandboxSpecStateError> {
        if self.operation_id.as_bytes() == &[0; 16]
            || self.request_digest.as_bytes() == &[0; 32]
            || self.spec_bytes.is_empty()
            || self.spec_bytes.len() > MAXIMUM_SPEC_BYTES
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || encode_sandbox_spec(&self.spec) != self.spec_bytes
            || descriptor_for(&self.spec_bytes)? != self.descriptor
            || self.compute_digest() != self.digest
        {
            return Err(SandboxSpecStateError::CorruptState);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(self.operation_id.as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(&(self.spec_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.spec_bytes);
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, SandboxSpecStateError> {
        if bytes.len() < FIXED_RECORD_BYTES || bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(SandboxSpecStateError::CorruptState);
        }

        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC || take::<4>(&mut bytes)? != [0; 4] {
            return Err(SandboxSpecStateError::CorruptState);
        }
        let operation_id = OperationId::from_bytes(take(&mut bytes)?);
        let request_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
        let spec_length = u32::from_be_bytes(take(&mut bytes)?) as usize;
        if spec_length == 0 || spec_length > MAXIMUM_SPEC_BYTES {
            return Err(SandboxSpecStateError::CorruptState);
        }
        let spec_bytes = bytes
            .get(..spec_length)
            .ok_or(SandboxSpecStateError::CorruptState)?
            .to_vec();
        bytes = bytes
            .get(spec_length..)
            .ok_or(SandboxSpecStateError::CorruptState)?;
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(SandboxSpecStateError::CorruptState);
        }

        let spec = decode_sandbox_spec(&spec_bytes, DecodeLimits::default())
            .map_err(|_| SandboxSpecStateError::CorruptState)?;
        let descriptor = descriptor_for(&spec_bytes)?;
        let record = Self {
            operation_id,
            request_digest,
            spec_bytes,
            spec,
            descriptor,
            digest,
        };
        record.validate()?;

        Ok(record)
    }

    fn transaction(&self) -> Result<JournalTransaction, SandboxSpecStateError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| SandboxSpecStateError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::SandboxSpec,
                self.key(),
                self.encode(),
            )],
        )?)
    }
}

#[derive(Default)]
struct History {
    specifications: BTreeMap<([u8; 32], u64), Record>,
    operations: BTreeMap<OperationId, ([u8; 32], u64)>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &Journal) -> Result<Self, SandboxSpecStateError> {
        let mut history = Self::default();

        for (key, value) in journal.records(RecordNamespace::SandboxSpec) {
            if key.len() != 40 || value.len() > MAXIMUM_RECORD_BYTES {
                return Err(SandboxSpecStateError::CorruptState);
            }
            if history.specifications.len() >= MAXIMUM_SPECIFICATIONS {
                return Err(SandboxSpecStateError::Capacity);
            }
            history.retained_bytes = history
                .retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(SandboxSpecStateError::Capacity)?;
            if history.retained_bytes > MAXIMUM_NAMESPACE_BYTES {
                return Err(SandboxSpecStateError::Capacity);
            }

            let record = Record::decode(value)?;
            if key != record.key() {
                return Err(SandboxSpecStateError::CorruptState);
            }
            let descriptor_key = descriptor_tuple(&record.descriptor);
            if history
                .operations
                .insert(record.operation_id, descriptor_key)
                .is_some()
                || history
                    .specifications
                    .insert(descriptor_key, record)
                    .is_some()
            {
                return Err(SandboxSpecStateError::CorruptState);
            }
        }

        Ok(history)
    }

    fn select(
        &self,
        publication: &SandboxSpecPublicationV1,
    ) -> Result<SandboxSpecCommitOutcomeV1, SandboxSpecStateError> {
        let record = &publication.record;
        let key = descriptor_tuple(&record.descriptor);
        if let Some(current) = self.specifications.get(&key) {
            return if current == record {
                Ok(SandboxSpecCommitOutcomeV1::Replay)
            } else {
                Err(SandboxSpecStateError::Conflict)
            };
        }
        if self.operations.contains_key(&record.operation_id) {
            return Err(SandboxSpecStateError::Conflict);
        }
        self.ensure_capacity(record)?;
        Ok(SandboxSpecCommitOutcomeV1::Recorded)
    }

    fn ensure_capacity(&self, record: &Record) -> Result<(), SandboxSpecStateError> {
        let retained_bytes = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(SandboxSpecStateError::Capacity)?;
        if self.specifications.len() >= MAXIMUM_SPECIFICATIONS
            || retained_bytes > MAXIMUM_NAMESPACE_BYTES
        {
            return Err(SandboxSpecStateError::Capacity);
        }
        Ok(())
    }
}

pub(crate) fn commit(
    journal: &mut Journal,
    publication: SandboxSpecPublicationV1,
) -> Result<(DurableSandboxSpecV1, SandboxSpecCommitOutcomeV1), SandboxSpecStateError> {
    journal.ensure_healthy()?;
    let history = History::load(journal)?;
    let outcome = history.select(&publication)?;
    if outcome == SandboxSpecCommitOutcomeV1::Recorded {
        journal.commit(&publication.record.transaction()?)?;
    }

    let committed = History::load(journal)?;
    if committed
        .specifications
        .get(&descriptor_tuple(&publication.record.descriptor))
        != Some(&publication.record)
    {
        return Err(SandboxSpecStateError::CorruptState);
    }

    Ok((
        DurableSandboxSpecV1 {
            record: publication.record,
        },
        outcome,
    ))
}

pub(crate) fn get(
    journal: &Journal,
    descriptor: &ObjectDescriptor,
) -> Result<Option<DurableSandboxSpecV1>, SandboxSpecStateError> {
    validate_spec_descriptor(descriptor)?;
    let history = History::load(journal)?;
    Ok(history
        .specifications
        .get(&descriptor_tuple(descriptor))
        .cloned()
        .map(|record| DurableSandboxSpecV1 { record }))
}

/// Reads one specification after the caller has validated the complete namespace.
pub(crate) fn get_in_validated_namespace(
    journal: &Journal,
    descriptor: &ObjectDescriptor,
) -> Result<Option<DurableSandboxSpecV1>, SandboxSpecStateError> {
    validate_spec_descriptor(descriptor)?;
    journal
        .get(RecordNamespace::SandboxSpec, &descriptor_key(descriptor))
        .map(Record::decode)
        .transpose()
        .map(|record| record.map(|record| DurableSandboxSpecV1 { record }))
}

pub(crate) fn validate_namespace(journal: &Journal) -> Result<(), SandboxSpecStateError> {
    History::load(journal).map(|_| ())
}

pub(crate) fn validate_slot_declaration(
    journal: &Journal,
    descriptor: &ObjectDescriptor,
    slot_id: AttachmentSlotId,
) -> Result<(), SandboxSpecStateError> {
    let history = History::load(journal)?;
    let record = history
        .specifications
        .get(&validated_descriptor_tuple(descriptor)?)
        .ok_or(SandboxSpecStateError::Conflict)?;
    if record
        .spec
        .attachment_slots()
        .binary_search(&slot_id)
        .is_err()
    {
        return Err(SandboxSpecStateError::Conflict);
    }
    Ok(())
}

pub(crate) fn validate_historical_slot_declarations<'a>(
    journal: &Journal,
    declarations: impl IntoIterator<Item = (&'a ObjectDescriptor, AttachmentSlotId)>,
) -> Result<(), SandboxSpecStateError> {
    let history = History::load(journal)?;
    for (descriptor, slot_id) in declarations {
        let key = validated_descriptor_tuple(descriptor)
            .map_err(|_| SandboxSpecStateError::CorruptState)?;
        let Some(record) = history.specifications.get(&key) else {
            return Err(SandboxSpecStateError::CorruptState);
        };
        if record
            .spec
            .attachment_slots()
            .binary_search(&slot_id)
            .is_err()
        {
            return Err(SandboxSpecStateError::CorruptState);
        }
    }
    Ok(())
}

fn descriptor_for(bytes: &[u8]) -> Result<ObjectDescriptor, SandboxSpecStateError> {
    let media_type = MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned())
        .map_err(|_| SandboxSpecStateError::CorruptState)?;
    Ok(descriptor_for_bytes(media_type, bytes))
}

pub(crate) fn validate_spec_descriptor(
    descriptor: &ObjectDescriptor,
) -> Result<(), SandboxSpecStateError> {
    if validate_descriptor_role(DescriptorRole::SnapshotSpec, descriptor).is_err()
        || descriptor.digest().as_bytes() == &[0; 32]
        || descriptor.encoded_size() == 0
    {
        return Err(SandboxSpecStateError::InvalidPublication);
    }
    Ok(())
}

fn validated_descriptor_tuple(
    descriptor: &ObjectDescriptor,
) -> Result<([u8; 32], u64), SandboxSpecStateError> {
    validate_spec_descriptor(descriptor)?;
    Ok(descriptor_tuple(descriptor))
}

fn descriptor_tuple(descriptor: &ObjectDescriptor) -> ([u8; 32], u64) {
    (*descriptor.digest().as_bytes(), descriptor.encoded_size())
}

fn descriptor_key(descriptor: &ObjectDescriptor) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(descriptor.digest().as_bytes());
    key.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    key
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], SandboxSpecStateError> {
    let value = bytes
        .get(..N)
        .ok_or(SandboxSpecStateError::CorruptState)?
        .try_into()
        .map_err(|_| SandboxSpecStateError::CorruptState)?;
    *bytes = bytes.get(N..).ok_or(SandboxSpecStateError::CorruptState)?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn slot_spec_publication_for_test(
    slot_ids: Vec<AttachmentSlotId>,
    byte: u8,
) -> SandboxSpecPublicationV1 {
    SandboxSpecPublicationV1::new(
        tests::spec(slot_ids),
        OperationId::from_bytes([byte.wrapping_add(80); 16]),
        ObjectDigest::from_bytes([byte.wrapping_add(100); 32]),
    )
    .unwrap()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn publish_slot_spec_for_test(
    journal: &mut Journal,
    slot_id: AttachmentSlotId,
) -> ObjectDescriptor {
    let publication = slot_spec_publication_for_test(vec![slot_id], slot_id.as_bytes()[0]);
    let descriptor = publication.descriptor().clone();
    commit(journal, publication).unwrap();
    descriptor
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::num::NonZeroU32;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        EffectFailure, EffectObservation, EffectPlan, EffectReceipt, Reconciler,
        SingleNodeEffectExecutor,
    };
    use aos_sandbox_core::FeatureRef;
    use aos_sandbox_core::model::{
        IdentityProfile, NetworkKind, NetworkProfile, ResourceProfile, UnmappableIdentityPolicy,
    };

    struct NoEffects;

    impl SingleNodeEffectExecutor for NoEffects {
        fn observe(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            panic!("sandbox-specification tests must not observe effects")
        }

        fn apply(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            panic!("sandbox-specification tests must not apply effects")
        }
    }

    fn journal() -> (TempDir, Journal) {
        let directory = TempDir::new().unwrap();
        let journal = Journal::open(
            directory.path().join("controller.journal"),
            Default::default(),
        )
        .unwrap()
        .0;
        (directory, journal)
    }

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    pub(super) fn spec(slots: Vec<AttachmentSlotId>) -> SandboxSpec {
        SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(Vec::new()).unwrap(),
            descriptor(PortableMediaType::Environment, 1),
            descriptor(PortableMediaType::View, 2),
            slots,
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    fn publication(byte: u8, slots: Vec<AttachmentSlotId>) -> SandboxSpecPublicationV1 {
        SandboxSpecPublicationV1::new(
            spec(slots),
            OperationId::from_bytes([byte; 16]),
            ObjectDigest::from_bytes([byte.wrapping_add(20); 32]),
        )
        .unwrap()
    }

    #[test]
    fn publication_replay_compaction_and_lookup_are_content_exact() {
        let (directory, mut journal) = journal();
        let publication = publication(3, vec![AttachmentSlotId::from_bytes([4; 16])]);
        let descriptor = publication.descriptor().clone();
        let (durable, outcome) = commit(&mut journal, publication.clone()).unwrap();
        assert_eq!(outcome, SandboxSpecCommitOutcomeV1::Recorded);
        assert_eq!(durable.descriptor(), &descriptor);
        assert_eq!(
            commit(&mut journal, publication).unwrap().1,
            SandboxSpecCommitOutcomeV1::Replay
        );

        journal.compact().unwrap();
        drop(journal);
        let journal = Journal::open(
            directory.path().join("controller.journal"),
            Default::default(),
        )
        .unwrap()
        .0;
        assert_eq!(get(&journal, &descriptor).unwrap().unwrap(), durable);
    }

    #[test]
    fn descriptor_and_operation_conflicts_fail_closed() {
        let (_directory, mut journal) = journal();
        let first = publication(3, vec![AttachmentSlotId::from_bytes([4; 16])]);
        commit(&mut journal, first.clone()).unwrap();

        let same_spec_other_operation = SandboxSpecPublicationV1::new(
            first.record.spec.clone(),
            OperationId::from_bytes([5; 16]),
            ObjectDigest::from_bytes([6; 32]),
        )
        .unwrap();
        assert!(matches!(
            commit(&mut journal, same_spec_other_operation),
            Err(SandboxSpecStateError::Conflict)
        ));

        let reused_operation = SandboxSpecPublicationV1::new(
            spec(vec![AttachmentSlotId::from_bytes([7; 16])]),
            first.record.operation_id,
            ObjectDigest::from_bytes([8; 32]),
        )
        .unwrap();
        assert!(matches!(
            commit(&mut journal, reused_operation),
            Err(SandboxSpecStateError::Conflict)
        ));
    }

    #[test]
    fn codec_rejects_every_changed_and_truncated_byte() {
        let record = publication(3, vec![AttachmentSlotId::from_bytes([4; 16])]).record;
        let encoded = record.encode();
        assert_eq!(Record::decode(&encoded).unwrap(), record);

        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(Record::decode(&changed).is_err(), "changed byte {index}");
            assert!(Record::decode(&encoded[..index]).is_err(), "length {index}");
        }
    }

    #[test]
    fn slot_declaration_requires_the_exact_published_specification() {
        let (_directory, mut journal) = journal();
        let declared = AttachmentSlotId::from_bytes([4; 16]);
        let absent = AttachmentSlotId::from_bytes([5; 16]);
        let publication = publication(3, vec![declared]);
        let descriptor = publication.descriptor().clone();

        assert!(matches!(
            validate_slot_declaration(&journal, &descriptor, declared),
            Err(SandboxSpecStateError::Conflict)
        ));
        commit(&mut journal, publication).unwrap();
        validate_slot_declaration(&journal, &descriptor, declared).unwrap();
        assert!(matches!(
            validate_slot_declaration(&journal, &descriptor, absent),
            Err(SandboxSpecStateError::Conflict)
        ));
    }

    #[test]
    fn malformed_specification_namespace_blocks_reconciliation_startup() {
        let (_directory, mut journal) = journal();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::SandboxSpec,
                        vec![1; 40],
                        b"corrupt".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            validate_namespace(&journal),
            Err(SandboxSpecStateError::CorruptState)
        ));
        let mut reconciler = Reconciler::new(journal, NoEffects);
        assert!(matches!(
            reconciler.reconcile_next(),
            Err(crate::ReconcilerError::SandboxSpec(error))
                if matches!(*error, SandboxSpecStateError::CorruptState)
        ));
    }

    #[test]
    fn publication_rejects_sentinel_operation_metadata() {
        let valid_spec = spec(vec![AttachmentSlotId::from_bytes([4; 16])]);
        assert!(matches!(
            SandboxSpecPublicationV1::new(
                valid_spec.clone(),
                OperationId::from_bytes([0; 16]),
                ObjectDigest::from_bytes([1; 32]),
            ),
            Err(SandboxSpecStateError::InvalidPublication)
        ));
        assert!(matches!(
            SandboxSpecPublicationV1::new(
                valid_spec,
                OperationId::from_bytes([1; 16]),
                ObjectDigest::from_bytes([0; 32]),
            ),
            Err(SandboxSpecStateError::InvalidPublication)
        ));
    }
}
