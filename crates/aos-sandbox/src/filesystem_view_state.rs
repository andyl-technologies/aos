//! Persists immutable filesystem-view revisions and exact source handles.
//!
//! One append-only record binds a logical view identity and revision to the
//! canonical portable [`View`] bytes that describe its source. Successor
//! records form a digest-linked chain, so a caller cannot replace historical
//! semantics or release a different source:
//!
//! ```text
//! AOSVRS01 | presence:1 | flags:1 | reserved:2 | view-id:16 |
//! revision:8 | operation-id:16 | request-digest:32 |
//! predecessor-digest:32 | view-bytes:4 | canonical-view | digest:32
//! ```
//!
//! The portable view's [`ViewSource`] is the durable logical source handle.
//! It remains free of host paths and OS descriptors: a later node-local
//! realizer must resolve it through separately authorized broker state.

use std::collections::BTreeMap;

use aos_sandbox_core::model::{AttachmentConsistency, AttachmentIntent, View, ViewSource};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, OperationId, PortableMediaType, Revision, ViewId,
    decode_view, descriptor_for_bytes, encode_view,
};
use sha2::{Digest as _, Sha256};

use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSVRS01";
const DOMAIN: &[u8] = b"aos.sandbox.filesystem-view-revision.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.filesystem-view-revision.transaction.v1\0";
const FIXED_RECORD_BYTES: usize = 152;
const FLAG_EXPECTED_PREVIOUS: u8 = 1;
const MAXIMUM_VIEW_BYTES: usize = 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = MAXIMUM_VIEW_BYTES + FIXED_RECORD_BYTES;
const MAXIMUM_VIEW_REVISIONS: usize = 65_536;
const MAXIMUM_NAMESPACE_BYTES: usize = 256 * 1024 * 1024;

/// Selects whether a filesystem-view revision is available or released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FilesystemViewRevisionPresenceV1 {
    /// Makes the exact immutable revision available for attachment.
    Available = 1,
    /// Permanently releases the logical view after its attachments drain.
    Released = 2,
}

impl FilesystemViewRevisionPresenceV1 {
    fn from_byte(value: u8) -> Result<Self, FilesystemViewRevisionStateError> {
        match value {
            1 => Ok(Self::Available),
            2 => Ok(Self::Released),
            _ => Err(FilesystemViewRevisionStateError::CorruptState),
        }
    }
}

/// Describes one generation-fenced filesystem-view revision mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemViewRevisionMutationV1 {
    record: Record,
}

impl FilesystemViewRevisionMutationV1 {
    /// Constructs an immutable view-revision publication or release tombstone.
    ///
    /// Revision one supplies no predecessor. Every successor supplies the
    /// record digest returned for the preceding revision. A release carries
    /// the preceding canonical view unchanged and permanently closes the
    /// logical identity.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, revision zero, an invalid source handle,
    /// oversized canonical bytes, or invalid operation metadata. Chain and
    /// release-transition checks occur atomically during commit.
    pub fn new(
        presence: FilesystemViewRevisionPresenceV1,
        view_id: ViewId,
        revision: Revision,
        view: View,
        operation_id: OperationId,
        request_digest: ObjectDigest,
        expected_previous: Option<ObjectDigest>,
    ) -> Result<Self, FilesystemViewRevisionStateError> {
        if view_id.as_bytes() == &[0; 16]
            || revision.get() == 0
            || operation_id.as_bytes() == &[0; 16]
            || request_digest.as_bytes() == &[0; 32]
            || expected_previous.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || !source_handle_is_specified(view.source())
        {
            return Err(FilesystemViewRevisionStateError::InvalidMutation);
        }

        let view_bytes = encode_view(&view);
        if view_bytes.is_empty() || view_bytes.len() > MAXIMUM_VIEW_BYTES {
            return Err(FilesystemViewRevisionStateError::Capacity);
        }
        if !matches!(
            decode_view(&view_bytes, aos_sandbox_core::DecodeLimits::default()),
            Ok(decoded) if decoded == view
        ) {
            return Err(FilesystemViewRevisionStateError::InvalidMutation);
        }
        let descriptor = descriptor_for(&view_bytes)?;

        let mut record = Record {
            presence,
            view_id,
            revision,
            operation_id,
            request_digest,
            expected_previous,
            view_bytes,
            view,
            descriptor,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate()?;

        Ok(Self { record })
    }

    /// Returns the logical view changed by this mutation.
    #[must_use]
    pub const fn view_id(&self) -> ViewId {
        self.record.view_id
    }

    /// Returns the immutable revision changed by this mutation.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.record.revision
    }

    /// Returns the expected current resource version, if this is a successor.
    #[must_use]
    pub const fn expected_previous(&self) -> Option<ObjectDigest> {
        self.record.expected_previous
    }
}

/// Reports whether an exact view-revision mutation committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemViewRevisionCommitOutcomeV1 {
    /// The mutation became durable in this call.
    Recorded,
    /// The exact operation and revision bytes were already durable.
    Replay,
}

/// Exposes one validated durable filesystem-view revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFilesystemViewRevisionV1 {
    record: Record,
}

impl DurableFilesystemViewRevisionV1 {
    /// Returns whether this revision is available or is a release tombstone.
    #[must_use]
    pub const fn presence(&self) -> FilesystemViewRevisionPresenceV1 {
        self.record.presence
    }

    /// Returns the logical view identity.
    #[must_use]
    pub const fn view_id(&self) -> ViewId {
        self.record.view_id
    }

    /// Returns this immutable revision number.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.record.revision
    }

    /// Borrows the canonical portable view semantics.
    #[must_use]
    pub const fn view(&self) -> &View {
        &self.record.view
    }

    /// Borrows the path-free logical source handle committed by this revision.
    #[must_use]
    pub const fn source_handle(&self) -> &ViewSource {
        self.record.view.source()
    }

    /// Returns the exact portable descriptor named by attachment intent.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.record.descriptor
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

/// Reports invalid view state, conflicting mutations, or durability failures.
#[derive(Debug, thiserror::Error)]
pub enum FilesystemViewRevisionStateError {
    /// A caller supplied sentinel or structurally incomplete mutation metadata.
    #[error("filesystem-view revision mutation is invalid")]
    InvalidMutation,
    /// The expected revision, resource version, or transition conflicts.
    #[error("filesystem-view revision mutation conflicts with current state")]
    Conflict,
    /// Reserved revision bytes violate their closed schema or chain invariants.
    #[error("filesystem-view revision state is corrupt")]
    CorruptState,
    /// Revision count or retained bytes exceed the fixed controller ceiling.
    #[error("filesystem-view revision capacity is exhausted")]
    Capacity,
    /// The durable journal rejected the transaction.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    presence: FilesystemViewRevisionPresenceV1,
    view_id: ViewId,
    revision: Revision,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    expected_previous: Option<ObjectDigest>,
    view_bytes: Vec<u8>,
    view: View,
    descriptor: ObjectDescriptor,
    digest: [u8; 32],
}

impl Record {
    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(self.view_id.as_bytes());
        key.extend_from_slice(&self.revision.get().to_be_bytes());
        key
    }

    fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES.saturating_add(self.view_bytes.len())
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update([self.presence as u8]);
        digest.update(self.view_id.as_bytes());
        digest.update(self.revision.get().to_be_bytes());
        digest.update(self.operation_id.as_bytes());
        digest.update(self.request_digest.as_bytes());
        digest.update([u8::from(self.expected_previous.is_some())]);
        digest.update(
            self.expected_previous
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        digest.update((self.view_bytes.len() as u64).to_be_bytes());
        digest.update(&self.view_bytes);
        digest.finalize().into()
    }

    fn validate(&self) -> Result<(), FilesystemViewRevisionStateError> {
        if self.view_id.as_bytes() == &[0; 16]
            || self.revision.get() == 0
            || self.operation_id.as_bytes() == &[0; 16]
            || self.request_digest.as_bytes() == &[0; 32]
            || self
                .expected_previous
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || self.view_bytes.is_empty()
            || self.view_bytes.len() > MAXIMUM_VIEW_BYTES
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || !source_handle_is_specified(self.view.source())
            || encode_view(&self.view) != self.view_bytes
            || descriptor_for(&self.view_bytes)? != self.descriptor
            || self.compute_digest() != self.digest
        {
            return Err(FilesystemViewRevisionStateError::CorruptState);
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
        bytes.extend_from_slice(self.view_id.as_bytes());
        bytes.extend_from_slice(&self.revision.get().to_be_bytes());
        bytes.extend_from_slice(self.operation_id.as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(
            &self
                .expected_previous
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        bytes.extend_from_slice(&(self.view_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.view_bytes);
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, FilesystemViewRevisionStateError> {
        if bytes.len() < FIXED_RECORD_BYTES || bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(FilesystemViewRevisionStateError::CorruptState);
        }

        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC {
            return Err(FilesystemViewRevisionStateError::CorruptState);
        }
        let presence = FilesystemViewRevisionPresenceV1::from_byte(take::<1>(&mut bytes)?[0])?;
        let flags = take::<1>(&mut bytes)?[0];
        if flags & !FLAG_EXPECTED_PREVIOUS != 0 || take::<2>(&mut bytes)? != [0; 2] {
            return Err(FilesystemViewRevisionStateError::CorruptState);
        }
        let view_id = ViewId::from_bytes(take(&mut bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        let operation_id = OperationId::from_bytes(take(&mut bytes)?);
        let request_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
        let expected_previous_bytes = take::<32>(&mut bytes)?;
        let expected_previous = match (flags & FLAG_EXPECTED_PREVIOUS != 0, expected_previous_bytes)
        {
            (false, bytes) if bytes == [0; 32] => None,
            (true, bytes) if bytes != [0; 32] => Some(ObjectDigest::from_bytes(bytes)),
            _ => return Err(FilesystemViewRevisionStateError::CorruptState),
        };
        let view_length = u32::from_be_bytes(take(&mut bytes)?) as usize;
        if view_length == 0 || view_length > MAXIMUM_VIEW_BYTES {
            return Err(FilesystemViewRevisionStateError::CorruptState);
        }
        let view_bytes = bytes
            .get(..view_length)
            .ok_or(FilesystemViewRevisionStateError::CorruptState)?
            .to_vec();
        bytes = bytes
            .get(view_length..)
            .ok_or(FilesystemViewRevisionStateError::CorruptState)?;
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(FilesystemViewRevisionStateError::CorruptState);
        }
        let view = decode_view(&view_bytes, aos_sandbox_core::DecodeLimits::default())
            .map_err(|_| FilesystemViewRevisionStateError::CorruptState)?;
        let descriptor = descriptor_for(&view_bytes)?;
        let record = Self {
            presence,
            view_id,
            revision,
            operation_id,
            request_digest,
            expected_previous,
            view_bytes,
            view,
            descriptor,
            digest,
        };
        record.validate()?;

        Ok(record)
    }

    fn transaction(&self) -> Result<JournalTransaction, FilesystemViewRevisionStateError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| FilesystemViewRevisionStateError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::FilesystemViewRevision,
                self.key(),
                self.encode(),
            )],
        )?)
    }
}

#[derive(Default)]
struct History {
    current: BTreeMap<ViewId, Record>,
    revisions: BTreeMap<(ViewId, u64), Record>,
    operations: BTreeMap<OperationId, (ViewId, u64)>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &Journal) -> Result<Self, FilesystemViewRevisionStateError> {
        let mut current: BTreeMap<ViewId, Record> = BTreeMap::new();
        let mut revisions = BTreeMap::new();
        let mut operations = BTreeMap::new();
        let mut retained_bytes = 0_usize;

        for (key, value) in journal.records(RecordNamespace::FilesystemViewRevision) {
            if key.len() != 24 {
                return Err(FilesystemViewRevisionStateError::CorruptState);
            }
            if revisions.len() >= MAXIMUM_VIEW_REVISIONS || value.len() > MAXIMUM_RECORD_BYTES {
                return Err(FilesystemViewRevisionStateError::Capacity);
            }
            retained_bytes = retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(FilesystemViewRevisionStateError::Capacity)?;
            if retained_bytes > MAXIMUM_NAMESPACE_BYTES {
                return Err(FilesystemViewRevisionStateError::Capacity);
            }

            let record = Record::decode(value)?;
            if key != record.key() {
                return Err(FilesystemViewRevisionStateError::CorruptState);
            }
            let revision_key = (record.view_id, record.revision.get());
            if operations
                .insert(record.operation_id, revision_key)
                .is_some()
                || revisions.insert(revision_key, record).is_some()
            {
                return Err(FilesystemViewRevisionStateError::CorruptState);
            }
        }

        for ((view_id, revision), record) in &revisions {
            match current.get(view_id) {
                None if *revision == 1
                    && record.presence == FilesystemViewRevisionPresenceV1::Available
                    && record.expected_previous.is_none() => {}
                Some(previous)
                    if previous.revision.get().checked_add(1) == Some(*revision)
                        && previous.presence == FilesystemViewRevisionPresenceV1::Available
                        && record.expected_previous
                            == Some(ObjectDigest::from_bytes(previous.digest))
                        && (record.presence != FilesystemViewRevisionPresenceV1::Released
                            || record.view_bytes == previous.view_bytes) => {}
                _ => return Err(FilesystemViewRevisionStateError::CorruptState),
            }
            current.insert(*view_id, record.clone());
        }

        Ok(Self {
            current,
            revisions,
            operations,
            retained_bytes,
        })
    }

    fn validate_mutation(
        &self,
        mutation: &FilesystemViewRevisionMutationV1,
    ) -> Result<FilesystemViewRevisionCommitOutcomeV1, FilesystemViewRevisionStateError> {
        let proposed = &mutation.record;
        let Some(current) = self.current.get(&proposed.view_id) else {
            if proposed.expected_previous.is_some()
                || proposed.presence != FilesystemViewRevisionPresenceV1::Available
                || proposed.revision.get() != 1
                || self.operations.contains_key(&proposed.operation_id)
            {
                return Err(FilesystemViewRevisionStateError::Conflict);
            }
            self.ensure_capacity(proposed)?;
            return Ok(FilesystemViewRevisionCommitOutcomeV1::Recorded);
        };

        if current == proposed {
            return Ok(FilesystemViewRevisionCommitOutcomeV1::Replay);
        }
        if self.operations.contains_key(&proposed.operation_id)
            || current.presence == FilesystemViewRevisionPresenceV1::Released
            || proposed.expected_previous != Some(ObjectDigest::from_bytes(current.digest))
            || proposed.revision.get()
                != current
                    .revision
                    .get()
                    .checked_add(1)
                    .ok_or(FilesystemViewRevisionStateError::Capacity)?
            || (proposed.presence == FilesystemViewRevisionPresenceV1::Released
                && proposed.view_bytes != current.view_bytes)
        {
            return Err(FilesystemViewRevisionStateError::Conflict);
        }
        self.ensure_capacity(proposed)?;

        Ok(FilesystemViewRevisionCommitOutcomeV1::Recorded)
    }

    fn ensure_capacity(&self, record: &Record) -> Result<(), FilesystemViewRevisionStateError> {
        let retained_bytes = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(FilesystemViewRevisionStateError::Capacity)?;
        if self.revisions.len() >= MAXIMUM_VIEW_REVISIONS
            || retained_bytes > MAXIMUM_NAMESPACE_BYTES
        {
            return Err(FilesystemViewRevisionStateError::Capacity);
        }

        Ok(())
    }
}

pub(crate) fn commit(
    journal: &mut Journal,
    mutation: FilesystemViewRevisionMutationV1,
) -> Result<
    (
        DurableFilesystemViewRevisionV1,
        FilesystemViewRevisionCommitOutcomeV1,
    ),
    FilesystemViewRevisionStateError,
> {
    journal.ensure_healthy()?;
    let history = History::load(journal)?;
    let outcome = history.validate_mutation(&mutation)?;
    #[cfg(target_os = "linux")]
    if outcome == FilesystemViewRevisionCommitOutcomeV1::Recorded
        && mutation.record.presence == FilesystemViewRevisionPresenceV1::Released
    {
        let (has_attachment_history, has_present_attachment) =
            crate::attachment_state::source_view_usage(journal, mutation.record.view_id)
                .map_err(|_| FilesystemViewRevisionStateError::CorruptState)?;
        if has_present_attachment
            || (has_attachment_history
                && !crate::mount_attempt::source_view_absent_in_fresh_inventory(
                    journal,
                    mutation.record.view_id,
                )
                .map_err(|_| FilesystemViewRevisionStateError::CorruptState)?)
        {
            return Err(FilesystemViewRevisionStateError::Conflict);
        }
    }
    if outcome == FilesystemViewRevisionCommitOutcomeV1::Recorded {
        journal.commit(&mutation.record.transaction()?)?;
    }

    let committed = History::load(journal)?;
    if committed
        .revisions
        .get(&(mutation.record.view_id, mutation.record.revision.get()))
        != Some(&mutation.record)
    {
        return Err(FilesystemViewRevisionStateError::CorruptState);
    }

    Ok((
        DurableFilesystemViewRevisionV1 {
            record: mutation.record,
        },
        outcome,
    ))
}

pub(crate) fn get_current(
    journal: &Journal,
    view_id: ViewId,
) -> Result<Option<DurableFilesystemViewRevisionV1>, FilesystemViewRevisionStateError> {
    let history = History::load(journal)?;
    Ok(history
        .current
        .get(&view_id)
        .cloned()
        .map(|record| DurableFilesystemViewRevisionV1 { record }))
}

pub(crate) fn get_revision(
    journal: &Journal,
    view_id: ViewId,
    revision: Revision,
) -> Result<Option<DurableFilesystemViewRevisionV1>, FilesystemViewRevisionStateError> {
    let history = History::load(journal)?;
    Ok(history
        .revisions
        .get(&(view_id, revision.get()))
        .cloned()
        .map(|record| DurableFilesystemViewRevisionV1 { record }))
}

pub(crate) fn validate_namespace(
    journal: &Journal,
) -> Result<(), FilesystemViewRevisionStateError> {
    History::load(journal).map(|_| ())
}

pub(crate) fn validate_attachment_reference(
    journal: &Journal,
    intent: &AttachmentIntent,
) -> Result<(), FilesystemViewRevisionStateError> {
    let history = History::load(journal)?;
    if !attachment_reference_matches(&history, intent)
        || history
            .current
            .get(&intent.source_view().0)
            .is_none_or(|record| record.presence != FilesystemViewRevisionPresenceV1::Available)
    {
        return Err(FilesystemViewRevisionStateError::Conflict);
    }

    Ok(())
}

pub(crate) fn validate_historical_attachment_references<'a>(
    journal: &Journal,
    intents: impl IntoIterator<Item = &'a AttachmentIntent>,
) -> Result<(), FilesystemViewRevisionStateError> {
    let history = History::load(journal)?;
    if intents
        .into_iter()
        .any(|intent| !attachment_reference_matches(&history, intent))
    {
        return Err(FilesystemViewRevisionStateError::CorruptState);
    }

    Ok(())
}

fn attachment_reference_matches(history: &History, intent: &AttachmentIntent) -> bool {
    let (view_id, revision) = intent.source_view();
    let Some(record) = history.revisions.get(&(view_id, revision.get())) else {
        return false;
    };
    if record.presence != FilesystemViewRevisionPresenceV1::Available
        || &record.descriptor != intent.view()
        || record.view.mutation() != intent.mutation()
    {
        return false;
    }

    matches!(
        (record.view.consistency(), intent.consistency()),
        (
            aos_sandbox_core::model::ViewConsistency::Immutable,
            AttachmentConsistency::ImmutableRevision
        ) | (
            aos_sandbox_core::model::ViewConsistency::LocalLive,
            AttachmentConsistency::LocalLive
        ) | (
            aos_sandbox_core::model::ViewConsistency::ExternalVersioned,
            AttachmentConsistency::TransactionalService
        ) | (
            aos_sandbox_core::model::ViewConsistency::ExternalVersioned,
            AttachmentConsistency::BestEffortReplica
        )
    ) && ((intent.consistency() == AttachmentConsistency::TransactionalService)
        == (record.view.mutation() == aos_sandbox_core::model::ViewMutation::Service))
}

fn source_handle_is_specified(source: &ViewSource) -> bool {
    match source {
        ViewSource::ImmutableTree { tree } => {
            tree.digest().as_bytes() != &[0; 32] && tree.encoded_size() != 0
        }
        ViewSource::LiveExport {
            owner_sandbox,
            export,
            source_generation,
        } => {
            owner_sandbox.as_bytes() != &[0; 16]
                && export.as_bytes() != &[0; 16]
                && source_generation.get() != 0
        }
    }
}

fn descriptor_for(view_bytes: &[u8]) -> Result<ObjectDescriptor, FilesystemViewRevisionStateError> {
    let media_type = MediaType::new(PortableMediaType::View.as_str().to_owned())
        .map_err(|_| FilesystemViewRevisionStateError::CorruptState)?;
    Ok(descriptor_for_bytes(media_type, view_bytes))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], FilesystemViewRevisionStateError> {
    let value = bytes
        .get(..N)
        .ok_or(FilesystemViewRevisionStateError::CorruptState)?
        .try_into()
        .map_err(|_| FilesystemViewRevisionStateError::CorruptState)?;
    *bytes = bytes
        .get(N..)
        .ok_or(FilesystemViewRevisionStateError::CorruptState)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::model::{CacheDomain, CacheDomainKind, ViewConsistency, ViewMutation};
    use aos_sandbox_core::{CacheDomainId, ExportId, FeatureRef, MediaType, SandboxId};
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
            panic!("view-revision tests must not observe effects")
        }

        fn apply(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            panic!("view-revision tests must not apply effects")
        }
    }

    fn journal() -> (TempDir, Journal) {
        let directory = TempDir::new().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("controller.journal"),
            Default::default(),
        )
        .unwrap();
        (directory, journal)
    }

    fn feature() -> FeatureRef {
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap()
    }

    fn immutable_view(source_byte: u8) -> View {
        View::new(
            ViewSource::ImmutableTree {
                tree: ObjectDescriptor::new(
                    MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor").unwrap(),
                    ObjectDigest::from_bytes([source_byte; 32]),
                    1,
                ),
            },
            Vec::new(),
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        )
        .unwrap()
    }

    fn live_view(owner: u8, export: u8, generation: u64) -> View {
        View::new(
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([owner; 16]),
                export: ExportId::from_bytes([export; 16]),
                source_generation: Revision::new(generation),
            },
            Vec::new(),
            ViewConsistency::LocalLive,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        )
        .unwrap()
    }

    fn mutation(
        presence: FilesystemViewRevisionPresenceV1,
        revision: u64,
        view: View,
        expected_previous: Option<ObjectDigest>,
    ) -> FilesystemViewRevisionMutationV1 {
        let byte = u8::try_from(revision).unwrap().checked_add(10).unwrap();
        FilesystemViewRevisionMutationV1::new(
            presence,
            ViewId::from_bytes([1; 16]),
            Revision::new(revision),
            view,
            OperationId::from_bytes([byte; 16]),
            ObjectDigest::from_bytes([byte.checked_add(20).unwrap(); 32]),
            expected_previous,
        )
        .unwrap()
    }

    #[test]
    fn publication_successors_release_and_replay_are_generation_fenced() {
        let (directory, mut journal) = journal();
        let first = mutation(
            FilesystemViewRevisionPresenceV1::Available,
            1,
            immutable_view(4),
            None,
        );
        let (first_state, outcome) = commit(&mut journal, first.clone()).unwrap();
        assert_eq!(outcome, FilesystemViewRevisionCommitOutcomeV1::Recorded);
        assert_eq!(
            commit(&mut journal, first).unwrap().1,
            FilesystemViewRevisionCommitOutcomeV1::Replay
        );

        let second = mutation(
            FilesystemViewRevisionPresenceV1::Available,
            2,
            immutable_view(5),
            Some(first_state.record_digest()),
        );
        let (second_state, outcome) = commit(&mut journal, second).unwrap();
        assert_eq!(outcome, FilesystemViewRevisionCommitOutcomeV1::Recorded);
        assert_ne!(first_state.descriptor(), second_state.descriptor());
        assert_eq!(
            get_revision(&journal, first_state.view_id(), Revision::new(1))
                .unwrap()
                .unwrap(),
            first_state
        );

        let release = mutation(
            FilesystemViewRevisionPresenceV1::Released,
            3,
            immutable_view(5),
            Some(second_state.record_digest()),
        );
        let (released, outcome) = commit(&mut journal, release).unwrap();
        assert_eq!(outcome, FilesystemViewRevisionCommitOutcomeV1::Recorded);
        assert_eq!(
            released.presence(),
            FilesystemViewRevisionPresenceV1::Released
        );

        journal.compact().unwrap();
        drop(journal);
        let (recovered, _) = Journal::open(
            directory.path().join("controller.journal"),
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            get_current(&recovered, ViewId::from_bytes([1; 16]))
                .unwrap()
                .unwrap()
                .presence(),
            FilesystemViewRevisionPresenceV1::Released
        );

        let resurrection = mutation(
            FilesystemViewRevisionPresenceV1::Available,
            4,
            immutable_view(6),
            Some(released.record_digest()),
        );
        assert!(matches!(
            History::load(&recovered)
                .unwrap()
                .validate_mutation(&resurrection),
            Err(FilesystemViewRevisionStateError::Conflict)
        ));
    }

    #[test]
    fn stale_revision_operation_reuse_and_changed_release_fail_closed() {
        let (_directory, mut journal) = journal();
        let first = mutation(
            FilesystemViewRevisionPresenceV1::Available,
            1,
            immutable_view(4),
            None,
        );
        let (first_state, _) = commit(&mut journal, first.clone()).unwrap();

        let stale = mutation(
            FilesystemViewRevisionPresenceV1::Available,
            3,
            immutable_view(5),
            Some(first_state.record_digest()),
        );
        assert!(matches!(
            History::load(&journal).unwrap().validate_mutation(&stale),
            Err(FilesystemViewRevisionStateError::Conflict)
        ));

        let changed_release = mutation(
            FilesystemViewRevisionPresenceV1::Released,
            2,
            immutable_view(5),
            Some(first_state.record_digest()),
        );
        assert!(matches!(
            History::load(&journal)
                .unwrap()
                .validate_mutation(&changed_release),
            Err(FilesystemViewRevisionStateError::Conflict)
        ));

        let reused_operation = FilesystemViewRevisionMutationV1::new(
            FilesystemViewRevisionPresenceV1::Available,
            ViewId::from_bytes([2; 16]),
            Revision::new(1),
            immutable_view(6),
            first.record.operation_id,
            ObjectDigest::from_bytes([40; 32]),
            None,
        )
        .unwrap();
        assert!(matches!(
            History::load(&journal)
                .unwrap()
                .validate_mutation(&reused_operation),
            Err(FilesystemViewRevisionStateError::Conflict)
        ));
    }

    #[test]
    fn codec_rejects_every_changed_and_truncated_byte() {
        let record = mutation(
            FilesystemViewRevisionPresenceV1::Available,
            1,
            immutable_view(4),
            None,
        )
        .record;
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
    fn durable_source_handles_reject_sentinels() {
        let cases = [live_view(0, 2, 1), live_view(1, 0, 1), live_view(1, 2, 0)];
        for view in cases {
            assert!(matches!(
                FilesystemViewRevisionMutationV1::new(
                    FilesystemViewRevisionPresenceV1::Available,
                    ViewId::from_bytes([1; 16]),
                    Revision::new(1),
                    view,
                    OperationId::from_bytes([2; 16]),
                    ObjectDigest::from_bytes([3; 32]),
                    None,
                ),
                Err(FilesystemViewRevisionStateError::InvalidMutation)
            ));
        }
    }

    #[test]
    fn publication_revalidates_in_memory_view_objects_through_the_closed_codec() {
        let invalid_role = View::new(
            ViewSource::ImmutableTree {
                tree: ObjectDescriptor::new(
                    MediaType::new("application/vnd.aos.sandbox.content.v1").unwrap(),
                    ObjectDigest::from_bytes([4; 32]),
                    1,
                ),
            },
            Vec::new(),
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        )
        .unwrap();

        assert!(matches!(
            FilesystemViewRevisionMutationV1::new(
                FilesystemViewRevisionPresenceV1::Available,
                ViewId::from_bytes([1; 16]),
                Revision::new(1),
                invalid_role,
                OperationId::from_bytes([2; 16]),
                ObjectDigest::from_bytes([3; 32]),
                None,
            ),
            Err(FilesystemViewRevisionStateError::InvalidMutation)
        ));
    }

    #[test]
    fn corrupt_reserved_namespace_blocks_reconciliation_startup() {
        let (_directory, mut journal) = journal();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::FilesystemViewRevision,
                        vec![1; 24],
                        b"corrupt".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            validate_namespace(&journal),
            Err(FilesystemViewRevisionStateError::CorruptState)
        ));
        let mut reconciler = Reconciler::new(journal, NoEffects);
        assert!(matches!(
            reconciler.reconcile_next(),
            Err(crate::ReconcilerError::FilesystemViewRevision(error))
                if matches!(*error, FilesystemViewRevisionStateError::CorruptState)
        ));
    }
}
