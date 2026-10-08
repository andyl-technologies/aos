//! Fixed-root protected artifact ownership and complete cold-read validation.
//!
//! This private store retains only carrier-authenticated immutable bytes. Each
//! object is framed with the exact protected owner, replay fence, semantic
//! subject, ordinal, and checksum. A write is classified only after reopening
//! the protected journal and byte-comparing current materialized state. Artifact
//! mutation and uncertain-write recovery require `multi-node`; cold-open loading,
//! bounded framing, exact payload/receipt reads, and integrity checks do not.
//!
//! ```text
//! magic | kind | subject | ordinal | storage | replay | context | length | bytes | sha256
//! ```

#[cfg(feature = "multi-node")]
pub(super) mod remote;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::ObjectDigest;

use crate::journal::{Journal, JournalLimits, RecordNamespace};

use super::evidence::AuthenticatedEvidenceContextV1;
use super::journal::InvalidMultiNodeJournal;

const ARTIFACT_JOURNAL_NAME: &str = "multi-node-artifacts-v1.journal";
const ARTIFACT_KEY_PREFIX: &[u8] = b"\0aos-multi-node-artifact-v1\0";
const ARTIFACT_MAGIC: &[u8; 8] = b"AOSMAB01";
const MAXIMUM_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_ARTIFACTS: usize = 70_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedArtifactKindV1 {
    SnapshotChunk = 1,
    SnapshotDependencyRange = 2,
    WatchEvent = 3,
    WatchInventory = 4,
}

pub(super) struct ProtectedArtifactStoreV1 {
    directory: PathBuf,
    journal: Option<Journal>,
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    context_digest: ObjectDigest,
    values: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ProtectedArtifactStoreV1 {
    pub(super) fn open_fixed(
        directory: &Path,
        storage_domain_digest: ObjectDigest,
        replay_fence: ObjectDigest,
        context: AuthenticatedEvidenceContextV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let (mut journal, _) = Journal::open_protected_at(
            directory,
            ARTIFACT_JOURNAL_NAME,
            protected_artifact_limits(),
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let context_digest = artifact_context_digest(context);
        let values = load_values(
            &mut journal,
            storage_domain_digest,
            replay_fence,
            context_digest,
        )?;
        Ok(Self {
            directory: directory.to_path_buf(),
            journal: Some(journal),
            storage_domain_digest,
            replay_fence,
            context_digest,
            values,
        })
    }

    pub(super) fn snapshot_prefix(
        &self,
        subject: ObjectDigest,
        next_chunk: u32,
    ) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
        let mut prefix = Vec::new();
        for index in 0..next_chunk {
            let key = artifact_key(
                ProtectedArtifactKindV1::SnapshotChunk,
                subject,
                u64::from(index),
            );
            let value = self
                .values
                .get(&key)
                .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
            let decoded = decode_artifact(
                &key,
                value,
                self.storage_domain_digest,
                self.replay_fence,
                self.context_digest,
            )?;
            prefix.extend_from_slice(decoded);
        }
        Ok(prefix)
    }

    pub(super) fn dependency_prefix(
        &self,
        subject: ObjectDigest,
        end_offset: u64,
    ) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
        let maximum = usize::try_from(end_offset)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        let mut prefix = Vec::with_capacity(maximum);
        let mut offset = 0_u64;
        while offset < end_offset {
            let key = artifact_key(
                ProtectedArtifactKindV1::SnapshotDependencyRange,
                subject,
                offset,
            );
            let value = self
                .values
                .get(&key)
                .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
            let decoded = decode_artifact(
                &key,
                value,
                self.storage_domain_digest,
                self.replay_fence,
                self.context_digest,
            )?;
            prefix.extend_from_slice(decoded);
            offset = offset
                .checked_add(
                    u64::try_from(decoded.len())
                        .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?,
                )
                .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
            if offset > end_offset {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            }
        }
        Ok(prefix)
    }

    pub(super) fn exact_payload(
        &self,
        kind: ProtectedArtifactKindV1,
        subject: ObjectDigest,
        ordinal: u64,
    ) -> Result<&[u8], InvalidMultiNodeJournal> {
        let key = artifact_key(kind, subject, ordinal);
        let value = self
            .values
            .get(&key)
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        decode_artifact(
            &key,
            value,
            self.storage_domain_digest,
            self.replay_fence,
            self.context_digest,
        )
    }

    pub(super) fn exact_receipt(
        &self,
        kind: ProtectedArtifactKindV1,
        subject: ObjectDigest,
        ordinal: u64,
    ) -> Result<ObjectDigest, InvalidMultiNodeJournal> {
        let key = artifact_key(kind, subject, ordinal);
        let value = self
            .values
            .get(&key)
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        decode_artifact(
            &key,
            value,
            self.storage_domain_digest,
            self.replay_fence,
            self.context_digest,
        )?;
        Ok(artifact_receipt(&key, value))
    }

    fn reopen(&mut self) -> Result<(), InvalidMultiNodeJournal> {
        let (mut journal, _) = Journal::open_protected_at(
            &self.directory,
            ARTIFACT_JOURNAL_NAME,
            protected_artifact_limits(),
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let values = load_values(
            &mut journal,
            self.storage_domain_digest,
            self.replay_fence,
            self.context_digest,
        )?;
        self.journal = Some(journal);
        self.values = values;
        Ok(())
    }
}

fn protected_artifact_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 32 * 1024 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_ARTIFACT_BYTES + 256,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: MAXIMUM_ARTIFACT_BYTES + 512,
        maximum_transactions: MAXIMUM_ARTIFACTS,
        maximum_materialized_bytes: 16 * 1024 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_ARTIFACTS,
    }
}

fn load_values(
    journal: &mut Journal,
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    context_digest: ObjectDigest,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, InvalidMultiNodeJournal> {
    let authority = journal
        .claim_protected_authority(RecordNamespace::RuntimeAuthority)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let values = authority
        .records()
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
        .take(MAXIMUM_ARTIFACTS.saturating_add(1))
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<BTreeMap<_, _>>();
    if values.len() > MAXIMUM_ARTIFACTS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    for (key, value) in &values {
        decode_artifact(
            key,
            value,
            storage_domain_digest,
            replay_fence,
            context_digest,
        )?;
    }
    Ok(values)
}

fn validate_artifact_input(
    subject: ObjectDigest,
    bytes: &[u8],
) -> Result<(), InvalidMultiNodeJournal> {
    if subject.as_bytes() == &[0; 32] || bytes.is_empty() || bytes.len() > MAXIMUM_ARTIFACT_BYTES {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok(())
}

fn artifact_key(kind: ProtectedArtifactKindV1, subject: ObjectDigest, ordinal: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(ARTIFACT_KEY_PREFIX.len().saturating_add(41));
    key.extend_from_slice(ARTIFACT_KEY_PREFIX);
    key.push(kind as u8);
    key.extend_from_slice(subject.as_bytes());
    key.extend_from_slice(&ordinal.to_be_bytes());
    key
}

fn decode_artifact<'a>(
    key: &[u8],
    value: &'a [u8],
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    context_digest: ObjectDigest,
) -> Result<&'a [u8], InvalidMultiNodeJournal> {
    const HEADER_BYTES: usize = 149;
    const TRAILER_BYTES: usize = 32;
    if value.len() < HEADER_BYTES.saturating_add(TRAILER_BYTES)
        || value.get(..8) != Some(ARTIFACT_MAGIC)
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let kind = match value[8] {
        1 => ProtectedArtifactKindV1::SnapshotChunk,
        2 => ProtectedArtifactKindV1::SnapshotDependencyRange,
        3 => ProtectedArtifactKindV1::WatchEvent,
        4 => ProtectedArtifactKindV1::WatchInventory,
        _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
    };
    let subject = ObjectDigest::from_bytes(
        value
            .get(9..41)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    );
    let ordinal = u64::from_be_bytes(
        value
            .get(41..49)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    );
    if value.get(49..81) != Some(storage_domain_digest.as_bytes())
        || value.get(81..113) != Some(replay_fence.as_bytes())
        || value.get(113..145) != Some(context_digest.as_bytes())
        || artifact_key(kind, subject, ordinal) != key
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let length = u32::from_be_bytes(
        value
            .get(145..149)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    ) as usize;
    let body_end = HEADER_BYTES
        .checked_add(length)
        .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let payload = value
        .get(HEADER_BYTES..body_end)
        .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let checksum = value
        .get(body_end..)
        .filter(|checksum| checksum.len() == TRAILER_BYTES)
        .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let expected: [u8; 32] = Sha256::digest(
        value
            .get(..body_end)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    )
    .into();
    if expected.as_slice() != checksum
        || payload.is_empty()
        || payload.len() > MAXIMUM_ARTIFACT_BYTES
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(payload)
}

fn artifact_receipt(key: &[u8], value: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-artifact-receipt.v1\0")
            .chain_update(key)
            .chain_update(value)
            .finalize()
            .into(),
    )
}

fn artifact_context_digest(context: AuthenticatedEvidenceContextV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-artifact-context.v1\0")
            .chain_update(context.node().as_bytes())
            .chain_update(context.lineage().boot().as_bytes())
            .chain_update(context.lineage().generation().to_be_bytes())
            .chain_update(context.audience_digest().as_bytes())
            .chain_update(context.disclosure_domain_digest().as_bytes())
            .chain_update(context.carrier_binding_digest().as_bytes())
            .chain_update(context.coordinator_epoch().to_be_bytes())
            .chain_update(context.replay_fence().as_bytes())
            .finalize()
            .into(),
    )
}
