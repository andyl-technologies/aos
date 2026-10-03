//! Fixed-root protected byte staging for dormant multi-node recovery paths.
//!
//! This private store retains only carrier-authenticated immutable bytes. Each
//! object is framed with the exact protected owner, replay fence, semantic
//! subject, ordinal, and checksum. A write is classified only after reopening
//! the protected journal and byte-comparing current materialized state.
//!
//! ```text
//! magic | kind | subject | ordinal | storage | replay | context | length | bytes | sha256
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::ObjectDigest;

use crate::journal::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

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

#[derive(Clone)]
pub(super) enum ProtectedArtifactRecoveryV1 {
    Snapshot {
        recovery: wire::SnapshotTransferRecovery,
        bytes: Vec<u8>,
    },
    Other {
        kind: ProtectedArtifactKindV1,
        subject: ObjectDigest,
        ordinal: u64,
        bytes: Vec<u8>,
    },
}

impl ProtectedArtifactRecoveryV1 {
    pub(super) fn subject(&self) -> Result<ObjectDigest, InvalidMultiNodeJournal> {
        self.identity().map(|(_, subject, _)| subject)
    }

    pub(super) fn ordinal(&self) -> Result<u64, InvalidMultiNodeJournal> {
        self.identity().map(|(_, _, ordinal)| ordinal)
    }

    pub(super) fn byte_length(&self) -> usize {
        self.bytes().len()
    }

    fn identity(
        &self,
    ) -> Result<(ProtectedArtifactKindV1, ObjectDigest, u64), InvalidMultiNodeJournal> {
        match self {
            Self::Snapshot { recovery, bytes } => validate_generated_recovery(recovery, bytes),
            Self::Other {
                kind,
                subject,
                ordinal,
                ..
            } => Ok((*kind, *subject, *ordinal)),
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Snapshot { bytes, .. } | Self::Other { bytes, .. } => bytes,
        }
    }

    fn protobuf(&self) -> Option<&wire::SnapshotTransferRecovery> {
        match self {
            Self::Snapshot { recovery, .. } => Some(recovery),
            Self::Other { .. } => None,
        }
    }
}

pub(super) enum ProtectedArtifactStoreOutcomeV1 {
    Stored(ObjectDigest),
    RecoveryRequired(ProtectedArtifactRecoveryV1),
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

    pub(super) fn store_exact(
        &mut self,
        kind: ProtectedArtifactKindV1,
        subject: ObjectDigest,
        ordinal: u64,
        bytes: &[u8],
    ) -> Result<ProtectedArtifactStoreOutcomeV1, InvalidMultiNodeJournal> {
        if matches!(
            kind,
            ProtectedArtifactKindV1::SnapshotChunk
                | ProtectedArtifactKindV1::SnapshotDependencyRange
        ) {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        validate_artifact_input(subject, bytes)?;
        self.store_validated(kind, subject, ordinal, bytes, None)
    }

    pub(super) fn store_snapshot_effect(
        &mut self,
        effect: wire::SnapshotTransferEffect,
        bytes: &[u8],
    ) -> Result<ProtectedArtifactStoreOutcomeV1, InvalidMultiNodeJournal> {
        let (kind, subject, ordinal) = generated_snapshot_identity(&effect, bytes)?;
        validate_artifact_input(subject, bytes)?;
        self.store_validated(kind, subject, ordinal, bytes, Some(effect))
    }

    fn store_validated(
        &mut self,
        kind: ProtectedArtifactKindV1,
        subject: ObjectDigest,
        ordinal: u64,
        bytes: &[u8],
        generated: Option<wire::SnapshotTransferEffect>,
    ) -> Result<ProtectedArtifactStoreOutcomeV1, InvalidMultiNodeJournal> {
        let key = artifact_key(kind, subject, ordinal);
        let value = encode_artifact(
            kind,
            subject,
            ordinal,
            bytes,
            self.storage_domain_digest,
            self.replay_fence,
            self.context_digest,
        )?;
        match self.values.get(&key) {
            Some(current) if current == &value => {
                return Ok(ProtectedArtifactStoreOutcomeV1::Stored(artifact_receipt(
                    &key, &value,
                )));
            }
            Some(_) => return Err(InvalidMultiNodeJournal::Equivocation),
            None => {}
        }
        let transaction = artifact_transaction(&key, &value)?;
        let mut journal = self
            .journal
            .take()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let _attempted = (|| {
            let mut authority = journal
                .claim_protected_authority(RecordNamespace::RuntimeAuthority)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            let preflight = authority
                .preflight_transactions(std::slice::from_ref(&transaction))
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            authority
                .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            authority
                .commit(&transaction)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            Ok::<(), InvalidMultiNodeJournal>(())
        })();
        drop(journal);
        if self.reopen().is_err() {
            let recovery = match generated {
                Some(effect) => snapshot_recovery(effect, bytes, 4)?,
                None => ProtectedArtifactRecoveryV1::Other {
                    kind,
                    subject,
                    ordinal,
                    bytes: bytes.to_vec(),
                },
            };
            return Ok(ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery));
        }
        match self.values.get(&key) {
            Some(current) if current == &value => Ok(ProtectedArtifactStoreOutcomeV1::Stored(
                artifact_receipt(&key, &value),
            )),
            None => {
                let recovery = match generated {
                    Some(effect) => snapshot_recovery(effect, bytes, 1)?,
                    None => ProtectedArtifactRecoveryV1::Other {
                        kind,
                        subject,
                        ordinal,
                        bytes: bytes.to_vec(),
                    },
                };
                Ok(ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery))
            }
            Some(_) => Err(InvalidMultiNodeJournal::Equivocation),
        }
    }

    pub(super) fn resolve(
        &mut self,
        recovery: ProtectedArtifactRecoveryV1,
    ) -> Result<ProtectedArtifactStoreOutcomeV1, InvalidMultiNodeJournal> {
        let (kind, subject, ordinal) = recovery.identity()?;
        let bytes = recovery.bytes();
        let carrier = recovery.protobuf();
        if carrier.is_some_and(|value| value.status.to_i32() == 4) || self.journal.is_none() {
            self.reopen()?;
        }
        let key = artifact_key(kind, subject, ordinal);
        let expected = encode_artifact(
            kind,
            subject,
            ordinal,
            bytes,
            self.storage_domain_digest,
            self.replay_fence,
            self.context_digest,
        )?;
        let recovery_status = carrier.map_or(4, |value| value.status.to_i32());
        match (recovery_status, self.values.get(&key)) {
            (_, Some(current)) if current == &expected => {
                if let Some(carrier) = carrier {
                    let observed =
                        generated_recovery_observation(carrier, 2, Sha256::digest(bytes).to_vec())?;
                    consume_generated_recovery_observation(carrier, &observed, 2, bytes)?;
                }
                return Ok(ProtectedArtifactStoreOutcomeV1::Stored(artifact_receipt(
                    &key, &expected,
                )));
            }
            (_, Some(current)) => {
                if let Some(carrier) = carrier {
                    let observed_payload = decode_artifact(
                        &key,
                        current,
                        self.storage_domain_digest,
                        self.replay_fence,
                        self.context_digest,
                    )?;
                    let observed = generated_recovery_observation(
                        carrier,
                        3,
                        Sha256::digest(observed_payload).to_vec(),
                    )?;
                    consume_generated_recovery_observation(
                        carrier,
                        &observed,
                        3,
                        observed_payload,
                    )?;
                }
                return Err(InvalidMultiNodeJournal::Equivocation);
            }
            (1 | 4, None) => {}
            _ => return Err(InvalidMultiNodeJournal::NonCanonicalPayload),
        }
        match carrier.and_then(|recovery| recovery.expected.as_option().cloned()) {
            Some(effect) => self.store_snapshot_effect(effect, bytes),
            None => self.store_exact(kind, subject, ordinal, bytes),
        }
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

fn generated_recovery_observation(
    recovery: &wire::SnapshotTransferRecovery,
    status: i32,
    observed_bytes_sha256: Vec<u8>,
) -> Result<wire::SnapshotTransferRecovery, InvalidMultiNodeJournal> {
    if recovery.expected.is_unset()
        || !matches!(recovery.status.to_i32(), 1 | 4)
        || !recovery.observed_bytes_sha256.is_empty()
        || !matches!(status, 2 | 3)
        || observed_bytes_sha256.len() != 32
    {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    let observed = wire::SnapshotTransferRecovery {
        expected: recovery.expected.clone(),
        status: status.into(),
        observed_bytes_sha256,
        ..Default::default()
    };
    Ok(observed)
}

fn consume_generated_recovery_observation(
    expected: &wire::SnapshotTransferRecovery,
    observed: &wire::SnapshotTransferRecovery,
    status: i32,
    observed_bytes: &[u8],
) -> Result<(), InvalidMultiNodeJournal> {
    if observed.expected != expected.expected
        || observed.status.to_i32() != status
        || observed.observed_bytes_sha256 != Sha256::digest(observed_bytes).as_slice()
    {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok(())
}

fn snapshot_recovery(
    effect: wire::SnapshotTransferEffect,
    bytes: &[u8],
    status: i32,
) -> Result<ProtectedArtifactRecoveryV1, InvalidMultiNodeJournal> {
    let recovery = wire::SnapshotTransferRecovery {
        expected: Some(effect).into(),
        status: status.into(),
        observed_bytes_sha256: Vec::new(),
        ..Default::default()
    };
    validate_generated_recovery(&recovery, bytes)?;
    Ok(ProtectedArtifactRecoveryV1::Snapshot {
        recovery,
        bytes: bytes.to_vec(),
    })
}

fn validate_generated_recovery(
    recovery: &wire::SnapshotTransferRecovery,
    bytes: &[u8],
) -> Result<(ProtectedArtifactKindV1, ObjectDigest, u64), InvalidMultiNodeJournal> {
    let effect = recovery
        .expected
        .as_option()
        .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let identity = generated_snapshot_identity(effect, bytes)?;
    if !matches!(recovery.status.to_i32(), 1 | 4) || !recovery.observed_bytes_sha256.is_empty() {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok(identity)
}

fn generated_snapshot_identity(
    effect: &wire::SnapshotTransferEffect,
    bytes: &[u8],
) -> Result<(ProtectedArtifactKindV1, ObjectDigest, u64), InvalidMultiNodeJournal> {
    let transfer: [u8; 32] = effect
        .transfer_sha256
        .as_slice()
        .try_into()
        .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let bytes_digest: [u8; 32] = effect
        .bytes_sha256
        .as_slice()
        .try_into()
        .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let subject = ObjectDigest::from_bytes(transfer);
    let (kind, ordinal) = match effect.artifact.as_ref() {
        Some(wire::snapshot_transfer_effect::Artifact::Chunk(chunk)) => (
            ProtectedArtifactKindV1::SnapshotChunk,
            u64::from(chunk.index),
        ),
        Some(wire::snapshot_transfer_effect::Artifact::Dependency(dependency)) => (
            ProtectedArtifactKindV1::SnapshotDependencyRange,
            dependency.offset,
        ),
        None => return Err(InvalidMultiNodeJournal::NonCanonicalPayload),
    };
    let expected_idempotency_uid = Sha256::digest(artifact_key(kind, subject, ordinal));
    if subject.as_bytes() == &[0; 32]
        || ObjectDigest::from_bytes(bytes_digest)
            != ObjectDigest::from_bytes(Sha256::digest(bytes).into())
        || effect.byte_count
            != u32::try_from(bytes.len())
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?
        || effect.idempotency_uid.as_slice() != expected_idempotency_uid.as_slice()
    {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok((kind, subject, ordinal))
}

pub(super) fn snapshot_chunk_effect(
    subject: ObjectDigest,
    index: u32,
    bytes: &[u8],
) -> Result<wire::SnapshotTransferEffect, InvalidMultiNodeJournal> {
    snapshot_effect(
        subject,
        wire::snapshot_transfer_effect::Artifact::Chunk(Box::new(wire::SnapshotChunkEffect {
            index,
            ..Default::default()
        })),
        bytes,
    )
}

pub(super) fn snapshot_dependency_effect(
    subject: ObjectDigest,
    offset: u64,
    bytes: &[u8],
) -> Result<wire::SnapshotTransferEffect, InvalidMultiNodeJournal> {
    snapshot_effect(
        subject,
        wire::snapshot_transfer_effect::Artifact::Dependency(Box::new(
            wire::SnapshotDependencyEffect {
                offset,
                ..Default::default()
            },
        )),
        bytes,
    )
}

fn snapshot_effect(
    subject: ObjectDigest,
    artifact: wire::snapshot_transfer_effect::Artifact,
    bytes: &[u8],
) -> Result<wire::SnapshotTransferEffect, InvalidMultiNodeJournal> {
    let byte_count =
        u32::try_from(bytes.len()).map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let (kind, ordinal) = match &artifact {
        wire::snapshot_transfer_effect::Artifact::Chunk(chunk) => (
            ProtectedArtifactKindV1::SnapshotChunk,
            u64::from(chunk.index),
        ),
        wire::snapshot_transfer_effect::Artifact::Dependency(dependency) => (
            ProtectedArtifactKindV1::SnapshotDependencyRange,
            dependency.offset,
        ),
    };
    let idempotency_uid = artifact_key(kind, subject, ordinal);
    Ok(wire::SnapshotTransferEffect {
        transfer_sha256: subject.as_bytes().to_vec(),
        artifact: Some(artifact),
        bytes_sha256: Sha256::digest(bytes).to_vec(),
        byte_count,
        idempotency_uid: Sha256::digest(idempotency_uid).to_vec(),
        ..Default::default()
    })
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

#[allow(clippy::too_many_arguments)]
fn encode_artifact(
    kind: ProtectedArtifactKindV1,
    subject: ObjectDigest,
    ordinal: u64,
    payload: &[u8],
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    context_digest: ObjectDigest,
) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let mut bytes = Vec::with_capacity(payload.len().saturating_add(181));
    bytes.extend_from_slice(ARTIFACT_MAGIC);
    bytes.push(kind as u8);
    bytes.extend_from_slice(subject.as_bytes());
    bytes.extend_from_slice(&ordinal.to_be_bytes());
    bytes.extend_from_slice(storage_domain_digest.as_bytes());
    bytes.extend_from_slice(replay_fence.as_bytes());
    bytes.extend_from_slice(context_digest.as_bytes());
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
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

fn artifact_transaction(
    key: &[u8],
    value: &[u8],
) -> Result<JournalTransaction, InvalidMultiNodeJournal> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-artifact-transaction.v1\0")
        .chain_update(key)
        .chain_update(value)
        .finalize()
        .into();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    if transaction_id == [0; 16] {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::RuntimeAuthority,
            key.to_vec(),
            value.to_vec(),
        )],
    )
    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)
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
