//! Selected protected artifact writes and exact ambiguous-write recovery.
//!
//! The default parent still opens and validates every retained artifact. This
//! private child uses the same owned journal and original canonical framing;
//! it cannot construct an independent backend or detach write custody.

use super::*;

use crate::journal::{JournalRecord, JournalTransaction};
use aos_proto::aos::sandbox::coordinator::v1 as wire;

#[derive(Clone)]
pub(in crate::local_inventory) enum ProtectedArtifactRecoveryV1 {
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
    pub(in crate::local_inventory) fn subject(
        &self,
    ) -> Result<ObjectDigest, InvalidMultiNodeJournal> {
        self.identity().map(|(_, subject, _)| subject)
    }

    pub(in crate::local_inventory) fn ordinal(&self) -> Result<u64, InvalidMultiNodeJournal> {
        self.identity().map(|(_, _, ordinal)| ordinal)
    }

    pub(in crate::local_inventory) fn byte_length(&self) -> usize {
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

pub(in crate::local_inventory) enum ProtectedArtifactStoreOutcomeV1 {
    Stored(ObjectDigest),
    RecoveryRequired(ProtectedArtifactRecoveryV1),
}

impl ProtectedArtifactStoreV1 {
    pub(in crate::local_inventory) fn store_exact(
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

    pub(in crate::local_inventory) fn store_snapshot_effect(
        &mut self,
        effect: wire::SnapshotTransferEffect,
        bytes: &[u8],
    ) -> Result<ProtectedArtifactStoreOutcomeV1, InvalidMultiNodeJournal> {
        let (kind, subject, ordinal) = generated_snapshot_identity(&effect, bytes)?;
        validate_artifact_input(subject, bytes)?;
        self.store_validated(kind, subject, ordinal, bytes, Some(effect))
    }

    pub(in crate::local_inventory) fn resolve(
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

pub(in crate::local_inventory) fn snapshot_chunk_effect(
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

pub(in crate::local_inventory) fn snapshot_dependency_effect(
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
