//! Canonical reconstructing payload codecs for durable Git projections.
//!
//! ```text
//! kind-specific-payload := repository | receive | publication | export |
//!                          pack | pack-lease | cheap-fork
//! ```
//!
//! Every variant contains the complete domain record. Digests in the outer
//! durable envelope are integrity commitments, never substitutes for replay
//! data. Decoding preflights all variable lengths before allocating and binds
//! graph evidence to a verifier-issued [`GitTrustedValidatorV1`].

use aos_sandbox_core::{ObjectDigest, PrincipalId, ProjectId, ResourceId, Revision, SandboxId};

use super::format::{
    decode_export, decode_refs, decode_whole_database, encode_export, encode_git_receive_plan_v1,
    encode_refs, encode_whole_database, export_encoded_length, preflight_export,
    preflight_whole_database, refs_encoded_length, whole_database_encoded_length,
};
use super::pack_format::decode_pack_generation_payload_v1;
use super::{
    GitAtomicCasDigestV1, GitBoottimeV1, GitCheapForkStatusV1, GitCheapForkV1,
    GitDurableRecordKindV1, GitExchangePlanV1, GitExportGenerationDigestV1,
    GitExportHistoryRecordV1, GitModelError, GitObjectFormatV1, GitPackConsumerV1,
    GitPackGenerationDigestV1, GitPackLeaseStatusV1, GitPackLeaseV1, GitPublicationRecordV1,
    GitReceiveHistoryRecordV1, GitReceivePhaseV1, GitRefMapDigestV1, GitRepositoryStateV1,
    GitRepositoryV1, GitTrustedValidatorV1, ImmutablePackGenerationV1, decode_git_exchange_plan_v1,
    encode_pack_generation_v1,
};

/// Maximum bytes in one reconstructing durable Git payload.
pub const MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES: usize = 160 * 1024 * 1024;

/// Stores one complete reconstructing durable Git projection value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitDurablePayloadV1 {
    /// Stores a complete repository revision.
    Repository(GitRepositoryStateV1),
    /// Stores one receive/quarantine progress revision.
    Receive(GitReceiveHistoryRecordV1),
    /// Stores exact atomic publication evidence.
    Publication(GitPublicationRecordV1),
    /// Stores an immutable export lineage revision.
    Export(GitExportHistoryRecordV1),
    /// Stores an immutable pack generation.
    Pack(ImmutablePackGenerationV1),
    /// Stores exact pack-lease currentness.
    PackLease(GitPackLeaseV1),
    /// Stores a cheap-fork dependency and target genesis.
    CheapFork(GitCheapForkV1),
}

impl GitDurablePayloadV1 {
    /// Returns the closed projection family containing this payload.
    #[must_use]
    pub const fn kind(&self) -> GitDurableRecordKindV1 {
        match self {
            Self::Repository(_) => GitDurableRecordKindV1::Repository,
            Self::Receive(_) => GitDurableRecordKindV1::Receive,
            Self::Publication(_) => GitDurableRecordKindV1::Publication,
            Self::Export(_) => GitDurableRecordKindV1::Export,
            Self::Pack(_) => GitDurableRecordKindV1::Pack,
            Self::PackLease(_) => GitDurableRecordKindV1::PackLease,
            Self::CheapFork(_) => GitDurableRecordKindV1::CheapFork,
        }
    }

    /// Returns the family-local lineage identity and revision.
    #[must_use]
    pub fn lineage_revision(&self) -> (ResourceId, Revision) {
        match self {
            Self::Repository(value) => (
                value.repository().repository(),
                value.repository().revision(),
            ),
            Self::Receive(value) => (value.plan().exchange(), value.revision()),
            Self::Publication(value) => (value.repository(), value.successor_revision()),
            Self::Export(value) => (value.export().export(), value.export().generation()),
            Self::Pack(value) => (value.pack_generation(), value.generation()),
            Self::PackLease(value) => (value.lease(), value.lease_revision()),
            Self::CheapFork(value) => (
                value.target().repository().repository(),
                value.record_revision(),
            ),
        }
    }
}

/// Encodes one complete Git projection payload.
///
/// # Errors
///
/// Returns [`GitModelError`] if a nested encoding exceeds its fixed ceiling,
/// a length is not representable, or checked allocation fails.
pub fn encode_git_durable_payload_v1(
    payload: &GitDurablePayloadV1,
) -> Result<Vec<u8>, GitModelError> {
    if let GitDurablePayloadV1::Pack(value) = payload {
        return encode_pack_generation_v1(value);
    }
    let receive_plan = match payload {
        GitDurablePayloadV1::Receive(value) => Some(encode_git_receive_plan_v1(value.plan())?),
        _ => None,
    };
    let expected_length = payload_encoded_length(payload, receive_plan.as_deref())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| GitModelError::Allocation)?;
    match payload {
        GitDurablePayloadV1::Repository(value) => encode_repository(&mut bytes, value)?,
        GitDurablePayloadV1::Receive(value) => {
            let plan = receive_plan.as_ref().ok_or(GitModelError::InvalidModel)?;
            push_length(&mut bytes, plan.len())?;
            bytes.extend_from_slice(plan);
            bytes.extend_from_slice(&value.revision().get().to_be_bytes());
            encode_optional_digest(&mut bytes, value.predecessor());
            bytes.push(value.phase() as u8);
            bytes.extend_from_slice(&[0; 7]);
            for digest in [
                value.sealed_quarantine(),
                value.validation(),
                value.publication().map(GitAtomicCasDigestV1::digest),
                value.failure(),
            ] {
                encode_optional_digest(&mut bytes, digest);
            }
        }
        GitDurablePayloadV1::Publication(value) => {
            bytes.extend_from_slice(value.repository().as_bytes());
            bytes.extend_from_slice(&value.predecessor_revision().get().to_be_bytes());
            bytes.extend_from_slice(&value.successor_revision().get().to_be_bytes());
            bytes.extend_from_slice(value.atomic_cas().digest().as_bytes());
            bytes.extend_from_slice(&value.published_at().to_be_bytes());
        }
        GitDurablePayloadV1::Export(value) => {
            bytes.push(value.export().graph().format() as u8);
            bytes.extend_from_slice(&[0; 7]);
            match value.predecessor() {
                Some((generation, digest)) => {
                    bytes.extend_from_slice(&generation.get().to_be_bytes());
                    bytes.extend_from_slice(digest.digest().as_bytes());
                }
                None => bytes.extend_from_slice(&[0; 40]),
            }
            encode_export(&mut bytes, value.export());
        }
        GitDurablePayloadV1::Pack(_) => return Err(GitModelError::InvalidModel),
        GitDurablePayloadV1::PackLease(value) => encode_pack_lease(&mut bytes, *value),
        GitDurablePayloadV1::CheapFork(value) => {
            encode_repository(&mut bytes, value.target())?;
            bytes.extend_from_slice(value.source_repository().as_bytes());
            bytes.extend_from_slice(&value.source_revision().get().to_be_bytes());
            bytes.extend_from_slice(value.source_export().digest().as_bytes());
            bytes.extend_from_slice(value.pack().digest().as_bytes());
            encode_pack_lease(&mut bytes, value.lease());
            bytes.extend_from_slice(&value.observed_at().get().to_be_bytes());
            bytes.extend_from_slice(&value.record_revision().get().to_be_bytes());
            bytes.extend_from_slice(
                value
                    .predecessor()
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                    .as_bytes(),
            );
            bytes.push(value.status() as u8);
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(
                &value
                    .closed_at()
                    .map_or(0, GitBoottimeV1::get)
                    .to_be_bytes(),
            );
        }
    }
    if bytes.len() != expected_length || bytes.len() > MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES {
        return Err(GitModelError::InvalidModel);
    }
    Ok(bytes)
}

fn payload_encoded_length(
    payload: &GitDurablePayloadV1,
    receive_plan: Option<&[u8]>,
) -> Result<usize, GitModelError> {
    let length = match payload {
        GitDurablePayloadV1::Repository(value) => repository_encoded_length(value)?,
        GitDurablePayloadV1::Receive(_) => receive_plan
            .ok_or(GitModelError::InvalidModel)?
            .len()
            .checked_add(220)
            .ok_or(GitModelError::InvalidModel)?,
        GitDurablePayloadV1::Publication(_) => 72,
        GitDurablePayloadV1::Export(value) => export_encoded_length(value.export())?
            .checked_add(48)
            .ok_or(GitModelError::InvalidModel)?,
        GitDurablePayloadV1::Pack(_) => return Err(GitModelError::InvalidModel),
        GitDurablePayloadV1::PackLease(_) => 336,
        GitDurablePayloadV1::CheapFork(value) => repository_encoded_length(value.target())?
            .checked_add(488)
            .ok_or(GitModelError::InvalidModel)?,
    };
    if length > MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES {
        Err(GitModelError::InvalidModel)
    } else {
        Ok(length)
    }
}

fn repository_encoded_length(value: &GitRepositoryStateV1) -> Result<usize, GitModelError> {
    let database = whole_database_encoded_length(value.database())?;
    let refs = refs_encoded_length(value.refs())?;
    120_usize
        .checked_add(database)
        .and_then(|total| total.checked_add(refs))
        .and_then(|total| total.checked_add(32))
        .ok_or(GitModelError::InvalidModel)
}

/// Decodes one complete Git projection payload under trusted graph evidence.
///
/// # Errors
///
/// Returns [`GitModelError`] for malformed, non-canonical, oversized, or
/// validator-mismatched payload bytes.
pub fn decode_git_durable_payload_v1(
    kind: GitDurableRecordKindV1,
    encoded: &[u8],
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitDurablePayloadV1, GitModelError> {
    if encoded.is_empty() || encoded.len() > MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES {
        return Err(GitModelError::CorruptEncoding);
    }
    preflight_payload(kind, encoded)?;
    let mut bytes = encoded;
    let payload = match kind {
        GitDurableRecordKindV1::Repository => {
            GitDurablePayloadV1::Repository(decode_repository(&mut bytes, trusted_validator)?)
        }
        GitDurableRecordKindV1::Receive => {
            let length = read_length(&mut bytes)?;
            let plan = take_slice(&mut bytes, length)?;
            let GitExchangePlanV1::Receive(plan) =
                decode_git_exchange_plan_v1(plan, trusted_validator)?
            else {
                return Err(GitModelError::CorruptEncoding);
            };
            let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
            let predecessor = decode_optional_digest(&mut bytes)?;
            let phase = decode_receive_phase(take::<1>(&mut bytes)?[0])?;
            if take::<7>(&mut bytes)? != [0; 7] {
                return Err(GitModelError::CorruptEncoding);
            }
            let sealed = decode_optional_digest(&mut bytes)?;
            let validation = decode_optional_digest(&mut bytes)?;
            let publication = decode_optional_digest(&mut bytes)?
                .map(GitAtomicCasDigestV1::from_stored)
                .transpose()?;
            let failure = decode_optional_digest(&mut bytes)?;
            GitDurablePayloadV1::Receive(
                GitReceiveHistoryRecordV1::new(
                    revision,
                    predecessor,
                    plan,
                    phase,
                    sealed,
                    validation,
                    publication,
                    failure,
                )
                .map_err(|_| GitModelError::CorruptEncoding)?,
            )
        }
        GitDurableRecordKindV1::Publication => {
            let value = GitPublicationRecordV1::from_stored(
                ResourceId::from_bytes(take(&mut bytes)?),
                Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
                Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
                GitAtomicCasDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?,
                u64::from_be_bytes(take(&mut bytes)?),
            )?;
            GitDurablePayloadV1::Publication(value)
        }
        GitDurableRecordKindV1::Export => {
            let format = decode_format(take::<1>(&mut bytes)?[0])?;
            if take::<7>(&mut bytes)? != [0; 7] {
                return Err(GitModelError::CorruptEncoding);
            }
            let predecessor_generation = u64::from_be_bytes(take(&mut bytes)?);
            let predecessor_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
            let predecessor = match (predecessor_generation, predecessor_digest.as_bytes()) {
                (0, digest) if digest == &[0; 32] => None,
                (generation, digest)
                    if generation != 0 && generation != u64::MAX && digest != &[0; 32] =>
                {
                    Some((
                        Revision::new(generation),
                        GitExportGenerationDigestV1::from_stored(ObjectDigest::from_bytes(
                            *digest,
                        ))?,
                    ))
                }
                _ => return Err(GitModelError::CorruptEncoding),
            };
            let export = decode_export(&mut bytes, format, trusted_validator)?;
            GitDurablePayloadV1::Export(
                GitExportHistoryRecordV1::new(export, predecessor)
                    .map_err(|_| GitModelError::CorruptEncoding)?,
            )
        }
        GitDurableRecordKindV1::Pack => {
            bytes = &[];
            GitDurablePayloadV1::Pack(decode_pack_generation_payload_v1(
                encoded,
                trusted_validator,
            )?)
        }
        GitDurableRecordKindV1::PackLease => {
            GitDurablePayloadV1::PackLease(decode_pack_lease(&mut bytes)?)
        }
        GitDurableRecordKindV1::CheapFork => {
            let target = decode_repository(&mut bytes, trusted_validator)?;
            let source_repository = ResourceId::from_bytes(take(&mut bytes)?);
            let source_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
            let source_export = GitExportGenerationDigestV1::from_stored(
                ObjectDigest::from_bytes(take(&mut bytes)?),
            )?;
            let pack = GitPackGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(
                &mut bytes,
            )?))?;
            let lease = decode_pack_lease(&mut bytes)?;
            let observed_at = GitBoottimeV1::from_stored(u64::from_be_bytes(take(&mut bytes)?))?;
            let record_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
            let predecessor = decode_optional_raw_digest(&mut bytes)?;
            let status = match take::<1>(&mut bytes)?[0] {
                1 => GitCheapForkStatusV1::Attached,
                2 => GitCheapForkStatusV1::Detached,
                3 => GitCheapForkStatusV1::Converted,
                4 => GitCheapForkStatusV1::Tombstoned,
                _ => return Err(GitModelError::CorruptEncoding),
            };
            if take::<7>(&mut bytes)? != [0; 7] {
                return Err(GitModelError::CorruptEncoding);
            }
            let closed = u64::from_be_bytes(take(&mut bytes)?);
            let closed_at = (closed != 0)
                .then(|| GitBoottimeV1::from_stored(closed))
                .transpose()?;
            GitDurablePayloadV1::CheapFork(
                GitCheapForkV1::from_stored(
                    target,
                    source_repository,
                    source_revision,
                    source_export,
                    pack,
                    lease,
                    observed_at,
                    record_revision,
                    predecessor,
                    status,
                    closed_at,
                )
                .map_err(|_| GitModelError::CorruptEncoding)?,
            )
        }
    };
    if !bytes.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(payload)
}

fn encode_repository(
    bytes: &mut Vec<u8>,
    value: &GitRepositoryStateV1,
) -> Result<(), GitModelError> {
    let repository = value.repository();
    bytes.push(repository.format() as u8);
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(repository.repository().as_bytes());
    bytes.extend_from_slice(repository.project().as_bytes());
    bytes.extend_from_slice(repository.sandbox().as_bytes());
    bytes.extend_from_slice(repository.workspace().as_bytes());
    bytes.extend_from_slice(&repository.revision().get().to_be_bytes());
    encode_optional_digest(bytes, value.predecessor());
    encode_whole_database(bytes, value.database());
    encode_refs(bytes, value.refs());
    bytes.extend_from_slice(value.ref_map().digest().as_bytes());
    Ok(())
}

fn decode_repository(
    bytes: &mut &[u8],
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitRepositoryStateV1, GitModelError> {
    let format = decode_format(take::<1>(bytes)?[0])?;
    if take::<7>(bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let repository = GitRepositoryV1::new(
        ResourceId::from_bytes(take(bytes)?),
        ProjectId::from_bytes(take(bytes)?),
        SandboxId::from_bytes(take(bytes)?),
        ResourceId::from_bytes(take(bytes)?),
        format,
        Revision::new(u64::from_be_bytes(take(bytes)?)),
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    let predecessor = decode_optional_digest(bytes)?;
    let database = decode_whole_database(bytes, format, trusted_validator)?;
    let refs = decode_refs(bytes, format)?;
    let stored_ref_map = GitRefMapDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let state = GitRepositoryStateV1::new(repository, predecessor, refs, database)
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if state.ref_map() != stored_ref_map {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(state)
}

fn encode_pack_lease(bytes: &mut Vec<u8>, value: GitPackLeaseV1) {
    bytes.extend_from_slice(value.project().as_bytes());
    bytes.extend_from_slice(value.repository().as_bytes());
    bytes.extend_from_slice(value.pack_generation().as_bytes());
    bytes.extend_from_slice(&value.generation().get().to_be_bytes());
    bytes.extend_from_slice(value.generation_digest().digest().as_bytes());
    bytes.extend_from_slice(value.export().as_bytes());
    bytes.extend_from_slice(&value.export_generation().get().to_be_bytes());
    bytes.extend_from_slice(value.export_digest().digest().as_bytes());
    let (kind, consumer) = match value.consumer() {
        GitPackConsumerV1::Repository(identity) => (1, identity),
        GitPackConsumerV1::Export(identity) => (2, identity),
    };
    bytes.push(kind);
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(consumer.as_bytes());
    bytes.extend_from_slice(value.lease().as_bytes());
    bytes.extend_from_slice(&value.lease_revision().get().to_be_bytes());
    bytes.extend_from_slice(value.principal().as_bytes());
    bytes.extend_from_slice(value.boot().digest().as_bytes());
    bytes.extend_from_slice(&value.observed_at().get().to_be_bytes());
    bytes.extend_from_slice(&value.expires_at().to_be_bytes());
    bytes.extend_from_slice(value.pin_receipt().as_bytes());
    bytes.push(value.status() as u8);
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&value.closed_at().unwrap_or(0).to_be_bytes());
    bytes.extend_from_slice(
        value
            .predecessor_boot()
            .map_or(ObjectDigest::from_bytes([0; 32]), |boot| boot.digest())
            .as_bytes(),
    );
}

fn decode_pack_lease(bytes: &mut &[u8]) -> Result<GitPackLeaseV1, GitModelError> {
    let project = ProjectId::from_bytes(take(bytes)?);
    let repository = ResourceId::from_bytes(take(bytes)?);
    let pack_generation = ResourceId::from_bytes(take(bytes)?);
    let generation = Revision::new(u64::from_be_bytes(take(bytes)?));
    let generation_digest =
        GitPackGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let export = ResourceId::from_bytes(take(bytes)?);
    let export_generation = Revision::new(u64::from_be_bytes(take(bytes)?));
    let export_digest =
        GitExportGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let kind = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let consumer = match (kind, ResourceId::from_bytes(take(bytes)?)) {
        (1, identity) => GitPackConsumerV1::Repository(identity),
        (2, identity) => GitPackConsumerV1::Export(identity),
        _ => return Err(GitModelError::CorruptEncoding),
    };
    let lease = ResourceId::from_bytes(take(bytes)?);
    let lease_revision = Revision::new(u64::from_be_bytes(take(bytes)?));
    let principal = PrincipalId::from_bytes(take(bytes)?);
    let boot = super::GitBootIdV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let observed_at = GitBoottimeV1::from_stored(u64::from_be_bytes(take(bytes)?))?;
    let expires_at = u64::from_be_bytes(take(bytes)?);
    let pin_receipt = ObjectDigest::from_bytes(take(bytes)?);
    let status = match take::<1>(bytes)?[0] {
        1 => GitPackLeaseStatusV1::Active,
        2 => GitPackLeaseStatusV1::Released,
        3 => GitPackLeaseStatusV1::Expired,
        4 => GitPackLeaseStatusV1::Invalidated,
        _ => return Err(GitModelError::CorruptEncoding),
    };
    if take::<7>(bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let closed_at = match u64::from_be_bytes(take(bytes)?) {
        0 => None,
        value => Some(value),
    };
    let predecessor_raw = ObjectDigest::from_bytes(take(bytes)?);
    let predecessor_boot = (predecessor_raw.as_bytes() != &[0; 32])
        .then(|| super::GitBootIdV1::from_stored(predecessor_raw))
        .transpose()?;
    GitPackLeaseV1::from_stored(
        project,
        repository,
        pack_generation,
        generation,
        generation_digest,
        export,
        export_generation,
        export_digest,
        consumer,
        lease,
        lease_revision,
        principal,
        boot,
        observed_at,
        expires_at,
        pin_receipt,
        status,
        closed_at,
        predecessor_boot,
    )
}

fn preflight_payload(kind: GitDurableRecordKindV1, encoded: &[u8]) -> Result<(), GitModelError> {
    let mut bytes = encoded;
    match kind {
        GitDurableRecordKindV1::Repository => preflight_repository(&mut bytes)?,
        GitDurableRecordKindV1::Receive => {
            let length = read_length(&mut bytes)?;
            take_slice(&mut bytes, length)?;
            take_slice(&mut bytes, 8 + 40 + 8 + 40 * 4)?;
        }
        GitDurableRecordKindV1::Publication => take_slice(&mut bytes, 72)?,
        GitDurableRecordKindV1::Export => {
            take_slice(&mut bytes, 48)?;
            preflight_export(&mut bytes)?;
        }
        GitDurableRecordKindV1::Pack => {
            // The pack codec owns a complete no-allocation body preflight.
            bytes = &[];
        }
        GitDurableRecordKindV1::PackLease => take_slice(&mut bytes, 336)?,
        GitDurableRecordKindV1::CheapFork => {
            preflight_repository(&mut bytes)?;
            take_slice(&mut bytes, 88 + 336 + 8 + 56)?;
        }
    }
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(GitModelError::CorruptEncoding)
    }
}

fn preflight_repository(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    take_slice(bytes, 8 + 16 * 4 + 8 + 40)?;
    preflight_whole_database(bytes)?;
    let count = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if count > super::model::MAXIMUM_GIT_GRAPH_ROOTS {
        return Err(GitModelError::CorruptEncoding);
    }
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(take(bytes)?));
        if length == 0 || length > super::model::MAXIMUM_GIT_REF_BYTES {
            return Err(GitModelError::CorruptEncoding);
        }
        take_slice(
            bytes,
            length
                .checked_add(32)
                .ok_or(GitModelError::CorruptEncoding)?,
        )?;
    }
    take_slice(bytes, 32)?;
    Ok(())
}

fn encode_optional_digest(bytes: &mut Vec<u8>, value: Option<ObjectDigest>) {
    bytes.push(u8::from(value.is_some()));
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(
        value
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
}

fn decode_optional_digest(bytes: &mut &[u8]) -> Result<Option<ObjectDigest>, GitModelError> {
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    match (present, digest.as_bytes()) {
        (0, value) if value == &[0; 32] => Ok(None),
        (1, value) if value != &[0; 32] => Ok(Some(digest)),
        _ => Err(GitModelError::CorruptEncoding),
    }
}

fn decode_optional_raw_digest(bytes: &mut &[u8]) -> Result<Option<ObjectDigest>, GitModelError> {
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    Ok((digest.as_bytes() != &[0; 32]).then_some(digest))
}

fn push_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), GitModelError> {
    bytes.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| GitModelError::InvalidModel)?
            .to_be_bytes(),
    );
    Ok(())
}

fn read_length(bytes: &mut &[u8]) -> Result<usize, GitModelError> {
    let length = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if length == 0 || length > MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES {
        Err(GitModelError::CorruptEncoding)
    } else {
        Ok(length)
    }
}

fn decode_format(value: u8) -> Result<GitObjectFormatV1, GitModelError> {
    match value {
        1 => Ok(GitObjectFormatV1::Sha1),
        2 => Ok(GitObjectFormatV1::Sha256),
        _ => Err(GitModelError::CorruptEncoding),
    }
}

fn decode_receive_phase(value: u8) -> Result<GitReceivePhaseV1, GitModelError> {
    match value {
        1 => Ok(GitReceivePhaseV1::Admitted),
        2 => Ok(GitReceivePhaseV1::Quarantined),
        3 => Ok(GitReceivePhaseV1::Validated),
        4 => Ok(GitReceivePhaseV1::Published),
        5 => Ok(GitReceivePhaseV1::Rejected),
        _ => Err(GitModelError::CorruptEncoding),
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GitModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| GitModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], GitModelError> {
    let (head, tail) = bytes
        .split_at_checked(length)
        .ok_or(GitModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
