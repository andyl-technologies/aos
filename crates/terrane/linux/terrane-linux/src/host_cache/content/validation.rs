//! Validates complete upload context before native admission or deduplication.

use super::{NativeContentStore, native_failure};
use crate::host_cache::{
    NativeAdmissionHandoffError, NativeChunkAdmissionError, NativeConsumerLease,
    NativeMetadataAdmissionError,
};
use std::io;
use terrane_format::{
    codec::{Codec, CodecError, parse_envelope},
    identity::{Descriptor, Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    codec::FrameError,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::{
        ChunkPosition, ChunkUpload, ContentStore, ContentValidator, CorruptSubject, InvalidReason,
        MetaUpload, StoreErrorKind, StoreFailure, TokioLocalFs,
    },
};

impl NativeContentStore {
    pub(super) async fn put_chunk(
        &self,
        upload: ChunkUpload<'_>,
    ) -> Result<Identity, StoreFailure> {
        if upload.profile != self.ready.layout().layout().chunk_profile() {
            return Err(invalid("CDC-3"));
        }
        if upload.encoded.len() > self.max_allocation_bytes
            || upload.declared_plaintext_len > self.max_allocation_bytes
        {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        let mut leases = Vec::new();
        let result = async {
            let envelope = parse_envelope(upload.encoded)
                .map_err(|error| invalid_chunk(FrameError::Envelope(error)))?;
            let dictionary = if let Codec::ZstdDictionary(digest) = envelope.codec {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Chunk, &digest)
                    .map_err(|_| invalid("CDC-9"))?;
                let lease = self.pin(&identity).await.map_err(|error| {
                    if matches!(error.kind(), StoreErrorKind::Absent(_)) {
                        invalid("CDC-9")
                    } else {
                        error
                    }
                })?;
                leases.push(lease);
                let lease = &leases[leases.len() - 1];
                let encoded = lease
                    .read_encoded()
                    .map_err(|error| native_failure(error, &identity))?;
                if matches!(
                    parse_envelope(&encoded)
                        .map_err(|_| invalid("CDC-9"))?
                        .codec,
                    Codec::ZstdDictionary(_)
                ) {
                    return Err(invalid("CDC-9"));
                }
                Some(
                    lease
                        .read_verified()
                        .map_err(|error| native_failure(error, &identity))?,
                )
            } else {
                None
            };
            let verified = terrane_sdk::codec::decode_verified(
                upload.encoded,
                upload.declared_plaintext_len,
                upload.profile,
                upload.position == ChunkPosition::Final,
                upload.identity,
                dictionary.as_deref(),
            )
            .map_err(invalid_chunk)?;
            if verified.plaintext().is_empty() {
                return Ok(upload.identity.clone());
            }
            // Validation precedes membership even when another encoding of this
            // plaintext already has actual cached or sealed native backing.
            match self.get(upload.identity, None).await {
                Ok(_) => return Ok(upload.identity.clone()),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {}
                Err(error) => return Err(error),
            }
            let descriptor =
                Descriptor::from_identity(&TERRANE_V1, upload.identity, verified.plaintext())
                    .map_err(|_| invalid("CDC-14"))?;
            match self
                .ready
                .owner()
                .admit_chunk(descriptor, upload.position, upload.encoded.to_vec())
                .await
            {
                Ok(admission) => {
                    admission
                        .into_cache(self.ready.owner())
                        .await
                        .map_err(|error| handoff_failure(error, upload.identity))?;
                    Ok(upload.identity.clone())
                }
                Err(NativeChunkAdmissionError::Accepted(error))
                    if error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    self.get(upload.identity, None).await?;
                    Ok(upload.identity.clone())
                }
                Err(
                    NativeChunkAdmissionError::Accepted(error)
                    | NativeChunkAdmissionError::Unsubmitted { error, .. },
                ) => Err(native_failure(error, upload.identity)),
            }
        }
        .await;
        self.finish(result, leases).await
    }

    pub(super) async fn put_meta(&self, upload: MetaUpload<'_>) -> Result<Identity, StoreFailure> {
        if upload.bytes().len() > self.max_allocation_bytes {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        self.validator.validate_meta(&upload)?;
        let requirements = self.validator.chunk_requirements(&upload)?;
        if requirements.len() > self.max_requests {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        let identity = TERRANE_V1
            .calculate(upload.kind(), upload.bytes())
            .map_err(|_| invalid("STORE-33"))?;
        let kind = entry_kind(upload.kind())
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        let mut leases: Vec<NativeConsumerLease> = Vec::with_capacity(requirements.len());
        let result = async {
            let profile = self.ready.layout().layout().chunk_profile();
            for requirement in requirements {
                if requirement.identity.kind() != IdentityKind::Chunk
                    || requirement.identity.profile() != TERRANE_V1.name()
                {
                    return Err(invalid("STORE-33"));
                }
                let plaintext = if requirement.identity == empty_chunk()? {
                    Vec::new()
                } else {
                    // Repeated references share this request's original grant.
                    // Each position still verifies actual bytes and its own CDC
                    // context; reference count must not multiply durable pins.
                    let index = match leases
                        .iter()
                        .position(|lease| lease.identity() == &requirement.identity)
                    {
                        Some(index) => index,
                        None => {
                            let lease = self.pin(&requirement.identity).await.map_err(|error| {
                                if matches!(error.kind(), StoreErrorKind::Absent(_)) {
                                    invalid(requirement.missing_rule_id)
                                } else {
                                    error
                                }
                            })?;
                            leases.push(lease);
                            leases.len() - 1
                        }
                    };
                    leases[index]
                        .read_verified()
                        .map_err(|error| native_failure(error, &requirement.identity))?
                };
                if plaintext.len() != requirement.declared_plaintext_len {
                    return Err(invalid("CDC-12"));
                }
                if requirement.position == ChunkPosition::Final {
                    if profile.first_boundary(&plaintext) != plaintext.len() {
                        return Err(invalid("CDC-19"));
                    }
                } else if plaintext.len() < profile.minimum() {
                    return Err(invalid("CDC-15"));
                } else if !profile.valid_nonfinal_chunk(&plaintext) {
                    return Err(invalid("CDC-16"));
                }
            }
            match self.ready.metadata().get(&identity).await {
                Ok(existing) if existing == upload.bytes() => return Ok(identity.clone()),
                Ok(_) => {
                    return Err(StoreFailure::new(StoreErrorKind::Corrupt(
                        CorruptSubject::Identity(identity.clone()),
                    )));
                }
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {}
                Err(error) => return Err(error),
            }
            let id = PackId::generate(&TokioLocalFs)
                .await
                .map_err(|error| native_failure(error, &identity))?;
            let mut writer = PackWriter::new(id, PackClass::Meta, false);
            writer.append_raw(kind, upload.bytes()).map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Invalid(InvalidReason::Upload {
                        rule_id: "STORE-33",
                    }),
                    error,
                )
            })?;
            let pack = writer.seal().map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Invalid(InvalidReason::Upload {
                        rule_id: "STORE-33",
                    }),
                    error,
                )
            })?;
            let admission = self
                .ready
                .owner()
                .admit_metadata_pack(id, pack.bytes().to_vec(), pack.index_object().to_vec())
                .await
                .map_err(|error| {
                    let (NativeMetadataAdmissionError::Accepted(error)
                    | NativeMetadataAdmissionError::Unsubmitted { error, .. }) = error;
                    native_failure(error, &identity)
                })?;
            admission
                .into_cache(self.ready.owner())
                .await
                .map_err(|error| handoff_failure(error, &identity))?;
            Ok(identity.clone())
        }
        .await;
        self.finish(result, leases).await
    }
}

pub(super) fn empty_chunk() -> Result<Identity, StoreFailure> {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, &[])
        .map_err(|error| StoreFailure::with_source(StoreErrorKind::Unsupported, error))
}

fn handoff_failure<A>(error: NativeAdmissionHandoffError<A>, identity: &Identity) -> StoreFailure {
    let (NativeAdmissionHandoffError::Accepted(error)
    | NativeAdmissionHandoffError::Unsubmitted { error, .. }) = error;
    native_failure(error, identity)
}

fn entry_kind(kind: IdentityKind) -> Option<EntryKind> {
    Some(match kind {
        IdentityKind::Chunk | IdentityKind::Pack => return None,
        IdentityKind::Manifest => EntryKind::Manifest,
        IdentityKind::Node => EntryKind::Node,
        IdentityKind::Commit => EntryKind::Commit,
        IdentityKind::Bundle => EntryKind::Bundle,
        IdentityKind::Index => EntryKind::Index,
        IdentityKind::Filter => EntryKind::Filter,
        IdentityKind::Attribute => EntryKind::Attribute,
        IdentityKind::Policy => EntryKind::Policy,
        IdentityKind::Memo => EntryKind::Memo,
    })
}

fn invalid(rule_id: &'static str) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }))
}

fn invalid_chunk(error: FrameError) -> StoreFailure {
    let rule_id = match &error {
        FrameError::NonfinalChunkTooShort => "CDC-15",
        FrameError::BoundaryMismatch => "CDC-16",
        FrameError::MissingDictionary | FrameError::WrongDictionary => "CDC-9",
        FrameError::WrongIdentityKind | FrameError::Identity(_) => "CDC-14",
        FrameError::ContentSizeMismatch
        | FrameError::PlaintextLengthMismatch
        | FrameError::Envelope(
            CodecError::DeclaredLengthTooLarge | CodecError::RawLengthMismatch,
        ) => "CDC-12",
        FrameError::Envelope(CodecError::CompressedLengthTooLarge) => "CDC-13",
        _ => "CDC-7",
    };
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }),
        error,
    )
}
