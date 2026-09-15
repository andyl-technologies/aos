//! Authenticated inline, manifest, and chunk storage records.

use super::*;

pub(super) enum AuthenticatedFindingTriageReplayRoot {
    Inline(FindingTriageReplayEvidence),
    Manifest(FindingTriageReplayManifest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FindingTriageReplayChunkDescriptor {
    content: ContentId,
    logical_bytes: u32,
}

impl FindingTriageReplayChunkDescriptor {
    pub(crate) const fn new(content: ContentId, logical_bytes: u32) -> Self {
        Self {
            content,
            logical_bytes,
        }
    }

    pub(crate) const fn content(self) -> ContentId {
        self.content
    }

    pub(crate) const fn logical_bytes(self) -> u32 {
        self.logical_bytes
    }
}

impl Canonical for FindingTriageReplayChunkDescriptor {
    fn encode(&self, encoder: &mut Encoder) {
        Canonical::encode(&self.content, encoder);
        self.logical_bytes.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            content: ContentId::decode(decoder)?,
            logical_bytes: u32::decode(decoder)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FindingTriageReplayManifest {
    schema_version: u32,
    reproduction: ReproductionArtifactId,
    observed_signature: FindingSignature,
    payload_schema: u32,
    payload_bytes: u64,
    chunks: Vec<FindingTriageReplayChunkDescriptor>,
}

impl FindingTriageReplayManifest {
    pub(crate) fn new(
        reproduction: ReproductionArtifactId,
        observed_signature: FindingSignature,
        payload_schema: u32,
        payload_bytes: usize,
        chunks: Vec<FindingTriageReplayChunkDescriptor>,
    ) -> Result<Self, CampaignCodecError> {
        if payload_schema == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay manifest has no payload schema",
            });
        }
        let payload_bytes =
            u64::try_from(payload_bytes).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-bytes",
            })?;
        validate_chunk_descriptors(payload_bytes, &chunks)?;
        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            reproduction,
            observed_signature,
            payload_schema,
            payload_bytes,
            chunks,
        })
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    pub(crate) fn chunks(&self) -> &[FindingTriageReplayChunkDescriptor] {
        &self.chunks
    }

    pub(crate) const fn reproduction(&self) -> ReproductionArtifactId {
        self.reproduction
    }

    pub(crate) const fn observed_signature(&self) -> &FindingSignature {
        &self.observed_signature
    }

    pub(crate) fn payload_bytes(&self) -> Result<usize, CampaignCodecError> {
        usize::try_from(self.payload_bytes).map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-payload-bytes",
        })
    }

    pub(crate) fn into_evidence(
        self,
        payload: Vec<u8>,
    ) -> Result<FindingTriageReplayEvidence, CampaignCodecError> {
        if payload.len() != self.payload_bytes()? {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay payload length disagrees with manifest",
            });
        }
        FindingTriageReplayEvidence::new(
            self.reproduction,
            self.observed_signature,
            self.payload_schema,
            payload,
        )
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    pub(crate) fn children(&self) -> Vec<(String, ContentId)> {
        let mut children = evidence_children(self.reproduction, &self.observed_signature);
        children.extend(
            self.chunks
                .iter()
                .enumerate()
                .map(|(index, chunk)| (chunk_role(index), chunk.content)),
        );
        children
    }
}

impl Canonical for FindingTriageReplayManifest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.reproduction.encode(encoder);
        self.observed_signature.encode(encoder);
        self.payload_schema.encode(encoder);
        self.payload_bytes.encode(encoder);
        self.chunks.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != MANIFEST_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding triage replay manifest schema version",
            });
        }
        Self::new(
            ReproductionArtifactId::decode(decoder)?,
            FindingSignature::decode(decoder)?,
            u32::decode(decoder)?,
            usize::try_from(u64::decode(decoder)?).map_err(|_| {
                CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-payload-bytes",
                }
            })?,
            decoder.sequence_bounded(
                MAX_PAYLOAD_CHUNKS,
                "finding-triage-replay-payload-chunk-count",
                FindingTriageReplayChunkDescriptor::decode,
            )?,
        )
    }
}

pub(super) struct FindingTriageReplayChunk {
    schema_version: u32,
    pub(super) payload: Vec<u8>,
}

impl FindingTriageReplayChunk {
    pub(super) fn new(payload: Vec<u8>) -> Result<Self, CampaignCodecError> {
        if payload.is_empty() || payload.len() > PAYLOAD_CHUNK_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-chunk-bytes",
            });
        }
        Ok(Self {
            schema_version: CHUNK_SCHEMA_VERSION,
            payload,
        })
    }

    pub(super) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    pub(super) fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    pub(super) fn envelope(&self) -> Result<ObjectEnvelope, CampaignCodecError> {
        ObjectEnvelope::for_record_versioned(
            CampaignRecordKind::FindingTriageReplayEvidenceChunk,
            CHUNK_SCHEMA_VERSION,
            Default::default(),
            self.canonical_bytes(),
        )
    }
}

impl Canonical for FindingTriageReplayChunk {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.payload.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != CHUNK_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding triage replay chunk schema version",
            });
        }
        Self::new(decoder.sequence_bounded(
            PAYLOAD_CHUNK_BYTES,
            "finding-triage-replay-payload-chunk-bytes",
            u8::decode,
        )?)
    }
}

pub(crate) fn validate_finding_triage_replay_chunk_body(
    body: &[u8],
) -> Result<(), CampaignCodecError> {
    FindingTriageReplayChunk::from_canonical_bytes(body).map(|_| ())
}

fn validate_chunk_descriptors(
    payload_bytes: u64,
    chunks: &[FindingTriageReplayChunkDescriptor],
) -> Result<(), CampaignCodecError> {
    if chunks.is_empty() || chunks.len() > MAX_PAYLOAD_CHUNKS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-payload-chunk-count",
        });
    }
    let mut total = 0_u64;
    for (index, chunk) in chunks.iter().enumerate() {
        let length = chunk.logical_bytes as usize;
        if length == 0
            || length > PAYLOAD_CHUNK_BYTES
            || (index + 1 < chunks.len() && length != PAYLOAD_CHUNK_BYTES)
            || chunk.content.kind() != ObjectKind::Finding
            || chunk.content.schema_version() != CHUNK_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay payload chunk descriptor is invalid",
            });
        }
        total = total
            .checked_add(length as u64)
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-bytes",
            })?;
    }
    if total != payload_bytes
        || payload_bytes == 0
        || payload_bytes > MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES as u64
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "finding triage replay payload length disagrees with chunk descriptors",
        });
    }
    Ok(())
}

pub(super) fn evidence_children(
    reproduction: ReproductionArtifactId,
    observed_signature: &FindingSignature,
) -> Vec<(String, ContentId)> {
    let mut children = vec![("reproduction".to_owned(), reproduction.content_id())];
    children.extend(crate::finding_candidate::signature_children(
        "observed-signature",
        observed_signature,
    ));
    children
}

pub(super) fn chunk_role(index: usize) -> String {
    format!("payload-chunk-{index:06}")
}

pub(super) fn encoded_schema_version(bytes: &[u8]) -> Result<u32, CampaignCodecError> {
    bytes
        .get(..std::mem::size_of::<u32>())
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(CampaignCodecError::Truncated)
}

pub(super) fn authenticated_storage_envelope(
    description: &FindingTriageReplayStorageObject,
    bytes: &[u8],
) -> Result<ObjectEnvelope, CampaignCodecError> {
    if bytes.len() as u64 != description.stored_envelope_bytes {
        return Err(CampaignCodecError::InvalidValue {
            reason: "finding triage replay stored envelope length is invalid",
        });
    }
    let envelope = ObjectEnvelope::from_canonical_bytes(bytes)?;
    if envelope.content_id() != description.content {
        return Err(CampaignCodecError::InvalidValue {
            reason: "finding triage replay stored envelope identity is invalid",
        });
    }
    Ok(envelope)
}
