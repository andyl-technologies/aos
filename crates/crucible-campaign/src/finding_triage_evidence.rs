//! Durable replay inputs for reconstructing one observed finding signature.
//!
//! Every value uses a manifest over deterministic childless payload chunks.
//! The logical payload has its own canonical form inside that current storage
//! layout; it is never published as a root object.
//!
//! ```text
//! logical payload v1:
//!   u32 schema-version = 1
//!   ReproductionArtifactId reproduction
//!   FindingSignature observed-signature
//!   u32 payload-schema
//!   bytes payload
//!
//! manifest body v2:
//!   u32 schema-version = 2
//!   ReproductionArtifactId reproduction
//!   FindingSignature observed-signature
//!   u32 payload-schema
//!   u64 payload-bytes
//!   sequence (ContentId chunk, u32 chunk-bytes)
//!
//! chunk body v1:
//!   u32 schema-version = 1
//!   bytes payload
//! ```

use crucible_cas::content_store::{ByteRange, ContentId, ObjectKind};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    CampaignCodecError, CampaignRecordKind, FindingSignature, FindingTriageReplayEvidenceId,
    ObjectEnvelope, ReproductionArtifactId,
};

const LOGICAL_PAYLOAD_SCHEMA_VERSION: u32 = 1;
const MANIFEST_SCHEMA_VERSION: u32 = 2;
const CHUNK_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 84 * 1024 * 1024;
const PAYLOAD_CHUNK_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAYLOAD_CHUNKS: usize = 3;
const STORAGE_DESCRIPTION_SCHEMA_VERSION: u32 = 1;
const MAX_STORAGE_OBJECTS: usize = MAX_PAYLOAD_CHUNKS + 1;
const MAX_STORED_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum opaque execution-model payload retained by one replay record.
pub const MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES: usize = 80 * 1024 * 1024;

/// Maximum bytes returned by one replay-storage range read.
pub const MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES: u64 = 32 * 1024 * 1024;

/// Authenticated physical layout of one logical replay-evidence record.
///
/// The manifest root is followed by one to three payload chunks in logical
/// payload order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingTriageReplayStorageDescription {
    evidence: FindingTriageReplayEvidenceId,
    storage_schema_version: u32,
    logical_payload_bytes: u64,
    objects: Vec<FindingTriageReplayStorageObject>,
}

impl FindingTriageReplayStorageDescription {
    pub(crate) fn new(
        evidence: FindingTriageReplayEvidenceId,
        storage_schema_version: u32,
        logical_payload_bytes: u64,
        objects: Vec<FindingTriageReplayStorageObject>,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
            evidence,
            storage_schema_version,
            logical_payload_bytes,
            objects,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the logical evidence identity described by this layout.
    #[must_use]
    pub const fn evidence(&self) -> FindingTriageReplayEvidenceId {
        self.evidence
    }

    /// Returns the schema version of the stored root envelope.
    #[must_use]
    pub const fn storage_schema_version(&self) -> u32 {
        self.storage_schema_version
    }

    /// Returns the exact reassembled opaque payload length.
    #[must_use]
    pub const fn logical_payload_bytes(&self) -> u64 {
        self.logical_payload_bytes
    }

    /// Returns stored envelopes in root-then-payload order.
    #[must_use]
    pub fn objects(&self) -> &[FindingTriageReplayStorageObject] {
        &self.objects
    }

    /// Derives the canonical fixed-size segment range for one stored object.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the ordinal or content identity does
    /// not name the exact described position, or when `segment_index` is beyond
    /// the stored envelope.
    pub fn segment_range(
        &self,
        object_ordinal: u32,
        object_id: ContentId,
        segment_index: u32,
    ) -> Result<ByteRange, CampaignCodecError> {
        let object_index =
            usize::try_from(object_ordinal).map_err(|_| CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage object ordinal is invalid",
            })?;
        let object = self
            .objects
            .get(object_index)
            .filter(|object| object.ordinal == object_ordinal && object.content == object_id)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage object position is invalid",
            })?;
        let offset = u64::from(segment_index)
            .checked_mul(MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES)
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-storage-segment-offset",
            })?;
        if offset >= object.stored_envelope_bytes {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage segment index is out of bounds",
            });
        }
        Ok(ByteRange {
            offset,
            length: (object.stored_envelope_bytes - offset)
                .min(MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES),
        })
    }

    /// Returns strict canonical description bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes and validates strict canonical description bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Authenticates the root envelope and its complete storage layout.
    ///
    /// This verifies every described chunk identity and logical length before
    /// a caller requests chunk bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the description or root envelope is
    /// malformed, corrupt, inconsistent, noncanonical, or oversized.
    pub fn authenticate_root_envelope(&self, bytes: &[u8]) -> Result<(), CampaignCodecError> {
        self.authenticated_root(bytes).map(|_| ())
    }

    fn authenticated_root(
        &self,
        bytes: &[u8],
    ) -> Result<FindingTriageReplayManifest, CampaignCodecError> {
        self.validate()?;
        let root = authenticated_storage_envelope(&self.objects[0], bytes)?;
        if root.record_kind() != CampaignRecordKind::FindingTriageReplayEvidence
            || root.schema_version() != self.storage_schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage root envelope is invalid",
            });
        }

        if root.schema_version() != MANIFEST_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage root schema is invalid",
            });
        }
        let manifest = FindingTriageReplayManifest::from_canonical_bytes(root.body())?;
        self.validate_manifest_description(&manifest)?;
        Ok(manifest)
    }

    fn validate_manifest_description(
        &self,
        manifest: &FindingTriageReplayManifest,
    ) -> Result<(), CampaignCodecError> {
        let manifest_payload_bytes = u64::try_from(manifest.payload_bytes()?).map_err(|_| {
            CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-bytes",
            }
        })?;
        if manifest_payload_bytes != self.logical_payload_bytes
            || manifest.chunks().len() + 1 != self.objects.len()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage manifest description is invalid",
            });
        }

        for (index, manifest_chunk) in manifest.chunks().iter().copied().enumerate() {
            let object = &self.objects[index + 1];
            let FindingTriageReplayStorageObjectRole::PayloadChunk {
                index: described_index,
                logical_payload_bytes,
            } = object.role
            else {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding triage replay storage chunk role is invalid",
                });
            };
            if described_index as usize != index
                || object.content != manifest_chunk.content()
                || logical_payload_bytes != manifest_chunk.logical_bytes()
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding triage replay storage chunk description is invalid",
                });
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        if self.logical_payload_bytes == 0
            || self.logical_payload_bytes > MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES as u64
            || self.objects.is_empty()
            || self.objects.len() > MAX_STORAGE_OBJECTS
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage description bounds are invalid",
            });
        }
        let root = &self.objects[0];
        if root.ordinal != 0
            || root.role != FindingTriageReplayStorageObjectRole::Root
            || root.content != self.evidence.content_id()
            || root.stored_envelope_bytes == 0
            || root.stored_envelope_bytes > MAX_STORED_ENVELOPE_BYTES
            || self.evidence.content_id().schema_version() != self.storage_schema_version
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage root description is invalid",
            });
        }

        if self.storage_schema_version != MANIFEST_SCHEMA_VERSION || self.objects.len() <= 1 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage description schema is invalid",
            });
        }
        self.validate_chunk_objects()
    }

    fn validate_chunk_objects(&self) -> Result<(), CampaignCodecError> {
        let mut total_payload_bytes = 0_u64;
        let chunk_count = self.objects.len() - 1;
        for (position, object) in self.objects[1..].iter().enumerate() {
            let expected_ordinal =
                u32::try_from(position + 1).map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-storage-object-ordinal",
                })?;
            let expected_index =
                u32::try_from(position).map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-storage-object-ordinal",
                })?;
            let FindingTriageReplayStorageObjectRole::PayloadChunk {
                index,
                logical_payload_bytes,
            } = object.role
            else {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding triage replay storage chunk role is invalid",
                });
            };
            let logical_payload_bytes = logical_payload_bytes as u64;
            if object.ordinal != expected_ordinal
                || index != expected_index
                || object.content.kind() != ObjectKind::Finding
                || object.content.schema_version() != CHUNK_SCHEMA_VERSION
                || object.stored_envelope_bytes == 0
                || object.stored_envelope_bytes > MAX_STORED_ENVELOPE_BYTES
                || logical_payload_bytes == 0
                || logical_payload_bytes > PAYLOAD_CHUNK_BYTES as u64
                || (position + 1 < chunk_count
                    && logical_payload_bytes != PAYLOAD_CHUNK_BYTES as u64)
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding triage replay storage chunk description is invalid",
                });
            }
            total_payload_bytes = total_payload_bytes
                .checked_add(logical_payload_bytes)
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-payload-bytes",
                })?;
        }
        if total_payload_bytes != self.logical_payload_bytes {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage payload total is invalid",
            });
        }
        Ok(())
    }
}

impl Canonical for FindingTriageReplayStorageDescription {
    fn encode(&self, encoder: &mut Encoder) {
        STORAGE_DESCRIPTION_SCHEMA_VERSION.encode(encoder);
        self.evidence.encode(encoder);
        self.storage_schema_version.encode(encoder);
        self.logical_payload_bytes.encode(encoder);
        self.objects.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != STORAGE_DESCRIPTION_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding triage replay storage description schema version",
            });
        }
        Self::new(
            FindingTriageReplayEvidenceId::decode(decoder)?,
            u32::decode(decoder)?,
            u64::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_STORAGE_OBJECTS,
                "finding-triage-replay-storage-object-count",
                FindingTriageReplayStorageObject::decode,
            )?,
        )
    }
}

/// One exact stored envelope in a replay-evidence layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingTriageReplayStorageObject {
    ordinal: u32,
    role: FindingTriageReplayStorageObjectRole,
    content: ContentId,
    stored_envelope_bytes: u64,
}

impl FindingTriageReplayStorageObject {
    pub(crate) const fn new(
        ordinal: u32,
        role: FindingTriageReplayStorageObjectRole,
        content: ContentId,
        stored_envelope_bytes: u64,
    ) -> Self {
        Self {
            ordinal,
            role,
            content,
            stored_envelope_bytes,
        }
    }

    /// Returns this object's zero-based position in the described layout.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns this object's semantic position in the described layout.
    #[must_use]
    pub const fn role(&self) -> FindingTriageReplayStorageObjectRole {
        self.role
    }

    /// Returns the exact content identity of the stored envelope.
    #[must_use]
    pub const fn content(&self) -> ContentId {
        self.content
    }

    /// Returns the exact canonical length of the stored envelope.
    #[must_use]
    pub const fn stored_envelope_bytes(&self) -> u64 {
        self.stored_envelope_bytes
    }
}

impl Canonical for FindingTriageReplayStorageObject {
    fn encode(&self, encoder: &mut Encoder) {
        self.ordinal.encode(encoder);
        self.role.encode(encoder);
        Canonical::encode(&self.content, encoder);
        self.stored_envelope_bytes.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            ordinal: u32::decode(decoder)?,
            role: FindingTriageReplayStorageObjectRole::decode(decoder)?,
            content: ContentId::decode(decoder)?,
            stored_envelope_bytes: u64::decode(decoder)?,
        })
    }
}

/// Semantic position of one stored replay-evidence envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingTriageReplayStorageObjectRole {
    /// Current chunk manifest at ordinal zero.
    Root,
    /// One manifest payload chunk in logical payload order.
    PayloadChunk {
        /// Zero-based position within the logical payload.
        index: u32,
        /// Exact logical payload bytes carried by the chunk body.
        logical_payload_bytes: u32,
    },
}

impl Canonical for FindingTriageReplayStorageObjectRole {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Root => 0_u8.encode(encoder),
            Self::PayloadChunk {
                index,
                logical_payload_bytes,
            } => {
                1_u8.encode(encoder);
                index.encode(encoder);
                logical_payload_bytes.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Root),
            1 => Ok(Self::PayloadChunk {
                index: u32::decode(decoder)?,
                logical_payload_bytes: u32::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "finding-triage-replay-storage-object-role",
                tag,
            }),
        }
    }
}

/// One exact replay and the complete campaign signature it observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingTriageReplayEvidence {
    reproduction: ReproductionArtifactId,
    observed_signature: FindingSignature,
    payload_schema: u32,
    payload: Vec<u8>,
}

impl FindingTriageReplayEvidence {
    /// Builds one bounded replay-evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the payload schema is zero, the
    /// payload is empty or exceeds 80 MiB, or the complete record exceeds its
    /// canonical size bound.
    pub fn new(
        reproduction: ReproductionArtifactId,
        observed_signature: FindingSignature,
        payload_schema: u32,
        payload: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        if payload_schema == 0 || payload.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay payload is empty or has no schema",
            });
        }
        if payload.len() > MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-bytes",
            });
        }
        let value = Self {
            reproduction,
            observed_signature,
            payload_schema,
            payload,
        };
        value.validate_encoded_size()?;
        Ok(value)
    }

    /// Returns the exact reproduction executed by this replay.
    #[must_use]
    pub const fn reproduction(&self) -> ReproductionArtifactId {
        self.reproduction
    }

    /// Returns the complete campaign finding signature observed by the replay.
    #[must_use]
    pub const fn observed_signature(&self) -> &FindingSignature {
        &self.observed_signature
    }

    /// Returns the execution-model payload schema.
    #[must_use]
    pub const fn payload_schema(&self) -> u32 {
        self.payload_schema
    }

    /// Returns the opaque execution-model replay payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns strict canonical logical record bytes.
    ///
    /// These are the logical payload bytes reconstructed from the current
    /// manifest and its authenticated chunks.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical logical record bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(
            bytes,
            MAX_RECORD_BYTES,
            "finding-triage-replay-evidence-encoded-bytes",
        )
    }

    /// Reassembles logical evidence from its authenticated stored envelopes.
    ///
    /// `envelopes` must follow the exact root-then-payload order in
    /// `description`. Every canonical envelope, content identity, record kind,
    /// schema version, chunk position, chunk length, and final logical evidence
    /// identity is recomputed before the value is returned.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the description or any envelope is
    /// malformed, missing, reordered, corrupt, inconsistent, or oversized.
    pub fn from_storage_envelopes(
        description: &FindingTriageReplayStorageDescription,
        envelopes: &[Vec<u8>],
    ) -> Result<Self, CampaignCodecError> {
        if envelopes.len() != description.objects.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay stored envelope count is invalid",
            });
        }
        let root = description.authenticated_root(&envelopes[0])?;

        let evidence = {
            let manifest = root;
            let payload_bytes = manifest.payload_bytes()?;
            let mut payload = Vec::new();
            payload.try_reserve_exact(payload_bytes).map_err(|_| {
                CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-payload-allocation",
                }
            })?;
            for (index, _) in manifest.chunks().iter().enumerate() {
                let object = &description.objects[index + 1];
                let FindingTriageReplayStorageObjectRole::PayloadChunk {
                    logical_payload_bytes,
                    ..
                } = object.role
                else {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finding triage replay storage chunk role is invalid",
                    });
                };
                let chunk = authenticated_storage_envelope(object, &envelopes[index + 1])?;
                if chunk.record_kind() != CampaignRecordKind::FindingTriageReplayEvidenceChunk
                    || chunk.schema_version() != CHUNK_SCHEMA_VERSION
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finding triage replay storage chunk envelope is invalid",
                    });
                }
                let bytes = FindingTriageReplayChunk::from_canonical_bytes(chunk.body())?.payload;
                if bytes.len() != logical_payload_bytes as usize {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finding triage replay storage chunk length is invalid",
                    });
                }
                payload.extend_from_slice(&bytes);
            }
            manifest.into_evidence(payload)?
        };
        if evidence.payload.len() as u64 != description.logical_payload_bytes
            || evidence.id()?.content_id() != description.evidence.content_id()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay reassembled identity is invalid",
            });
        }
        Ok(evidence)
    }

    /// Returns the exact stored replay-evidence identity.
    ///
    /// The identity is always the deterministic chunk-manifest root identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<FindingTriageReplayEvidenceId, CampaignCodecError> {
        FindingTriageReplayEvidenceId::from_content_id(self.storage_plan()?.root.content_id())
    }

    pub(crate) fn storage_plan(
        &self,
    ) -> Result<FindingTriageReplayStoragePlan, CampaignCodecError> {
        self.chunked_storage_plan()
    }

    pub(crate) fn chunk_envelope(
        &self,
        index: usize,
        expected: FindingTriageReplayChunkDescriptor,
    ) -> Result<ObjectEnvelope, CampaignCodecError> {
        let start =
            index
                .checked_mul(PAYLOAD_CHUNK_BYTES)
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-payload-chunk-offset",
                })?;
        let end = start.checked_add(expected.logical_bytes() as usize).ok_or(
            CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-chunk-offset",
            },
        )?;
        let bytes = self
            .payload
            .get(start..end)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "finding triage replay payload chunk range is invalid",
            })?;
        let envelope = FindingTriageReplayChunk::new(bytes.to_vec())?.envelope()?;
        if envelope.content_id() != expected.content() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay payload chunk identity disagrees with plan",
            });
        }
        Ok(envelope)
    }

    pub(crate) fn storage_content_children(
        body: &[u8],
    ) -> Result<Vec<(String, ContentId)>, CampaignCodecError> {
        FindingTriageReplayManifest::from_canonical_bytes(body).map(|manifest| manifest.children())
    }

    pub(crate) fn manifest_from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<FindingTriageReplayManifest, CampaignCodecError> {
        FindingTriageReplayManifest::from_canonical_bytes(bytes)
    }

    pub(crate) fn chunk_from_canonical_bytes(bytes: &[u8]) -> Result<Vec<u8>, CampaignCodecError> {
        FindingTriageReplayChunk::from_canonical_bytes(bytes).map(|chunk| chunk.payload)
    }

    fn validate_encoded_size(&self) -> Result<(), CampaignCodecError> {
        let mut metadata = Encoder::new();
        LOGICAL_PAYLOAD_SCHEMA_VERSION.encode(&mut metadata);
        self.reproduction.encode(&mut metadata);
        self.observed_signature.encode(&mut metadata);
        self.payload_schema.encode(&mut metadata);
        0_u64.encode(&mut metadata);
        let encoded_bytes = metadata
            .finish()
            .len()
            .checked_add(self.payload.len())
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-evidence-encoded-bytes",
            })?;
        if encoded_bytes > MAX_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-evidence-encoded-bytes",
            });
        }
        Ok(())
    }

    fn chunked_storage_plan(&self) -> Result<FindingTriageReplayStoragePlan, CampaignCodecError> {
        let mut chunks = Vec::with_capacity(MAX_PAYLOAD_CHUNKS);
        for bytes in self.payload.chunks(PAYLOAD_CHUNK_BYTES) {
            let envelope = FindingTriageReplayChunk::new(bytes.to_vec())?.envelope()?;
            chunks.push(FindingTriageReplayChunkDescriptor::new(
                envelope.content_id(),
                u32::try_from(bytes.len()).map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-payload-chunk-bytes",
                })?,
            ));
        }
        let manifest = FindingTriageReplayManifest::new(
            self.reproduction,
            self.observed_signature.clone(),
            self.payload_schema,
            self.payload.len(),
            chunks.clone(),
        )?;
        let root = ObjectEnvelope::for_record_versioned(
            CampaignRecordKind::FindingTriageReplayEvidence,
            MANIFEST_SCHEMA_VERSION,
            crate::object::content_children(manifest.children())?,
            manifest.canonical_bytes(),
        )?;

        // Exercise the ordinary structural validator before publication starts.
        if ObjectEnvelope::from_canonical_bytes(&root.canonical_bytes())? != root {
            return Err(CampaignCodecError::NonCanonical);
        }
        Ok(FindingTriageReplayStoragePlan { root, chunks })
    }

    #[cfg(test)]
    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        evidence_children(self.reproduction, &self.observed_signature)
    }
}

impl Canonical for FindingTriageReplayEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        LOGICAL_PAYLOAD_SCHEMA_VERSION.encode(encoder);
        self.reproduction.encode(encoder);
        self.observed_signature.encode(encoder);
        self.payload_schema.encode(encoder);
        self.payload.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != LOGICAL_PAYLOAD_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding triage replay evidence schema version",
            });
        }
        Self::new(
            ReproductionArtifactId::decode(decoder)?,
            FindingSignature::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES,
                "finding-triage-replay-payload-bytes",
                u8::decode,
            )?,
        )
    }
}

pub(crate) struct FindingTriageReplayStoragePlan {
    pub(crate) root: ObjectEnvelope,
    pub(crate) chunks: Vec<FindingTriageReplayChunkDescriptor>,
}

mod storage;

#[cfg(test)]
use storage::evidence_children;
use storage::{FindingTriageReplayChunk, authenticated_storage_envelope};
pub(crate) use storage::{
    FindingTriageReplayChunkDescriptor, FindingTriageReplayManifest,
    validate_finding_triage_replay_chunk_body,
};

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;
    use crate::{CampaignHash, FindingKind};

    fn fixture() -> (ReproductionArtifactId, FindingSignature) {
        let reproduction = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"triage-replay-reproduction",
        ))
        .expect("reproduction ID");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::derive("test", b"triage-replay-fingerprint"),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature");

        (reproduction, signature)
    }

    #[test]
    fn replay_evidence_round_trip_preserves_exact_native_payload() {
        let (reproduction, signature) = fixture();
        let evidence = FindingTriageReplayEvidence::new(
            reproduction,
            signature,
            7,
            b"versioned native replay payload".to_vec(),
        )
        .expect("triage replay evidence");

        let decoded =
            FindingTriageReplayEvidence::from_canonical_bytes(&evidence.canonical_bytes())
                .expect("decode triage replay evidence");
        assert_eq!(decoded, evidence);
        assert_eq!(decoded.payload_schema(), 7);
        assert_eq!(decoded.payload(), b"versioned native replay payload");
        assert_eq!(decoded.content_children().len(), 1);
    }

    #[test]
    fn maximum_replay_evidence_has_three_bounded_chunks() {
        let (reproduction, signature) = fixture();
        let evidence = FindingTriageReplayEvidence::new(
            reproduction,
            signature,
            1,
            vec![b'm'; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES],
        )
        .expect("maximum replay evidence");
        let logical_bytes = evidence.canonical_bytes();
        assert!(logical_bytes.len() > codec::MAX_CANONICAL_BYTES);
        assert_eq!(
            FindingTriageReplayEvidence::from_canonical_bytes(&logical_bytes)
                .expect("decode maximum logical evidence"),
            evidence
        );
        drop(logical_bytes);
        let plan = evidence.storage_plan().expect("maximum storage plan");

        assert_eq!(plan.root.schema_version(), MANIFEST_SCHEMA_VERSION);
        assert_eq!(plan.chunks.len(), MAX_PAYLOAD_CHUNKS);
        assert_eq!(plan.chunks[0].logical_bytes(), PAYLOAD_CHUNK_BYTES as u32);
        assert_eq!(plan.chunks[1].logical_bytes(), PAYLOAD_CHUNK_BYTES as u32);
        assert_eq!(plan.chunks[2].logical_bytes(), 16 * 1024 * 1024);
        assert_eq!(
            plan.chunks
                .iter()
                .map(|chunk| chunk.logical_bytes() as usize)
                .sum::<usize>(),
            MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES
        );
    }

    #[test]
    fn replay_manifest_rejects_wrong_kind_order_length_and_total() {
        let (reproduction, signature) = fixture();
        let first = FindingTriageReplayChunkDescriptor::new(
            ContentId::for_bytes(ObjectKind::Finding, CHUNK_SCHEMA_VERSION, b"first"),
            PAYLOAD_CHUNK_BYTES as u32,
        );
        let last = FindingTriageReplayChunkDescriptor::new(
            ContentId::for_bytes(ObjectKind::Finding, CHUNK_SCHEMA_VERSION, b"last"),
            1,
        );
        assert!(
            FindingTriageReplayManifest::new(
                reproduction,
                signature.clone(),
                1,
                PAYLOAD_CHUNK_BYTES + 1,
                vec![last, first],
            )
            .is_err()
        );

        let wrong_kind = FindingTriageReplayChunkDescriptor::new(
            ContentId::for_bytes(ObjectKind::Trace, CHUNK_SCHEMA_VERSION, b"wrong kind"),
            1,
        );
        assert!(
            FindingTriageReplayManifest::new(
                reproduction,
                signature.clone(),
                1,
                1,
                vec![wrong_kind],
            )
            .is_err()
        );
        assert!(
            FindingTriageReplayManifest::new(
                reproduction,
                signature.clone(),
                1,
                PAYLOAD_CHUNK_BYTES,
                vec![first, last],
            )
            .is_err()
        );
        assert!(
            FindingTriageReplayManifest::new(
                reproduction,
                signature,
                1,
                4,
                vec![last; MAX_PAYLOAD_CHUNKS + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn replay_chunk_decoder_rejects_corrupt_and_oversized_bodies() {
        let chunk =
            FindingTriageReplayChunk::new(b"authenticated chunk".to_vec()).expect("chunk record");
        let mut corrupt = chunk.canonical_bytes();
        corrupt.push(0);
        assert!(FindingTriageReplayEvidence::chunk_from_canonical_bytes(&corrupt).is_err());

        let mut oversized = Encoder::new();
        CHUNK_SCHEMA_VERSION.encode(&mut oversized);
        (PAYLOAD_CHUNK_BYTES as u64 + 1).encode(&mut oversized);
        assert!(
            FindingTriageReplayEvidence::chunk_from_canonical_bytes(&oversized.finish()).is_err()
        );
    }

    #[test]
    fn replay_evidence_rejects_empty_unversioned_and_oversized_payloads() {
        let (reproduction, signature) = fixture();
        assert!(
            FindingTriageReplayEvidence::new(
                reproduction,
                signature.clone(),
                0,
                b"payload".to_vec(),
            )
            .is_err()
        );
        assert!(
            FindingTriageReplayEvidence::new(reproduction, signature.clone(), 1, Vec::new())
                .is_err()
        );
        assert!(
            FindingTriageReplayEvidence::new(
                reproduction,
                signature,
                1,
                vec![0; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES + 1],
            )
            .is_err()
        );
    }
}
