//! Segmented reads for replay evidence owned by one finding occurrence.
//!
//! The service returns stored envelope bytes rather than the logical replay
//! value. Clients authenticate and reassemble the complete root and any chunk
//! envelopes before decoding or exposing replay evidence.

use crucible_cas::content_store::{ContentId, ObjectKind};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    CampaignCodecError, CampaignHash, CampaignName, CampaignPrincipal, CampaignSnapshot,
    CampaignSnapshotId, Finding, FindingCandidateBundle, FindingCandidateBundleId, FindingId,
    FindingTriageReplayEvidenceId, FindingTriageReplayStorageDescription,
    MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES, MerkleMap, MerkleMapLookupProof,
};

use super::{
    CAMPAIGN_SERVICE_SCHEMA_VERSION, decode_message, ensure_message_size, require_service_version,
    service_request_digest,
};

const MAX_STORAGE_DESCRIPTION_BYTES: usize = 16 * 1024;
const MAX_STORAGE_OBJECT_ORDINAL: u32 = 3;
const MAX_STORAGE_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Closed replay-evidence role addressable through segmented storage reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignFindingTriageReplayRole {
    /// The minimization pass replay of the original reproduction.
    MinimizationOriginal,
    /// The minimization pass replay of the selected reproduction.
    MinimizationSelected,
    /// The verification pass replay of the original reproduction.
    VerificationOriginal,
    /// The verification pass replay of the selected reproduction.
    VerificationSelected,
}

impl CampaignFindingTriageReplayRole {
    pub(super) fn evidence(
        self,
        bundle: &FindingCandidateBundle,
    ) -> Option<FindingTriageReplayEvidenceId> {
        let evidence = bundle.triage_evidence()?;
        Some(match self {
            Self::MinimizationOriginal => evidence.minimization_original(),
            Self::MinimizationSelected => evidence.minimization_selected(),
            Self::VerificationOriginal => evidence.verification_original(),
            Self::VerificationSelected => evidence.verification_selected(),
        })
    }
}

impl Canonical for CampaignFindingTriageReplayRole {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::MinimizationOriginal => 0,
            Self::MinimizationSelected => 1,
            Self::VerificationOriginal => 2,
            Self::VerificationSelected => 3,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::MinimizationOriginal),
            1 => Ok(Self::MinimizationSelected),
            2 => Ok(Self::VerificationOriginal),
            3 => Ok(Self::VerificationSelected),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-finding-triage-replay-role",
                tag,
            }),
        }
    }
}

/// Strict request for one canonical segment of a stored replay envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFindingTriageReplaySegmentRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
    bundle: FindingCandidateBundleId,
    role: CampaignFindingTriageReplayRole,
    evidence: FindingTriageReplayEvidenceId,
    object_ordinal: u32,
    object: ContentId,
    segment_index: u32,
}

impl GetCampaignFindingTriageReplaySegmentRequest {
    /// Builds one snapshot-, occurrence-, role-, and storage-object-bound read.
    ///
    /// The segment index selects a fixed 32 MiB window. The server derives the
    /// exact final-segment length from the authenticated storage description.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the ordinal, content identity,
    /// segment index, or encoded request is invalid.
    // crucible-lint: allow rust-allow -- the request binds every authenticated segment coordinate explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        finding: FindingId,
        bundle: FindingCandidateBundleId,
        role: CampaignFindingTriageReplayRole,
        evidence: FindingTriageReplayEvidenceId,
        object_ordinal: u32,
        object: ContentId,
        segment_index: u32,
    ) -> Result<Self, CampaignCodecError> {
        if object_ordinal > MAX_STORAGE_OBJECT_ORDINAL
            || object.kind() != ObjectKind::Finding
            || (object_ordinal == 0 && object != evidence.content_id())
            || (object_ordinal > 0 && object.schema_version() != 1)
            || u64::from(segment_index)
                .checked_mul(MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES)
                .is_none_or(|offset| offset >= MAX_STORAGE_OBJECT_BYTES)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding triage replay segment request is invalid",
            });
        }

        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            finding,
            bundle,
            role,
            evidence,
            object_ordinal,
            object,
            segment_index,
        };
        ensure_message_size(
            &request,
            "get-campaign-finding-triage-replay-segment-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact current snapshot anchoring the request.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the finding that owns the candidate occurrence.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }

    /// Returns the retained candidate bundle that owns the replay evidence.
    #[must_use]
    pub const fn bundle(&self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the closed replay role selected by the request.
    #[must_use]
    pub const fn role(&self) -> CampaignFindingTriageReplayRole {
        self.role
    }

    /// Returns the exact logical evidence identity selected by the request.
    #[must_use]
    pub const fn evidence(&self) -> FindingTriageReplayEvidenceId {
        self.evidence
    }

    /// Returns the root-first storage-object ordinal.
    #[must_use]
    pub const fn object_ordinal(&self) -> u32 {
        self.object_ordinal
    }

    /// Returns the exact stored-envelope content identity.
    #[must_use]
    pub const fn object(&self) -> ContentId {
        self.object
    }

    /// Returns the fixed-size segment position within the stored envelope.
    #[must_use]
    pub const fn segment_index(&self) -> u32 {
        self.segment_index
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-finding-triage-replay-segment", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded segment request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "get-campaign-finding-triage-replay-segment-request-encoded-bytes",
        )
    }
}

impl Canonical for GetCampaignFindingTriageReplaySegmentRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.finding.encode(encoder);
        self.bundle.encode(encoder);
        self.role.encode(encoder);
        self.evidence.encode(encoder);
        Canonical::encode(&self.object_ordinal, encoder);
        Canonical::encode(&self.object, encoder);
        Canonical::encode(&self.segment_index, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            FindingId::decode(decoder)?,
            FindingCandidateBundleId::decode(decoder)?,
            CampaignFindingTriageReplayRole::decode(decoder)?,
            FindingTriageReplayEvidenceId::decode(decoder)?,
            u32::decode(decoder)?,
            ContentId::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Request-bound segment plus the authenticated finding and storage layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFindingTriageReplaySegmentResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    finding: Finding,
    bundle: FindingCandidateBundle,
    description: FindingTriageReplayStorageDescription,
    object_ordinal: u32,
    object: ContentId,
    segment_index: u32,
    range_offset: u64,
    range_length: u64,
    range_bytes: Vec<u8>,
    finding_proof: MerkleMapLookupProof,
    occurrence_proof: MerkleMapLookupProof,
}

impl GetCampaignFindingTriageReplaySegmentResponse {
    /// Builds one authenticated canonical storage-segment response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the request basis, role binding,
    /// storage description, segment boundary, proof, or message size is invalid.
    // crucible-lint: allow rust-allow -- the response binds every authenticated segment coordinate explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &GetCampaignFindingTriageReplaySegmentRequest,
        snapshot_body: CampaignSnapshot,
        finding: Finding,
        bundle: FindingCandidateBundle,
        description: FindingTriageReplayStorageDescription,
        range_bytes: Vec<u8>,
        finding_proof: MerkleMapLookupProof,
        occurrence_proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let (range_offset, range_length) = canonical_segment(&description, request)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            finding,
            bundle,
            description,
            object_ordinal: request.object_ordinal,
            object: request.object,
            segment_index: request.segment_index,
            range_offset,
            range_length,
            range_bytes,
            finding_proof,
            occurrence_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-finding-triage-replay-segment-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the complete authenticated finding body.
    #[must_use]
    pub const fn finding(&self) -> &Finding {
        &self.finding
    }

    /// Returns the authenticated candidate bundle owning the evidence.
    #[must_use]
    pub const fn bundle(&self) -> &FindingCandidateBundle {
        &self.bundle
    }

    /// Returns the root-first authenticated storage layout.
    #[must_use]
    pub const fn description(&self) -> &FindingTriageReplayStorageDescription {
        &self.description
    }

    /// Returns the repeated storage-object ordinal.
    #[must_use]
    pub const fn object_ordinal(&self) -> u32 {
        self.object_ordinal
    }

    /// Returns the repeated stored-envelope content identity.
    #[must_use]
    pub const fn object(&self) -> ContentId {
        self.object
    }

    /// Returns the repeated segment index.
    #[must_use]
    pub const fn segment_index(&self) -> u32 {
        self.segment_index
    }

    /// Returns the canonical byte offset derived from the storage description.
    #[must_use]
    pub const fn range_offset(&self) -> u64 {
        self.range_offset
    }

    /// Returns the canonical byte length derived from the storage description.
    #[must_use]
    pub const fn range_length(&self) -> u64 {
        self.range_length
    }

    /// Returns only the requested stored-envelope bytes.
    #[must_use]
    pub fn range_bytes(&self) -> &[u8] {
        &self.range_bytes
    }

    /// Validates exact request binding, ownership proofs, and segment shape.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when any repeated request field,
    /// authenticated owner, storage description, proof, boundary, or byte count
    /// disagrees with the request.
    pub fn validate_for(
        &self,
        request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.request_digest != request.request_digest() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign service response request digest mismatch",
            });
        }
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded segment response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "get-campaign-finding-triage-replay-segment-response-encoded-bytes",
        )
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.finding.id()? != request.finding()
            || self.bundle.id()? != request.bundle()
            || self.bundle.signature() != self.finding.signature()
            || request.role().evidence(&self.bundle) != Some(request.evidence())
            || self.description.evidence() != request.evidence()
            || self.object_ordinal != request.object_ordinal()
            || self.object != request.object()
            || self.segment_index != request.segment_index()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding triage replay segment response basis mismatch",
            });
        }

        let indexed_finding = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().findings,
            crate::repository::finding_signature_key(self.finding.signature().cluster_key()),
            &self.finding_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign finding triage replay finding proof is invalid",
        })?;
        let occurrence_root =
            self.finding
                .candidate_occurrences()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "campaign finding has no authenticated candidate occurrence set",
                })?;
        let indexed_bundle = MerkleMap::verify_lookup_proof(
            occurrence_root,
            crate::repository::finding_candidate_occurrence_key(request.bundle()),
            &self.occurrence_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign finding triage replay occurrence proof is invalid",
        })?;
        if indexed_finding != Some(request.finding().content_id())
            || indexed_bundle != Some(request.bundle().content_id())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding triage replay ownership is not authenticated",
            });
        }

        let (expected_offset, expected_length) = canonical_segment(&self.description, request)?;
        let actual_length = u64::try_from(self.range_bytes.len()).map_err(|_| {
            CampaignCodecError::LimitExceeded {
                limit: "campaign-finding-triage-replay-segment-bytes",
            }
        })?;
        if self.range_offset != expected_offset
            || self.range_length != expected_length
            || actual_length != expected_length
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding triage replay segment boundary is invalid",
            });
        }
        Ok(())
    }
}

impl Canonical for GetCampaignFindingTriageReplaySegmentResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.finding.encode(encoder);
        self.bundle.encode(encoder);
        encoder.bytes(&self.description.canonical_bytes());
        self.object_ordinal.encode(encoder);
        Canonical::encode(&self.object, encoder);
        self.segment_index.encode(encoder);
        self.range_offset.encode(encoder);
        self.range_length.encode(encoder);
        encoder.bytes(&self.range_bytes);
        self.finding_proof.encode(encoder);
        self.occurrence_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let request_digest = CampaignHash::decode(decoder)?;
        let snapshot_body = CampaignSnapshot::decode(decoder)?;
        let finding = Finding::decode(decoder)?;
        let bundle = FindingCandidateBundle::decode(decoder)?;
        let mut description_bytes = 0;
        let description_bytes = decoder.byte_sequence_bounded_charged(
            MAX_STORAGE_DESCRIPTION_BYTES,
            "campaign-finding-triage-replay-storage-description-bytes",
            &mut description_bytes,
            MAX_STORAGE_DESCRIPTION_BYTES,
            "campaign-finding-triage-replay-storage-description-bytes",
        )?;
        let mut range_bytes = 0;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest,
            snapshot_body,
            finding,
            bundle,
            description: FindingTriageReplayStorageDescription::from_canonical_bytes(
                &description_bytes,
            )?,
            object_ordinal: u32::decode(decoder)?,
            object: ContentId::decode(decoder)?,
            segment_index: u32::decode(decoder)?,
            range_offset: u64::decode(decoder)?,
            range_length: u64::decode(decoder)?,
            range_bytes: decoder.byte_sequence_bounded_charged(
                MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES as usize,
                "campaign-finding-triage-replay-segment-bytes",
                &mut range_bytes,
                MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES as usize,
                "campaign-finding-triage-replay-segment-bytes",
            )?,
            finding_proof: MerkleMapLookupProof::decode(decoder)?,
            occurrence_proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-finding-triage-replay-segment-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

fn canonical_segment(
    description: &FindingTriageReplayStorageDescription,
    request: &GetCampaignFindingTriageReplaySegmentRequest,
) -> Result<(u64, u64), CampaignCodecError> {
    let range = description.segment_range(
        request.object_ordinal(),
        request.object(),
        request.segment_index(),
    )?;
    Ok((range.offset, range.length))
}
