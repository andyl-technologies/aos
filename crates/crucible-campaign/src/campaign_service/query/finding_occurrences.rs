//! Finding-occurrence pagination and exact occurrence-object queries.

use super::*;

/// Strict request for one authenticated page of a finding's candidate bundles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignFindingOccurrencesRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
    after: Option<CampaignHash>,
    limit: u32,
}

impl QueryCampaignFindingOccurrencesRequest {
    /// Builds one bounded snapshot- and finding-bound occurrence query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `limit` is zero or exceeds
    /// [`MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS`], or the encoded
    /// request exceeds the service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        finding: FindingId,
        after: Option<CampaignHash>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-finding-occurrence-query-page-items",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            finding,
            after,
            limit,
        };
        ensure_message_size(
            &request,
            "query-campaign-finding-occurrences-request-encoded-bytes",
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

    /// Returns the exact current snapshot that anchors this query.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the exact finding whose occurrences are requested.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }

    /// Returns the exclusive candidate-occurrence cursor.
    #[must_use]
    pub const fn after(&self) -> Option<CampaignHash> {
        self.after
    }

    /// Returns the maximum candidate-bundle count requested for this page.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-finding-occurrences", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded occurrence query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "query-campaign-finding-occurrences-request-encoded-bytes",
        )
    }
}

impl Canonical for QueryCampaignFindingOccurrencesRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.finding.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            FindingId::decode(decoder)?,
            Option::<CampaignHash>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Bounded metadata for one owner-validated candidate occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignFindingOccurrence {
    bundle: FindingCandidateBundle,
}

impl CampaignFindingOccurrence {
    /// Builds one bounded occurrence entry.
    #[must_use]
    pub const fn new(bundle: FindingCandidateBundle) -> Self {
        Self { bundle }
    }

    /// Returns the authenticated candidate bundle.
    #[must_use]
    pub const fn bundle(&self) -> &FindingCandidateBundle {
        &self.bundle
    }
}

impl Canonical for CampaignFindingOccurrence {
    fn encode(&self, encoder: &mut Encoder) {
        self.bundle.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(FindingCandidateBundle::decode(decoder)?))
    }
}

/// Request-bound candidate occurrences from one finding's authenticated set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignFindingOccurrencesResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    finding: Finding,
    entries: Vec<CampaignFindingOccurrence>,
    next_after: Option<CampaignHash>,
    finding_proof: MerkleMapLookupProof,
    occurrence_proof: MerkleMapPageProof,
}

impl QueryCampaignFindingOccurrencesResponse {
    /// Builds one authenticated candidate-occurrence response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, finding, proofs,
    /// bundle identities, signatures, cursor, or encoded-size contract is invalid.
    pub fn new(
        request: &QueryCampaignFindingOccurrencesRequest,
        snapshot_body: CampaignSnapshot,
        finding: Finding,
        entries: Vec<CampaignFindingOccurrence>,
        next_after: Option<CampaignHash>,
        finding_proof: MerkleMapLookupProof,
        occurrence_proof: MerkleMapPageProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            finding,
            entries,
            next_after,
            finding_proof,
            occurrence_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "query-campaign-finding-occurrences-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the authenticated finding body.
    #[must_use]
    pub const fn finding(&self) -> &Finding {
        &self.finding
    }

    /// Returns complete owner-validated candidates in canonical occurrence order.
    #[must_use]
    pub fn entries(&self) -> &[CampaignFindingOccurrence] {
        &self.entries
    }

    /// Returns the exclusive candidate-occurrence cursor for the next page.
    #[must_use]
    pub const fn next_after(&self) -> Option<CampaignHash> {
        self.next_after
    }

    /// Validates exact request, finding membership, occurrence membership, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or differs from either authenticated Merkle proof.
    pub fn validate_for(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded occurrence response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "query-campaign-finding-occurrences-response-encoded-bytes",
        )
    }

    fn validate_body_for(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<(), CampaignCodecError> {
        let limit =
            usize::try_from(request.limit()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "campaign-finding-occurrence-query-page-items",
            })?;
        if self.snapshot_body.id()? != request.snapshot()
            || self.finding.id()? != request.finding()
            || self.entries.len() > limit
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding occurrences response basis mismatch",
            });
        }
        let indexed = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().findings,
            crate::repository::finding_signature_key(self.finding.signature().cluster_key()),
            &self.finding_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign finding occurrence membership proof is invalid",
        })?;
        if indexed != Some(request.finding().content_id()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding occurrence is not in the snapshot",
            });
        }
        let root =
            self.finding
                .candidate_occurrences()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "campaign finding has no authenticated candidate occurrence set",
                })?;
        let verified =
            MerkleMap::verify_scan_proof(root, request.after(), limit, &self.occurrence_proof)
                .map_err(|_| CampaignCodecError::InvalidValue {
                    reason: "campaign finding occurrence page proof is invalid",
                })?;
        if verified.entries().len() != self.entries.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding occurrence count differs from proof",
            });
        }
        for ((key, value), occurrence) in verified.entries().iter().zip(&self.entries) {
            let bundle = occurrence.bundle();
            let bundle_id = bundle.id()?;
            if bundle_id.content_id() != *value
                || *key != crate::repository::finding_candidate_occurrence_key(bundle_id)
                || bundle.signature() != self.finding.signature()
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "campaign finding occurrence differs from index leaf",
                });
            }
        }
        if self.next_after != verified.next_after() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding occurrence cursor differs from proof",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignFindingOccurrencesResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.finding.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.finding_proof.encode(encoder);
        self.occurrence_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            finding: Finding::decode(decoder)?,
            entries: decoder.sequence_bounded(
                usize::try_from(MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS).map_err(
                    |_| CampaignCodecError::LimitExceeded {
                        limit: "campaign-finding-occurrence-query-page-items",
                    },
                )?,
                "campaign-query-finding-occurrence-items",
                CampaignFindingOccurrence::decode,
            )?,
            next_after: Option::<CampaignHash>::decode(decoder)?,
            finding_proof: MerkleMapLookupProof::decode(decoder)?,
            occurrence_proof: MerkleMapPageProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "query-campaign-finding-occurrences-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Dependency kind addressable through one retained candidate occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignFindingOccurrenceObjectKind {
    /// The exact observation reported by the candidate.
    Observation,
    /// The candidate's original verified reproduction.
    Reproduction,
    /// The candidate's minimized reproduction and verifier trace.
    MinimizedReproduction,
    /// The minimization pass replay of the original reproduction.
    MinimizationOriginalTriageEvidence,
    /// The minimization pass replay of the selected reproduction.
    MinimizationSelectedTriageEvidence,
    /// The verification pass replay of the original reproduction.
    VerificationOriginalTriageEvidence,
    /// The verification pass replay of the selected reproduction.
    VerificationSelectedTriageEvidence,
}

impl Canonical for CampaignFindingOccurrenceObjectKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Observation => 0,
            Self::Reproduction => 1,
            Self::MinimizedReproduction => 2,
            Self::MinimizationOriginalTriageEvidence => 3,
            Self::MinimizationSelectedTriageEvidence => 4,
            Self::VerificationOriginalTriageEvidence => 5,
            Self::VerificationSelectedTriageEvidence => 6,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Observation),
            1 => Ok(Self::Reproduction),
            2 => Ok(Self::MinimizedReproduction),
            3 => Ok(Self::MinimizationOriginalTriageEvidence),
            4 => Ok(Self::MinimizationSelectedTriageEvidence),
            5 => Ok(Self::VerificationOriginalTriageEvidence),
            6 => Ok(Self::VerificationSelectedTriageEvidence),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-finding-occurrence-object-kind",
                tag,
            }),
        }
    }
}

/// One immutable body named by a retained candidate bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignFindingOccurrenceObject {
    /// The exact observation reported by the candidate.
    Observation(Observation),
    /// The candidate's original verified reproduction.
    Reproduction(ReproductionArtifact),
    /// The candidate's minimized reproduction and verifier trace.
    MinimizedReproduction(ReproductionArtifact),
    /// The minimization pass replay of the original reproduction.
    MinimizationOriginalTriageEvidence(FindingTriageReplayEvidence),
    /// The minimization pass replay of the selected reproduction.
    MinimizationSelectedTriageEvidence(FindingTriageReplayEvidence),
    /// The verification pass replay of the original reproduction.
    VerificationOriginalTriageEvidence(FindingTriageReplayEvidence),
    /// The verification pass replay of the selected reproduction.
    VerificationSelectedTriageEvidence(FindingTriageReplayEvidence),
}

impl CampaignFindingOccurrenceObject {
    /// Returns the closed dependency kind carried by this value.
    #[must_use]
    pub const fn kind(&self) -> CampaignFindingOccurrenceObjectKind {
        match self {
            Self::Observation(_) => CampaignFindingOccurrenceObjectKind::Observation,
            Self::Reproduction(_) => CampaignFindingOccurrenceObjectKind::Reproduction,
            Self::MinimizedReproduction(_) => {
                CampaignFindingOccurrenceObjectKind::MinimizedReproduction
            }
            Self::MinimizationOriginalTriageEvidence(_) => {
                CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence
            }
            Self::MinimizationSelectedTriageEvidence(_) => {
                CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence
            }
            Self::VerificationOriginalTriageEvidence(_) => {
                CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence
            }
            Self::VerificationSelectedTriageEvidence(_) => {
                CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence
            }
        }
    }
}

impl Canonical for CampaignFindingOccurrenceObject {
    fn encode(&self, encoder: &mut Encoder) {
        self.kind().encode(encoder);
        match self {
            Self::Observation(value) => value.encode(encoder),
            Self::Reproduction(value) | Self::MinimizedReproduction(value) => {
                value.encode(encoder);
            }
            Self::MinimizationOriginalTriageEvidence(value)
            | Self::MinimizationSelectedTriageEvidence(value)
            | Self::VerificationOriginalTriageEvidence(value)
            | Self::VerificationSelectedTriageEvidence(value) => value.encode(encoder),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match CampaignFindingOccurrenceObjectKind::decode(decoder)? {
            CampaignFindingOccurrenceObjectKind::Observation => {
                Observation::decode(decoder).map(Self::Observation)
            }
            CampaignFindingOccurrenceObjectKind::Reproduction => {
                ReproductionArtifact::decode(decoder).map(Self::Reproduction)
            }
            CampaignFindingOccurrenceObjectKind::MinimizedReproduction => {
                ReproductionArtifact::decode(decoder).map(Self::MinimizedReproduction)
            }
            CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence => {
                FindingTriageReplayEvidence::decode(decoder)
                    .map(Self::MinimizationOriginalTriageEvidence)
            }
            CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence => {
                FindingTriageReplayEvidence::decode(decoder)
                    .map(Self::MinimizationSelectedTriageEvidence)
            }
            CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence => {
                FindingTriageReplayEvidence::decode(decoder)
                    .map(Self::VerificationOriginalTriageEvidence)
            }
            CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence => {
                FindingTriageReplayEvidence::decode(decoder)
                    .map(Self::VerificationSelectedTriageEvidence)
            }
        }
    }
}

/// Strict request for one dependency of a retained candidate occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFindingOccurrenceObjectRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
    bundle: FindingCandidateBundleId,
    kind: CampaignFindingOccurrenceObjectKind,
}

impl GetCampaignFindingOccurrenceObjectRequest {
    /// Builds one snapshot-, finding-, and bundle-bound dependency request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        finding: FindingId,
        bundle: FindingCandidateBundleId,
        kind: CampaignFindingOccurrenceObjectKind,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            finding,
            bundle,
            kind,
        };
        ensure_message_size(
            &request,
            "get-campaign-finding-occurrence-object-request-encoded-bytes",
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

    /// Returns the exact current snapshot that anchors the request.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the exact finding that owns the candidate occurrence.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }

    /// Returns the exact retained candidate bundle.
    #[must_use]
    pub const fn bundle(&self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the closed requested dependency kind.
    #[must_use]
    pub const fn kind(&self) -> CampaignFindingOccurrenceObjectKind {
        self.kind
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-finding-occurrence-object", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded occurrence-dependency request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "get-campaign-finding-occurrence-object-request-encoded-bytes",
        )
    }
}

impl Canonical for GetCampaignFindingOccurrenceObjectRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.finding.encode(encoder);
        self.bundle.encode(encoder);
        self.kind.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            FindingId::decode(decoder)?,
            FindingCandidateBundleId::decode(decoder)?,
            CampaignFindingOccurrenceObjectKind::decode(decoder)?,
        )
    }
}

/// Request-bound occurrence dependency with finding and bundle membership proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFindingOccurrenceObjectResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    finding: Finding,
    bundle: FindingCandidateBundle,
    object: CampaignFindingOccurrenceObject,
    finding_proof: MerkleMapLookupProof,
    occurrence_proof: MerkleMapLookupProof,
}

impl GetCampaignFindingOccurrenceObjectResponse {
    /// Builds one authenticated occurrence-dependency response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when either proof, identity, dependency,
    /// or the encoded-size contract is invalid.
    pub fn new(
        request: &GetCampaignFindingOccurrenceObjectRequest,
        snapshot_body: CampaignSnapshot,
        finding: Finding,
        bundle: FindingCandidateBundle,
        object: CampaignFindingOccurrenceObject,
        finding_proof: MerkleMapLookupProof,
        occurrence_proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            finding,
            bundle,
            object,
            finding_proof,
            occurrence_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-finding-occurrence-object-response-encoded-bytes",
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

    /// Returns the retained candidate bundle naming the dependency.
    #[must_use]
    pub const fn bundle(&self) -> &FindingCandidateBundle {
        &self.bundle
    }

    /// Returns the exact authenticated occurrence dependency.
    #[must_use]
    pub const fn object(&self) -> &CampaignFindingOccurrenceObject {
        &self.object
    }

    /// Validates the exact request and both levels of authenticated ownership.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or either membership proof, identity, or dependency disagrees.
    pub fn validate_for(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded occurrence-dependency response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "get-campaign-finding-occurrence-object-response-encoded-bytes",
        )
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.finding.id()? != request.finding()
            || self.bundle.id()? != request.bundle()
            || self.object.kind() != request.kind()
            || self.bundle.signature() != self.finding.signature()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding occurrence object response basis mismatch",
            });
        }
        let indexed_finding = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().findings,
            crate::repository::finding_signature_key(self.finding.signature().cluster_key()),
            &self.finding_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign finding occurrence object finding proof is invalid",
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
            reason: "campaign finding occurrence object bundle proof is invalid",
        })?;
        if indexed_finding != Some(request.finding().content_id())
            || indexed_bundle != Some(request.bundle().content_id())
            || !finding_occurrence_object_matches(&self.bundle, &self.object)?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding occurrence dependency is not authenticated",
            });
        }
        Ok(())
    }
}

impl Canonical for GetCampaignFindingOccurrenceObjectResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.finding.encode(encoder);
        self.bundle.encode(encoder);
        self.object.encode(encoder);
        self.finding_proof.encode(encoder);
        self.occurrence_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            finding: Finding::decode(decoder)?,
            bundle: FindingCandidateBundle::decode(decoder)?,
            object: CampaignFindingOccurrenceObject::decode(decoder)?,
            finding_proof: MerkleMapLookupProof::decode(decoder)?,
            occurrence_proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-finding-occurrence-object-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

fn finding_occurrence_object_matches(
    bundle: &FindingCandidateBundle,
    object: &CampaignFindingOccurrenceObject,
) -> Result<bool, CampaignCodecError> {
    match object {
        CampaignFindingOccurrenceObject::Observation(value) => {
            Ok(value.id()? == bundle.observation())
        }
        CampaignFindingOccurrenceObject::Reproduction(value) => Ok(value.id()?
            == bundle.reproduction()
            && value.finding_fingerprint() == bundle.signature().fingerprint()),
        CampaignFindingOccurrenceObject::MinimizedReproduction(value) => Ok(value.id()?
            == bundle.minimized()
            && value.finding_fingerprint() == bundle.signature().fingerprint()
            && value
                .minimization()
                .is_some_and(|evidence| evidence.original() == bundle.reproduction())),
        CampaignFindingOccurrenceObject::MinimizationOriginalTriageEvidence(value) => Ok(bundle
            .triage_evidence()
            .is_some_and(|evidence| value.id().ok() == Some(evidence.minimization_original()))),
        CampaignFindingOccurrenceObject::MinimizationSelectedTriageEvidence(value) => Ok(bundle
            .triage_evidence()
            .is_some_and(|evidence| value.id().ok() == Some(evidence.minimization_selected()))),
        CampaignFindingOccurrenceObject::VerificationOriginalTriageEvidence(value) => Ok(bundle
            .triage_evidence()
            .is_some_and(|evidence| value.id().ok() == Some(evidence.verification_original()))),
        CampaignFindingOccurrenceObject::VerificationSelectedTriageEvidence(value) => Ok(bundle
            .triage_evidence()
            .is_some_and(|evidence| value.id().ok() == Some(evidence.verification_selected()))),
    }
}
