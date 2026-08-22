//! Strict snapshot-bound campaign graph, frontier, object, and choice queries.

use crucible_cas::content_store::ContentId;

use super::*;
use crate::{
    Attempt, AttemptAdmission, AttemptAdmissionRole, AttemptId, AttemptStart, BranchPath,
    BranchRequestId, ChoiceDomain, ChoiceOpportunity, ContinuationProjection, Finding, FindingId,
    Observation, Proposal, ReproductionArtifact, SelectableDeclaration, Selection, SelectionOrigin,
};

/// Maximum entries returned by one campaign graph page.
pub const MAX_CAMPAIGN_QUERY_PAGE_ITEMS: u32 = crate::MAX_PROVEN_PAGE_ITEMS as u32;

/// Maximum choices returned by one proof-bearing nested-index page.
///
/// The smaller limit keeps the worst-case scan proof plus the independent
/// graph-anchor lookup proof below the 64-MiB component-message bound.
pub const MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS: u32 = 8;

/// Maximum continuations returned by one proof-bearing frontier page.
///
/// The limit keeps the nested-index lookup proof, range proof, and typed
/// projection bodies below the component-message ceiling.
pub const MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS: u32 = 8;

/// Maximum complete finding records returned by one proof-bearing page.
///
/// Finding bodies are independently bounded at 4 MiB. The smaller page limit
/// leaves room for the authenticated snapshot and Merkle range proof under the
/// 64-MiB component-message ceiling.
pub const MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS: u32 = 4;

/// One choice opportunity admitted into the authenticated campaign graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignChoiceEntry {
    opportunity: ChoiceOpportunityId,
}

impl CampaignChoiceEntry {
    /// Builds one choice-index entry.
    #[must_use]
    pub const fn new(opportunity: ChoiceOpportunityId) -> Self {
        Self { opportunity }
    }

    /// Returns the content-addressed choice opportunity.
    #[must_use]
    pub const fn opportunity(self) -> ChoiceOpportunityId {
        self.opportunity
    }

    /// Returns the nested choice-index key for this opportunity.
    #[must_use]
    pub fn index_key(self) -> CampaignHash {
        crate::repository::choice_index_order_key(self.opportunity)
    }

    /// Returns the graph key that anchors the nested choice-index root.
    #[must_use]
    pub fn index_anchor_key() -> CampaignHash {
        crate::repository::choice_index_anchor_key()
    }

    /// Returns the graph key used to fetch the exact opportunity body.
    #[must_use]
    pub fn graph_key(self) -> CampaignHash {
        crate::repository::authoritative_choice_key(self.opportunity)
    }
}

impl Canonical for CampaignChoiceEntry {
    fn encode(&self, encoder: &mut Encoder) {
        self.opportunity.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(ChoiceOpportunityId::decode(decoder)?))
    }
}

/// Strict request for one current-snapshot page of discovered choices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignChoicesRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    after: Option<ChoiceOpportunityId>,
    limit: u32,
}

impl QueryCampaignChoicesRequest {
    /// Builds one bounded snapshot-bound choice query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `limit` is zero or exceeds
    /// [`MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS`], or when the encoded request exceeds
    /// the service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        after: Option<ChoiceOpportunityId>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-choice-query-page-items",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            after,
            limit,
        };
        ensure_message_size(&request, "query-campaign-choices-request-encoded-bytes")?;
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

    /// Returns the exclusive choice-opportunity cursor.
    #[must_use]
    pub const fn after(&self) -> Option<ChoiceOpportunityId> {
        self.after
    }

    /// Returns the maximum entries requested for this page.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-choices", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded choice query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-choices-request-encoded-bytes")
    }
}

impl Canonical for QueryCampaignChoicesRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            Option::<ChoiceOpportunityId>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Request-bound page from the snapshot's authenticated choice index.
///
/// Authorization for this response grants visibility of every root ID, parent,
/// lineage, policy, and transition in the snapshot body. Choice and dependency
/// bodies remain separately authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignChoicesResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    entries: Vec<CampaignChoiceEntry>,
    next_after: Option<ChoiceOpportunityId>,
    index_proof: MerkleMapLookupProof,
    page_proof: MerkleMapPageProof,
}

impl QueryCampaignChoicesResponse {
    /// Builds one authenticated choice-index response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, nested-index proof,
    /// page entries, cursor, limit, or encoded-size contract is invalid.
    pub fn new(
        request: &QueryCampaignChoicesRequest,
        snapshot_body: CampaignSnapshot,
        entries: Vec<CampaignChoiceEntry>,
        next_after: Option<ChoiceOpportunityId>,
        index_proof: MerkleMapLookupProof,
        page_proof: MerkleMapPageProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            entries,
            next_after,
            index_proof,
            page_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(&response, "query-campaign-choices-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including all snapshot root IDs.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns discovered choice IDs in canonical content-ID order.
    #[must_use]
    pub fn entries(&self) -> &[CampaignChoiceEntry] {
        &self.entries
    }

    /// Returns the exclusive cursor for the next page, or `None` at EOF.
    #[must_use]
    pub const fn next_after(&self) -> Option<ChoiceOpportunityId> {
        self.next_after
    }

    /// Validates exact request, snapshot, nested index, page, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or differs from either authenticated Merkle proof.
    pub fn validate_for(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded choice response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-choices-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<(), CampaignCodecError> {
        let limit =
            usize::try_from(request.limit()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "campaign-choice-query-page-items",
            })?;
        if self.snapshot_body.id()? != request.snapshot() || self.entries.len() > limit {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign choices response snapshot or page limit mismatch",
            });
        }
        let index_root = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().graph,
            crate::repository::choice_index_anchor_key(),
            &self.index_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign choices index proof is invalid",
        })?
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "campaign snapshot has no authenticated choice index",
        })?;
        let verified = MerkleMap::verify_scan_proof(
            index_root,
            request
                .after()
                .map(crate::repository::choice_index_order_key),
            limit,
            &self.page_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign choices page proof is invalid",
        })?;
        let verified_entries = verified
            .entries()
            .iter()
            .map(|(key, value)| {
                let opportunity = ChoiceOpportunityId::from_content_id(*value)?;
                if *key != crate::repository::choice_index_order_key(opportunity) {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "campaign choice index ordering key mismatch",
                    });
                }
                Ok(CampaignChoiceEntry::new(opportunity))
            })
            .collect::<Result<Vec<_>, CampaignCodecError>>()?;
        let verified_next = verified
            .next_after()
            .map(|_| {
                verified_entries
                    .last()
                    .map(|entry| entry.opportunity())
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "campaign choices page has a cursor without entries",
                    })
            })
            .transpose()?;
        if self.entries != verified_entries || self.next_after != verified_next {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign choices response differs from its Merkle proof",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignChoicesResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.index_proof.encode(encoder);
        self.page_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            entries: decoder.sequence_bounded(
                usize::try_from(MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "campaign-choice-query-page-items",
                    }
                })?,
                "campaign-query-choice-items",
                CampaignChoiceEntry::decode,
            )?,
            next_after: Option::<ChoiceOpportunityId>::decode(decoder)?,
            index_proof: MerkleMapLookupProof::decode(decoder)?,
            page_proof: MerkleMapPageProof::decode(decoder)?,
        };
        ensure_message_size(&response, "query-campaign-choices-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Strict request for one current-snapshot page of continuation projections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignFrontierRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    after: Option<BranchRequestId>,
    limit: u32,
}

impl QueryCampaignFrontierRequest {
    /// Builds one bounded snapshot-bound frontier query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `limit` is zero or exceeds
    /// [`MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS`], or the encoded request exceeds
    /// the service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        after: Option<BranchRequestId>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-frontier-query-page-items",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            after,
            limit,
        };
        ensure_message_size(&request, "query-campaign-frontier-request-encoded-bytes")?;
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

    /// Returns the exclusive branch-request cursor.
    #[must_use]
    pub const fn after(&self) -> Option<BranchRequestId> {
        self.after
    }

    /// Returns the maximum continuation count requested for this page.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-frontier", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded frontier query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-frontier-request-encoded-bytes")
    }
}

impl Canonical for QueryCampaignFrontierRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            Option::<BranchRequestId>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Request-bound page from the snapshot's authenticated frontier index.
///
/// Authorization grants the complete snapshot metadata and the returned
/// continuation-projection bodies. Branch requests and other object bodies
/// remain separately authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignFrontierResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    entries: Vec<ContinuationProjection>,
    next_after: Option<BranchRequestId>,
    index_proof: MerkleMapLookupProof,
    page_proof: MerkleMapPageProof,
}

impl QueryCampaignFrontierResponse {
    /// Builds one authenticated frontier response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, index proof, page,
    /// typed projection bodies, cursor, limit, or encoded-size contract fails.
    pub fn new(
        request: &QueryCampaignFrontierRequest,
        snapshot_body: CampaignSnapshot,
        entries: Vec<ContinuationProjection>,
        next_after: Option<BranchRequestId>,
        index_proof: MerkleMapLookupProof,
        page_proof: MerkleMapPageProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            entries,
            next_after,
            index_proof,
            page_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(&response, "query-campaign-frontier-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including all root IDs.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns continuation projections in canonical request-ID order.
    #[must_use]
    pub fn entries(&self) -> &[ContinuationProjection] {
        &self.entries
    }

    /// Returns the exclusive cursor for the next page, or `None` at EOF.
    #[must_use]
    pub const fn next_after(&self) -> Option<BranchRequestId> {
        self.next_after
    }

    /// Validates exact request, snapshot, nested index, bodies, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or differs from either authenticated Merkle proof.
    pub fn validate_for(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded frontier response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-frontier-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<(), CampaignCodecError> {
        let limit =
            usize::try_from(request.limit()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "campaign-frontier-query-page-items",
            })?;
        if self.snapshot_body.id()? != request.snapshot() || self.entries.len() > limit {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign frontier response snapshot or page limit mismatch",
            });
        }
        let index_root = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().exploration,
            crate::repository::frontier_index_anchor_key(),
            &self.index_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign frontier index proof is invalid",
        })?
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "campaign snapshot has no authenticated frontier index",
        })?;
        let verified = MerkleMap::verify_scan_proof(
            index_root,
            request
                .after()
                .map(crate::repository::frontier_index_order_key),
            limit,
            &self.page_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign frontier page proof is invalid",
        })?;
        if verified.entries().len() != self.entries.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign frontier response entry count differs from proof",
            });
        }
        for ((key, value), projection) in verified.entries().iter().zip(&self.entries) {
            if projection.id()?.content_id() != *value
                || *key != crate::repository::frontier_index_order_key(projection.request())
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "campaign frontier projection differs from index leaf",
                });
            }
        }
        let verified_next = if verified.next_after().is_some() {
            self.entries.last().map(|projection| projection.request())
        } else {
            None
        };
        if self.next_after != verified_next {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign frontier cursor differs from its Merkle proof",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignFrontierResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.index_proof.encode(encoder);
        self.page_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            entries: decoder.sequence_bounded(
                usize::try_from(MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "campaign-frontier-query-page-items",
                    }
                })?,
                "campaign-query-frontier-items",
                ContinuationProjection::decode,
            )?,
            next_after: Option::<BranchRequestId>::decode(decoder)?,
            index_proof: MerkleMapLookupProof::decode(decoder)?,
            page_proof: MerkleMapPageProof::decode(decoder)?,
        };
        ensure_message_size(&response, "query-campaign-frontier-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Strict request for one current-snapshot page of canonical findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignFindingsRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    after: Option<CampaignHash>,
    limit: u32,
}

impl QueryCampaignFindingsRequest {
    /// Builds one bounded snapshot-bound finding query.
    ///
    /// `after` is the exclusive signature-index key returned by the preceding
    /// page. The first page uses `None`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `limit` is zero or exceeds
    /// [`MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS`], or the encoded request exceeds
    /// the service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        after: Option<CampaignHash>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-finding-query-page-items",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            after,
            limit,
        };
        ensure_message_size(&request, "query-campaign-findings-request-encoded-bytes")?;
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

    /// Returns the exclusive finding signature-index cursor.
    #[must_use]
    pub const fn after(&self) -> Option<CampaignHash> {
        self.after
    }

    /// Returns the maximum finding count requested for this page.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-findings", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded finding query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-findings-request-encoded-bytes")
    }
}

impl Canonical for QueryCampaignFindingsRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            Option::<CampaignHash>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Request-bound page from the snapshot's authenticated finding index.
///
/// Authorization grants the complete snapshot metadata and returned canonical
/// finding bodies, including their evidence, reproduction, and exact-pin IDs.
/// The objects named by those IDs remain separately authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignFindingsResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    entries: Vec<Finding>,
    next_after: Option<CampaignHash>,
    proof: MerkleMapPageProof,
}

impl QueryCampaignFindingsResponse {
    /// Builds one authenticated finding-index response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, proof, finding
    /// identities, signature keys, cursor, limit, or encoded-size contract is
    /// invalid.
    pub fn new(
        request: &QueryCampaignFindingsRequest,
        snapshot_body: CampaignSnapshot,
        entries: Vec<Finding>,
        next_after: Option<CampaignHash>,
        proof: MerkleMapPageProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            entries,
            next_after,
            proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(&response, "query-campaign-findings-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including all root IDs.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns complete finding records in canonical signature-key order.
    #[must_use]
    pub fn entries(&self) -> &[Finding] {
        &self.entries
    }

    /// Returns the exclusive signature-index cursor for the next page.
    #[must_use]
    pub const fn next_after(&self) -> Option<CampaignHash> {
        self.next_after
    }

    /// Validates exact request, snapshot, finding bodies, proof, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or differs from the authenticated findings Merkle proof.
    pub fn validate_for(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded finding response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-findings-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<(), CampaignCodecError> {
        let limit =
            usize::try_from(request.limit()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "campaign-finding-query-page-items",
            })?;
        if self.snapshot_body.id()? != request.snapshot() || self.entries.len() > limit {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign findings response snapshot or page limit mismatch",
            });
        }
        let verified = MerkleMap::verify_scan_proof(
            self.snapshot_body.roots().findings,
            request.after(),
            limit,
            &self.proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign findings page proof is invalid",
        })?;
        if verified.entries().len() != self.entries.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign findings response entry count differs from proof",
            });
        }
        for ((key, value), finding) in verified.entries().iter().zip(&self.entries) {
            if finding.id()?.content_id() != *value
                || *key
                    != crate::repository::finding_signature_key(finding.signature().cluster_key())
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "campaign finding differs from index leaf",
                });
            }
        }
        if self.next_after != verified.next_after() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign findings cursor differs from its Merkle proof",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignFindingsResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            entries: decoder.sequence_bounded(
                usize::try_from(MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "campaign-finding-query-page-items",
                    }
                })?,
                "campaign-query-finding-items",
                Finding::decode,
            )?,
            next_after: Option::<CampaignHash>::decode(decoder)?,
            proof: MerkleMapPageProof::decode(decoder)?,
        };
        ensure_message_size(&response, "query-campaign-findings-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Finding dependency selected for one authenticated body read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignFindingObjectKind {
    /// The representative observation retained by the finding.
    Observation,
    /// The most recent observation in the authenticated occurrence set.
    LatestOccurrence,
    /// The original verified reproduction artifact.
    Reproduction,
    /// The optional verified minimized reproduction artifact.
    MinimizedReproduction,
}

impl Canonical for CampaignFindingObjectKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Observation => 0,
            Self::LatestOccurrence => 1,
            Self::Reproduction => 2,
            Self::MinimizedReproduction => 3,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Observation),
            1 => Ok(Self::LatestOccurrence),
            2 => Ok(Self::Reproduction),
            3 => Ok(Self::MinimizedReproduction),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-finding-object-kind",
                tag,
            }),
        }
    }
}

/// Typed immutable body named by an authenticated finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignFindingObject {
    /// The representative observation retained by the finding.
    Observation(Observation),
    /// The latest observation in the finding occurrence set.
    LatestOccurrence(Observation),
    /// The original verified reproduction artifact.
    Reproduction(ReproductionArtifact),
    /// The verified minimized reproduction artifact.
    MinimizedReproduction(ReproductionArtifact),
}

impl CampaignFindingObject {
    /// Returns the closed dependency kind carried by this value.
    #[must_use]
    pub const fn kind(&self) -> CampaignFindingObjectKind {
        match self {
            Self::Observation(_) => CampaignFindingObjectKind::Observation,
            Self::LatestOccurrence(_) => CampaignFindingObjectKind::LatestOccurrence,
            Self::Reproduction(_) => CampaignFindingObjectKind::Reproduction,
            Self::MinimizedReproduction(_) => CampaignFindingObjectKind::MinimizedReproduction,
        }
    }
}

impl Canonical for CampaignFindingObject {
    fn encode(&self, encoder: &mut Encoder) {
        self.kind().encode(encoder);
        match self {
            Self::Observation(value) | Self::LatestOccurrence(value) => value.encode(encoder),
            Self::Reproduction(value) | Self::MinimizedReproduction(value) => {
                value.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match CampaignFindingObjectKind::decode(decoder)? {
            CampaignFindingObjectKind::Observation => {
                Observation::decode(decoder).map(Self::Observation)
            }
            CampaignFindingObjectKind::LatestOccurrence => {
                Observation::decode(decoder).map(Self::LatestOccurrence)
            }
            CampaignFindingObjectKind::Reproduction => {
                ReproductionArtifact::decode(decoder).map(Self::Reproduction)
            }
            CampaignFindingObjectKind::MinimizedReproduction => {
                ReproductionArtifact::decode(decoder).map(Self::MinimizedReproduction)
            }
        }
    }
}

/// Strict request for one dependency of an authenticated finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFindingObjectRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
    kind: CampaignFindingObjectKind,
}

impl GetCampaignFindingObjectRequest {
    /// Builds one snapshot-bound finding-dependency request.
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
        kind: CampaignFindingObjectKind,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            finding,
            kind,
        };
        ensure_message_size(
            &request,
            "get-campaign-finding-object-request-encoded-bytes",
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

    /// Returns the exact finding whose dependency is requested.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }

    /// Returns the closed requested dependency kind.
    #[must_use]
    pub const fn kind(&self) -> CampaignFindingObjectKind {
        self.kind
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-finding-object", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded finding-dependency request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-finding-object-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignFindingObjectRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.finding.encode(encoder);
        self.kind.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            FindingId::decode(decoder)?,
            CampaignFindingObjectKind::decode(decoder)?,
        )
    }
}

/// Request-bound finding dependency and exact finding-index proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFindingObjectResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    finding: Finding,
    object: CampaignFindingObject,
    proof: MerkleMapLookupProof,
}

impl GetCampaignFindingObjectResponse {
    /// Builds one authenticated finding-dependency response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, finding proof,
    /// dependency identity, semantic basis, or encoded-size contract is invalid.
    pub fn new(
        request: &GetCampaignFindingObjectRequest,
        snapshot_body: CampaignSnapshot,
        finding: Finding,
        object: CampaignFindingObject,
        proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            finding,
            object,
            proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-finding-object-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including every root ID.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the complete authenticated finding body.
    #[must_use]
    pub const fn finding(&self) -> &Finding {
        &self.finding
    }

    /// Returns the exact authenticated finding dependency.
    #[must_use]
    pub const fn object(&self) -> &CampaignFindingObject {
        &self.object
    }

    /// Validates exact request, snapshot, finding membership, and dependency binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or the proof, typed identity, or finding dependency disagrees.
    pub fn validate_for(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded finding-dependency response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-finding-object-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.finding.id()? != request.finding()
            || self.object.kind() != request.kind()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding object response basis mismatch",
            });
        }
        let indexed = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().findings,
            crate::repository::finding_signature_key(self.finding.signature().cluster_key()),
            &self.proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign finding object membership proof is invalid",
        })?;
        if indexed != Some(request.finding().content_id())
            || !finding_object_matches(&self.finding, &self.object)?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign finding dependency is not authenticated",
            });
        }
        Ok(())
    }
}

impl Canonical for GetCampaignFindingObjectResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.finding.encode(encoder);
        self.object.encode(encoder);
        self.proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            finding: Finding::decode(decoder)?,
            object: CampaignFindingObject::decode(decoder)?,
            proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-finding-object-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

fn finding_object_matches(
    finding: &Finding,
    object: &CampaignFindingObject,
) -> Result<bool, CampaignCodecError> {
    match object {
        CampaignFindingObject::Observation(value) => Ok(value.id()? == finding.observation()),
        CampaignFindingObject::LatestOccurrence(value) => {
            Ok(value.id()? == finding.latest_occurrence())
        }
        CampaignFindingObject::Reproduction(value) => Ok(value.id()? == finding.reproduction()
            && value.finding_fingerprint() == finding.signature().fingerprint()),
        CampaignFindingObject::MinimizedReproduction(value) => Ok(finding.minimized()
            == Some(value.id()?)
            && value.finding_fingerprint() == finding.signature().fingerprint()),
    }
}

/// Strict request for one authenticated attempt and its execution provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainCampaignAttemptRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    attempt: AttemptId,
}

impl ExplainCampaignAttemptRequest {
    /// Builds one snapshot-bound attempt-explanation request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        attempt: AttemptId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            attempt,
        };
        ensure_message_size(&request, "explain-campaign-attempt-request-encoded-bytes")?;
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

    /// Returns the exact semantic attempt to explain.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("explain-campaign-attempt", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded attempt-explanation request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "explain-campaign-attempt-request-encoded-bytes")
    }
}

impl Canonical for ExplainCampaignAttemptRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.attempt.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            AttemptId::decode(decoder)?,
        )
    }
}

/// Request-bound attempt, execution basis, proposal, and completion proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainCampaignAttemptResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    attempt: Attempt,
    admission: AttemptAdmission,
    path: BranchPath,
    selection: Option<Selection>,
    proposal: Option<Proposal>,
    observation: Option<Observation>,
    attempt_proof: MerkleMapLookupProof,
    admission_proof: MerkleMapLookupProof,
    proposal_proof: Option<MerkleMapLookupProof>,
    observation_proof: MerkleMapLookupProof,
}

impl ExplainCampaignAttemptResponse {
    /// Builds one authenticated attempt-explanation response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when any snapshot, accounting,
    /// exploration, path, selection, proposal, completion, or encoded-size
    /// invariant is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ExplainCampaignAttemptRequest,
        snapshot_body: CampaignSnapshot,
        attempt: Attempt,
        admission: AttemptAdmission,
        path: BranchPath,
        selection: Option<Selection>,
        proposal: Option<Proposal>,
        observation: Option<Observation>,
        attempt_proof: MerkleMapLookupProof,
        admission_proof: MerkleMapLookupProof,
        proposal_proof: Option<MerkleMapLookupProof>,
        observation_proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            attempt,
            admission,
            path,
            selection,
            proposal,
            observation,
            attempt_proof,
            admission_proof,
            proposal_proof,
            observation_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(&response, "explain-campaign-attempt-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including every root ID.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the exact authenticated semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the unique authenticated execution-basis admission.
    #[must_use]
    pub const fn admission(&self) -> AttemptAdmission {
        self.admission
    }

    /// Returns the authenticated root-to-leaf branch path.
    #[must_use]
    pub const fn path(&self) -> &BranchPath {
        &self.path
    }

    /// Returns the exact branch selection, absent for discovery attempts.
    #[must_use]
    pub const fn selection(&self) -> Option<&Selection> {
        self.selection.as_ref()
    }

    /// Returns the execution-basis proposal, absent for discovery attempts.
    #[must_use]
    pub const fn proposal(&self) -> Option<&Proposal> {
        self.proposal.as_ref()
    }

    /// Returns the canonical completion, or `None` when the proof authenticates absence.
    #[must_use]
    pub const fn observation(&self) -> Option<&Observation> {
        self.observation.as_ref()
    }

    /// Validates exact request, snapshot, attempt, provenance, and completion binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or any proof, typed identity, or cross-record basis disagrees.
    pub fn validate_for(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded attempt-explanation response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "explain-campaign-attempt-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.attempt.id()? != request.attempt()
            || self.path.id()? != self.attempt.path()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign attempt explanation basis mismatch",
            });
        }

        let accounting = self.snapshot_body.roots().accounting;
        verify_exact_lookup(
            accounting,
            crate::repository::attempt_index_key(request.attempt()),
            &self.attempt_proof,
            Some(request.attempt().content_id()),
            "campaign attempt membership proof is invalid",
        )?;
        let admission_id = self.admission.id()?;
        verify_exact_lookup(
            accounting,
            crate::repository::attempt_execution_basis_key(request.attempt()),
            &self.admission_proof,
            Some(admission_id.content_id()),
            "campaign attempt admission proof is invalid",
        )?;
        let AttemptAdmissionRole::ExecutionBasis { proposal, .. } = self.admission.role() else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign attempt explanation admission is not an execution basis",
            });
        };
        if self.admission.attempt() != request.attempt() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign attempt explanation admission names another attempt",
            });
        }

        self.validate_start_and_proposal(proposal)?;

        let observation_id = self.observation.as_ref().map(Observation::id).transpose()?;
        if let Some(observation) = &self.observation
            && (observation.attempt() != request.attempt()
                || observation.path() != self.attempt.path()
                || matches!(
                    observation.stop(),
                    crate::StopOutcome::Reached(stop) if stop != self.attempt.stop()
                ))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign attempt explanation observation basis mismatch",
            });
        }
        verify_exact_lookup(
            self.snapshot_body.roots().observations,
            crate::repository::attempt_observation_key(request.attempt()),
            &self.observation_proof,
            observation_id.map(|id| id.content_id()),
            "campaign attempt observation proof is invalid",
        )
    }

    fn validate_start_and_proposal(
        &self,
        admission_proposal: Option<crate::ProposalId>,
    ) -> Result<(), CampaignCodecError> {
        match self.attempt.start() {
            AttemptStart::Discover { .. } => {
                if admission_proposal.is_some()
                    || self.selection.is_some()
                    || self.proposal.is_some()
                    || self.proposal_proof.is_some()
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "campaign discovery explanation carries branch provenance",
                    });
                }
                Ok(())
            }
            AttemptStart::Branch {
                edge,
                selection: selection_id,
                ..
            } => {
                let selection =
                    self.selection
                        .as_ref()
                        .ok_or(CampaignCodecError::InvalidValue {
                            reason: "campaign branch explanation is missing its selection",
                        })?;
                let proposal = self
                    .proposal
                    .as_ref()
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "campaign branch explanation is missing its proposal",
                    })?;
                let proof =
                    self.proposal_proof
                        .as_ref()
                        .ok_or(CampaignCodecError::InvalidValue {
                            reason: "campaign branch explanation is missing its proposal proof",
                        })?;
                let proposal_id = proposal.id()?;
                if selection.id()? != selection_id
                    || admission_proposal != Some(proposal_id)
                    || selection.domain() != proposal.domain()
                    || selection.value() != proposal.value()
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "campaign branch explanation selection and proposal disagree",
                    });
                }
                let SelectionOrigin::CampaignBranch {
                    branch_point,
                    edge: selection_edge,
                } = selection.origin()
                else {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "campaign branch explanation selection has another origin",
                    });
                };
                if branch_point != proposal.branch_point() || selection_edge != edge {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "campaign branch explanation edge provenance disagrees",
                    });
                }
                verify_exact_lookup(
                    self.snapshot_body.roots().exploration,
                    crate::repository::proposal_index_key(proposal_id),
                    proof,
                    Some(proposal_id.content_id()),
                    "campaign attempt proposal proof is invalid",
                )
            }
        }
    }
}

impl Canonical for ExplainCampaignAttemptResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.attempt.encode(encoder);
        self.admission.encode(encoder);
        self.path.encode(encoder);
        self.selection.encode(encoder);
        self.proposal.encode(encoder);
        self.observation.encode(encoder);
        self.attempt_proof.encode(encoder);
        self.admission_proof.encode(encoder);
        self.proposal_proof.encode(encoder);
        self.observation_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            attempt: Attempt::decode(decoder)?,
            admission: AttemptAdmission::decode(decoder)?,
            path: BranchPath::decode(decoder)?,
            selection: Option::decode(decoder)?,
            proposal: Option::decode(decoder)?,
            observation: Option::decode(decoder)?,
            attempt_proof: MerkleMapLookupProof::decode(decoder)?,
            admission_proof: MerkleMapLookupProof::decode(decoder)?,
            proposal_proof: Option::decode(decoder)?,
            observation_proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(&response, "explain-campaign-attempt-response-encoded-bytes")?;
        Ok(response)
    }
}

fn verify_exact_lookup(
    root: ContentId,
    key: CampaignHash,
    proof: &MerkleMapLookupProof,
    expected: Option<ContentId>,
    reason: &'static str,
) -> Result<(), CampaignCodecError> {
    let actual = MerkleMap::verify_lookup_proof(root, key, proof)
        .map_err(|_| CampaignCodecError::InvalidValue { reason })?;
    if actual != expected {
        return Err(CampaignCodecError::InvalidValue { reason });
    }
    Ok(())
}

/// Strict request for one branch-request body authenticated by the frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFrontierObjectRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    request: BranchRequestId,
}

impl GetCampaignFrontierObjectRequest {
    /// Builds one snapshot-bound frontier-object request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        request: BranchRequestId,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            request,
        };
        ensure_message_size(&value, "get-campaign-frontier-object-request-encoded-bytes")?;
        Ok(value)
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

    /// Returns the exact branch request whose body is requested.
    #[must_use]
    pub const fn request(&self) -> BranchRequestId {
        self.request
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-frontier-object", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded frontier-object request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-frontier-object-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignFrontierObjectRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.request.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            BranchRequestId::decode(decoder)?,
        )
    }
}

/// Request-bound branch-request body and exact frontier-membership proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignFrontierObjectResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    projection: ContinuationProjection,
    object: BranchRequest,
    index_proof: MerkleMapLookupProof,
    object_proof: MerkleMapLookupProof,
}

impl GetCampaignFrontierObjectResponse {
    /// Builds one authenticated frontier-object response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, proofs, projection,
    /// request body, or encoded-size contract is invalid.
    pub fn new(
        request: &GetCampaignFrontierObjectRequest,
        snapshot_body: CampaignSnapshot,
        projection: ContinuationProjection,
        object: BranchRequest,
        index_proof: MerkleMapLookupProof,
        object_proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            projection,
            object,
            index_proof,
            object_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-frontier-object-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including every root ID.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the authenticated current projection for the request.
    #[must_use]
    pub const fn projection(&self) -> ContinuationProjection {
        self.projection
    }

    /// Returns the exact authenticated branch-request body.
    #[must_use]
    pub const fn object(&self) -> &BranchRequest {
        &self.object
    }

    /// Validates exact request, snapshot, nested membership, and body binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or either proof, typed identity, or branch point disagrees.
    pub fn validate_for(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded frontier-object response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-frontier-object-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.projection.request() != request.request()
            || self.object.id()? != request.request()
            || self.projection.branch_point() != self.object.branch_point()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign frontier object response basis mismatch",
            });
        }
        let index_root = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().exploration,
            crate::repository::frontier_index_anchor_key(),
            &self.index_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign frontier object index proof is invalid",
        })?
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "campaign snapshot has no authenticated frontier index",
        })?;
        let projection = MerkleMap::verify_lookup_proof(
            index_root,
            crate::repository::frontier_index_order_key(request.request()),
            &self.object_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign frontier object membership proof is invalid",
        })?;
        if projection != Some(self.projection.id()?.content_id()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign frontier object projection is not authenticated",
            });
        }
        Ok(())
    }
}

impl Canonical for GetCampaignFrontierObjectResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.projection.encode(encoder);
        self.object.encode(encoder);
        self.index_proof.encode(encoder);
        self.object_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            projection: ContinuationProjection::decode(decoder)?,
            object: BranchRequest::decode(decoder)?,
            index_proof: MerkleMapLookupProof::decode(decoder)?,
            object_proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-frontier-object-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Choice-opportunity dependency selected for an authenticated body read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignChoiceObjectKind {
    /// The reusable selectable declaration named by the opportunity.
    Declaration,
    /// The exact effective domain named by the opportunity.
    Domain,
}

impl Canonical for CampaignChoiceObjectKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Declaration => 0,
            Self::Domain => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Declaration),
            1 => Ok(Self::Domain),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-choice-object-kind",
                tag,
            }),
        }
    }
}

/// Typed immutable body named by an authenticated choice opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignChoiceObject {
    /// The opportunity's reusable selectable declaration.
    Declaration(SelectableDeclaration),
    /// The opportunity's exact effective domain.
    Domain(ChoiceDomain),
}

impl CampaignChoiceObject {
    /// Returns the closed dependency kind carried by this value.
    #[must_use]
    pub const fn kind(&self) -> CampaignChoiceObjectKind {
        match self {
            Self::Declaration(_) => CampaignChoiceObjectKind::Declaration,
            Self::Domain(_) => CampaignChoiceObjectKind::Domain,
        }
    }
}

impl Canonical for CampaignChoiceObject {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Declaration(value) => {
                CampaignChoiceObjectKind::Declaration.encode(encoder);
                value.encode(encoder);
            }
            Self::Domain(value) => {
                CampaignChoiceObjectKind::Domain.encode(encoder);
                value.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match CampaignChoiceObjectKind::decode(decoder)? {
            CampaignChoiceObjectKind::Declaration => {
                SelectableDeclaration::decode(decoder).map(Self::Declaration)
            }
            CampaignChoiceObjectKind::Domain => ChoiceDomain::decode(decoder).map(Self::Domain),
        }
    }
}

/// Strict request for one dependency of an authenticated choice opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignChoiceObjectRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    opportunity: ChoiceOpportunityId,
    kind: CampaignChoiceObjectKind,
}

impl GetCampaignChoiceObjectRequest {
    /// Builds one snapshot-bound choice-dependency request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        opportunity: ChoiceOpportunityId,
        kind: CampaignChoiceObjectKind,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            opportunity,
            kind,
        };
        ensure_message_size(&request, "get-campaign-choice-object-request-encoded-bytes")?;
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

    /// Returns the exact current snapshot that anchors the opportunity.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the exact opportunity that names the requested body.
    #[must_use]
    pub const fn opportunity(&self) -> ChoiceOpportunityId {
        self.opportunity
    }

    /// Returns the requested closed dependency kind.
    #[must_use]
    pub const fn kind(&self) -> CampaignChoiceObjectKind {
        self.kind
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-choice-object", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded choice-dependency request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-choice-object-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignChoiceObjectRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.opportunity.encode(encoder);
        self.kind.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            ChoiceOpportunityId::decode(decoder)?,
            CampaignChoiceObjectKind::decode(decoder)?,
        )
    }
}

/// Request-bound choice dependency and exact opportunity-membership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignChoiceObjectResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    opportunity: ChoiceOpportunity,
    object: CampaignChoiceObject,
    proof: MerkleMapLookupProof,
}

impl GetCampaignChoiceObjectResponse {
    /// Builds one authenticated choice-dependency response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, proof, opportunity,
    /// dependency kind or identity, or encoded-size contract is invalid.
    pub fn new(
        request: &GetCampaignChoiceObjectRequest,
        snapshot_body: CampaignSnapshot,
        opportunity: ChoiceOpportunity,
        object: CampaignChoiceObject,
        proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            opportunity,
            object,
            proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-choice-object-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including every root ID.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the exact opportunity that names the dependency.
    #[must_use]
    pub const fn opportunity(&self) -> &ChoiceOpportunity {
        &self.opportunity
    }

    /// Returns the exact typed dependency body.
    #[must_use]
    pub const fn object(&self) -> &CampaignChoiceObject {
        &self.object
    }

    /// Validates exact request, snapshot, opportunity, proof, and dependency binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or the dependency is not named by the authenticated opportunity.
    pub fn validate_for(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded choice-dependency response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-choice-object-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.opportunity.id()? != request.opportunity()
            || self.object.kind() != request.kind()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign choice object response basis mismatch",
            });
        }
        let value = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().graph,
            crate::repository::authoritative_choice_key(request.opportunity()),
            &self.proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign choice object opportunity proof is invalid",
        })?;
        if value != Some(request.opportunity().content_id()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign choice object opportunity is not graph-authenticated",
            });
        }
        let matches_reference = match &self.object {
            CampaignChoiceObject::Declaration(value) => {
                self.opportunity.declaration() == value.id()?
            }
            CampaignChoiceObject::Domain(value) => self.opportunity.domain() == value.id()?,
        };
        if !matches_reference {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign choice object is not named by the opportunity",
            });
        }
        Ok(())
    }
}

impl Canonical for GetCampaignChoiceObjectResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.opportunity.encode(encoder);
        self.object.encode(encoder);
        self.proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            opportunity: ChoiceOpportunity::decode(decoder)?,
            object: CampaignChoiceObject::decode(decoder)?,
            proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-choice-object-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// One immutable key/value entry from a campaign graph root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGraphEntry {
    key: CampaignHash,
    object: ContentId,
}

impl CampaignGraphEntry {
    /// Builds one graph-root entry.
    #[must_use]
    pub const fn new(key: CampaignHash, object: ContentId) -> Self {
        Self { key, object }
    }

    /// Returns the canonical graph ordering key.
    #[must_use]
    pub const fn key(self) -> CampaignHash {
        self.key
    }

    /// Returns the content-addressed graph object.
    #[must_use]
    pub const fn object(self) -> ContentId {
        self.object
    }
}

impl Canonical for CampaignGraphEntry {
    fn encode(&self, encoder: &mut Encoder) {
        self.key.encode(encoder);
        Canonical::encode(&self.object, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            key: CampaignHash::decode(decoder)?,
            object: ContentId::decode(decoder)?,
        })
    }
}

/// Strict request for one current-snapshot graph page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignGraphRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    after: Option<CampaignHash>,
    limit: u32,
}

impl QueryCampaignGraphRequest {
    /// Builds one bounded snapshot-bound graph query.
    ///
    /// `after` is the exclusive key returned by the preceding page. The first
    /// page uses `None`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `limit` is zero or exceeds
    /// [`MAX_CAMPAIGN_QUERY_PAGE_ITEMS`], or when the encoded request exceeds
    /// the service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        after: Option<CampaignHash>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_QUERY_PAGE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-query-page-items",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            after,
            limit,
        };
        ensure_message_size(&request, "query-campaign-graph-request-encoded-bytes")?;
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

    /// Returns the exclusive graph-key cursor, if this is not the first page.
    #[must_use]
    pub const fn after(&self) -> Option<CampaignHash> {
        self.after
    }

    /// Returns the maximum entries requested for this page.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-graph", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded graph query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-graph-request-encoded-bytes")
    }
}

impl Canonical for QueryCampaignGraphRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            Option::<CampaignHash>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Request-bound ascending page plus the complete anchoring snapshot metadata.
///
/// Authorization for this response grants visibility of every root ID, parent,
/// lineage, policy, and transition in the snapshot body. It does not grant
/// access to the objects named by those content IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignGraphResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshotId,
    snapshot_body: CampaignSnapshot,
    entries: Vec<CampaignGraphEntry>,
    next_after: Option<CampaignHash>,
    proof: MerkleMapPageProof,
}

impl QueryCampaignGraphResponse {
    /// Builds one response bound to an exact graph query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the page ordering, count, cursor,
    /// or encoded-size contract is invalid.
    pub fn new(
        request: &QueryCampaignGraphRequest,
        snapshot_body: CampaignSnapshot,
        entries: Vec<CampaignGraphEntry>,
        next_after: Option<CampaignHash>,
        proof: MerkleMapPageProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot: request.snapshot(),
            snapshot_body,
            entries,
            next_after,
            proof,
        };
        response.validate_page_for(request)?;
        ensure_message_size(&response, "query-campaign-graph-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the immutable snapshot that anchors every page entry.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the authenticated snapshot body, including all snapshot root IDs.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns entries in strict ascending graph-key order.
    #[must_use]
    pub fn entries(&self) -> &[CampaignGraphEntry] {
        &self.entries
    }

    /// Returns the exclusive cursor for the next page, or `None` at EOF.
    #[must_use]
    pub const fn next_after(&self) -> Option<CampaignHash> {
        self.next_after
    }

    /// Validates exact request, snapshot, page, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or violates the bounded ascending-page contract.
    pub fn validate_for(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_page_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded graph response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-graph-response-encoded-bytes")
    }

    fn validate_page_for(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<(), CampaignCodecError> {
        let request_limit =
            usize::try_from(request.limit()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "campaign-query-page-items",
            })?;
        if self.snapshot != request.snapshot()
            || self.snapshot_body.id()? != request.snapshot()
            || self.entries.len() > request_limit
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign graph response snapshot or page limit mismatch",
            });
        }
        let verified = MerkleMap::verify_scan_proof(
            self.snapshot_body.roots().graph,
            request.after(),
            request_limit,
            &self.proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign graph response Merkle proof is invalid",
        })?;
        let verified_entries = verified
            .entries()
            .iter()
            .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
            .collect::<Vec<_>>();
        if self.entries != verified_entries || self.next_after != verified.next_after() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign graph response differs from its Merkle proof",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignGraphResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            entries: decoder.sequence_bounded(
                usize::try_from(MAX_CAMPAIGN_QUERY_PAGE_ITEMS).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "campaign-query-page-items",
                    }
                })?,
                "campaign-query-page-items",
                CampaignGraphEntry::decode,
            )?,
            next_after: Option::<CampaignHash>::decode(decoder)?,
            proof: MerkleMapPageProof::decode(decoder)?,
        };
        ensure_message_size(&response, "query-campaign-graph-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Strict request for one object named by an exact current graph entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignGraphObjectRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    key: CampaignHash,
}

impl GetCampaignGraphObjectRequest {
    /// Builds one snapshot-bound graph-object request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        key: CampaignHash,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            key,
        };
        ensure_message_size(&request, "get-campaign-graph-object-request-encoded-bytes")?;
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

    /// Returns the exact current snapshot that anchors this lookup.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the exact graph key whose value is requested.
    #[must_use]
    pub const fn key(&self) -> CampaignHash {
        self.key
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-graph-object", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded graph-object request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-graph-object-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignGraphObjectRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.key.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            CampaignHash::decode(decoder)?,
        )
    }
}

/// Request-bound graph object plus exact snapshot-membership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignGraphObjectResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    object: ObjectEnvelope,
    proof: MerkleMapLookupProof,
}

impl GetCampaignGraphObjectResponse {
    /// Builds one authenticated graph-object response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, proof, object kind,
    /// key membership, or encoded-size contract is invalid.
    pub fn new(
        request: &GetCampaignGraphObjectRequest,
        snapshot_body: CampaignSnapshot,
        object: ObjectEnvelope,
        proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            object,
            proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-graph-object-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including all root IDs.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the strict graph-owned object envelope.
    #[must_use]
    pub const fn object(&self) -> &ObjectEnvelope {
        &self.object
    }

    /// Validates exact request, snapshot, graph membership, and object identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or its proof and object do not match the requested graph entry.
    pub fn validate_for(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded graph-object response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-graph-object-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || !matches!(
                self.object.record_kind(),
                CampaignRecordKind::ConfigurationArtifact | CampaignRecordKind::ChoiceOpportunity
            )
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign graph object response snapshot or record kind mismatch",
            });
        }
        let value = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().graph,
            request.key(),
            &self.proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign graph object response Merkle proof is invalid",
        })?;
        if value != Some(self.object.content_id()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign graph object differs from its Merkle proof",
            });
        }
        Ok(())
    }
}

impl Canonical for GetCampaignGraphObjectResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.object.canonical_bytes().encode(encoder);
        self.proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            object: ObjectEnvelope::from_canonical_bytes(&decoder.sequence_bounded(
                MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
                "get-campaign-graph-object-envelope-bytes",
                u8::decode,
            )?)?,
            proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-graph-object-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use crucible_cas::content_store::{MemoryBlobBackend, ObjectKind};

    use super::*;
    use crate::{
        AdmissionOrdinal, AttemptId, BooleanDomain, BranchBudget, BranchPathId, BranchPathSegment,
        BranchPointId, BranchRequestCause, CampaignCommandId, CampaignPolicyId, CampaignRoots,
        CampaignViewId, CandidateSource, ChoiceClassContext, ChoiceCoordinate, ChoiceDomainId,
        ChoiceOpportunityId, ChoiceSource, ChoiceValue, ConfigurationArtifact,
        ConfigurationArtifactId, ConfigurationId, ContinuationState, CoverageProjectionId,
        FindingKind, FindingOccurrenceSet, FindingSignature, MeasurementSetId, ObservationId,
        PropertyVerdictSetId, ReproductionArtifactId, ScenarioArtifactId, ScenarioDefId,
        StopCondition, StopOutcome,
    };

    fn hash(label: &str) -> CampaignHash {
        CampaignHash::derive("campaign-query-test-hash", label.as_bytes())
    }

    fn snapshot(label: &str) -> CampaignSnapshotId {
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            2,
            label.as_bytes(),
        ))
        .expect("snapshot")
    }

    fn graph_entry(label: &str) -> CampaignGraphEntry {
        CampaignGraphEntry::new(
            CampaignHash::derive("campaign-query-test-key", label.as_bytes()),
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()),
        )
    }

    fn branch_request(label: &str) -> BranchRequest {
        let hash = |suffix: &str| {
            CampaignHash::derive(
                "campaign-frontier-object-test",
                format!("{label}-{suffix}").as_bytes(),
            )
        };
        BranchRequest::new(
            BranchPointId::from_hash(hash("branch-point")),
            ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                ObjectKind::Configuration,
                1,
                format!("{label}-parent").as_bytes(),
            ))
            .expect("parent id"),
            ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("{label}-opportunity").as_bytes(),
            ))
            .expect("opportunity id"),
            ChoiceDomainId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("{label}-domain").as_bytes(),
            ))
            .expect("domain id"),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("finite source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("command"))),
            BranchBudget::new(1, 1).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request")
    }

    fn configuration_envelope(label: &str) -> ObjectEnvelope {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
            "campaign-query-test-scenario",
            label.as_bytes(),
        ));
        let scenario_artifact = ScenarioArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Scenario,
            1,
            format!("{label}-scenario").as_bytes(),
        ))
        .expect("scenario artifact id");
        let configuration = ConfigurationArtifact::new(
            scenario,
            scenario_artifact,
            ConfigurationId::from_hash(CampaignHash::derive(
                "campaign-query-test-configuration",
                label.as_bytes(),
            )),
            1,
            label.as_bytes().to_vec(),
        )
        .expect("configuration artifact");
        ObjectEnvelope::for_configuration_artifact(&configuration).expect("configuration envelope")
    }

    fn choice_objects() -> (SelectableDeclaration, ChoiceDomain, ChoiceOpportunity) {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.network.retry",
            ChoiceSource::Workload {
                producer: "network-product".to_owned(),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
                .expect("choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("declaration");
        let opportunity = ChoiceOpportunity::new(
            ScenarioDefId::from_hash(CampaignHash::derive(
                "campaign-choice-object-test-scenario",
                b"scenario",
            )),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive(
                    "campaign-choice-object-test-coordinate",
                    b"scheduler",
                ),
                producer: CampaignHash::derive(
                    "campaign-choice-object-test-coordinate",
                    b"producer",
                ),
            },
            "retry-choice",
            None,
        )
        .expect("opportunity");
        (declaration, domain, opportunity)
    }

    fn finding(label: &str, occurrence_root: ContentId) -> Finding {
        let observation = ObservationId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            format!("{label}-observation").as_bytes(),
        ))
        .expect("observation id");
        Finding::new(
            FindingSignature::new(
                FindingKind::Timeout,
                CampaignHash::derive("campaign-query-finding-fingerprint", label.as_bytes()),
                None,
                format!("timeout.{label}"),
                None,
                BTreeSet::new(),
            )
            .expect("finding signature"),
            observation,
            ReproductionArtifactId::from_content_id(ContentId::for_bytes(
                ObjectKind::Finding,
                1,
                format!("{label}-reproduction").as_bytes(),
            ))
            .expect("reproduction id"),
            snapshot(&format!("{label}-first-seen")),
            FindingOccurrenceSet::new(occurrence_root, 1, observation)
                .expect("finding occurrences"),
            None,
            BTreeSet::new(),
        )
        .expect("finding")
    }

    #[test]
    fn graph_pages_are_canonical_bounded_snapshot_and_cursor_bound() {
        assert!(
            QueryCampaignGraphRequest::new(
                CampaignPrincipal::new("operator:alice").expect("principal"),
                CampaignName::new("network-recovery").expect("campaign"),
                snapshot("current"),
                None,
                0,
            )
            .is_err()
        );
        assert!(
            QueryCampaignGraphRequest::new(
                CampaignPrincipal::new("operator:alice").expect("principal"),
                CampaignName::new("network-recovery").expect("campaign"),
                snapshot("current"),
                None,
                MAX_CAMPAIGN_QUERY_PAGE_ITEMS + 1,
            )
            .is_err()
        );

        let backend = Arc::new(MemoryBlobBackend::new("query-proof-test", u64::MAX));
        let map = MerkleMap::new(backend);
        let mut root = map.empty().expect("empty graph root");
        for entry in [
            graph_entry("first"),
            graph_entry("second"),
            graph_entry("third"),
        ] {
            root = map
                .insert(root.content_id(), entry.key(), entry.object())
                .expect("graph insert");
        }
        let roots = crate::CampaignRoots {
            graph: root.content_id(),
            exploration: root.content_id(),
            observations: root.content_id(),
            corpus: root.content_id(),
            coverage: root.content_id(),
            findings: root.content_id(),
            pins: root.content_id(),
            accounting: root.content_id(),
            coordination: root.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"query-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"query-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("query snapshot");
        let request = QueryCampaignGraphRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            None,
            2,
        )
        .expect("query request");
        assert_eq!(
            QueryCampaignGraphRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );

        let (page, proof) = map
            .scan_with_proof(root.content_id(), None, 2)
            .expect("proven page");
        let entries = page
            .entries()
            .iter()
            .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
            .collect::<Vec<_>>();
        let response = QueryCampaignGraphResponse::new(
            &request,
            snapshot_body.clone(),
            entries.clone(),
            page.next_after(),
            proof.clone(),
        )
        .expect("query response");
        response.validate_for(&request).expect("response binding");
        assert_eq!(
            QueryCampaignGraphResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );
        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("1bf139d3ed67872df2ec5241f5b1f3ffa578372fb8899deda231919342a834c0"),
                String::from("3d774c8603010f829bc81f672cabc7c683c98f9adeb8e10c7d8753f39b51f323"),
            ]
        );

        let mut reversed = entries.clone();
        reversed.reverse();
        assert!(
            QueryCampaignGraphResponse::new(
                &request,
                snapshot_body.clone(),
                reversed,
                page.next_after(),
                proof.clone(),
            )
            .is_err()
        );
        let mut forged_eof = response.clone();
        forged_eof.next_after = None;
        let forged_eof =
            QueryCampaignGraphResponse::from_canonical_bytes(&forged_eof.canonical_bytes())
                .expect("structurally canonical forged EOF");
        assert!(forged_eof.validate_for(&request).is_err());

        let mut substituted = entries.clone();
        substituted[0] = CampaignGraphEntry::new(
            substituted[0].key(),
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"substituted-object"),
        );
        assert!(
            QueryCampaignGraphResponse::new(
                &request,
                snapshot_body.clone(),
                substituted.clone(),
                page.next_after(),
                proof.clone(),
            )
            .is_err()
        );
        let mut forged_entry = response.clone();
        forged_entry.entries = substituted;
        let forged_entry =
            QueryCampaignGraphResponse::from_canonical_bytes(&forged_entry.canonical_bytes())
                .expect("structurally canonical substituted entry");
        assert!(forged_entry.validate_for(&request).is_err());

        assert!(
            QueryCampaignGraphResponse::new(
                &request,
                snapshot_body.clone(),
                entries.clone(),
                None,
                proof.clone(),
            )
            .is_err()
        );
        assert!(
            QueryCampaignGraphResponse::new(
                &request,
                snapshot_body,
                entries[..1].to_vec(),
                page.next_after(),
                proof,
            )
            .is_err()
        );

        let next_request = QueryCampaignGraphRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            request.snapshot(),
            response.next_after(),
            2,
        )
        .expect("next request");
        assert!(response.validate_for(&next_request).is_err());

        assert!(
            CampaignServiceFailure::Stale {
                expected: request.snapshot(),
                current: snapshot("new-current"),
            }
            .validate_for_query_campaign_graph(request.snapshot())
            .is_ok()
        );
        assert!(
            CampaignServiceFailure::Stale {
                expected: snapshot("wrong-expected"),
                current: snapshot("new-current"),
            }
            .validate_for_query_campaign_graph(request.snapshot())
            .is_err()
        );
        assert!(
            CampaignServiceFailure::Stale {
                expected: request.snapshot(),
                current: request.snapshot(),
            }
            .validate_for_query_campaign_graph(request.snapshot())
            .is_err()
        );
    }

    #[test]
    fn finding_pages_authenticate_complete_bodies_order_and_exact_eof() {
        assert!(
            QueryCampaignFindingsRequest::new(
                CampaignPrincipal::new("operator:alice").expect("principal"),
                CampaignName::new("network-recovery").expect("campaign"),
                snapshot("current"),
                None,
                MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS + 1,
            )
            .is_err()
        );

        let backend = Arc::new(MemoryBlobBackend::new("finding-query-proof", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty finding index");
        let findings = [
            finding("first", empty.content_id()),
            finding("second", empty.content_id()),
            finding("third", empty.content_id()),
        ];
        let mut root = empty;
        for finding in &findings {
            root = map
                .insert(
                    root.content_id(),
                    crate::repository::finding_signature_key(finding.signature().cluster_key()),
                    finding.id().expect("finding id").content_id(),
                )
                .expect("finding index insert");
        }
        let roots = CampaignRoots {
            graph: empty.content_id(),
            exploration: empty.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: root.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"finding-query-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"finding-query-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("finding query snapshot");
        let request = QueryCampaignFindingsRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            None,
            2,
        )
        .expect("finding query");
        let (page, proof) = map
            .scan_with_proof(root.content_id(), request.after(), 2)
            .expect("finding page proof");
        let entries = page
            .entries()
            .iter()
            .map(|(_, id)| {
                findings
                    .iter()
                    .find(|finding| finding.id().expect("finding identity").content_id() == *id)
                    .expect("indexed finding")
                    .clone()
            })
            .collect::<Vec<_>>();
        let response = QueryCampaignFindingsResponse::new(
            &request,
            snapshot_body,
            entries,
            page.next_after(),
            proof,
        )
        .expect("finding response");
        response.validate_for(&request).expect("response binding");
        assert_eq!(
            QueryCampaignFindingsRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        assert_eq!(
            QueryCampaignFindingsResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );

        let mut forged_eof = response.clone();
        forged_eof.next_after = None;
        let forged_eof =
            QueryCampaignFindingsResponse::from_canonical_bytes(&forged_eof.canonical_bytes())
                .expect("structurally canonical false EOF");
        assert!(forged_eof.validate_for(&request).is_err());

        let mut substituted = response.clone();
        substituted.entries[0] = finding("substituted", empty.content_id());
        let substituted =
            QueryCampaignFindingsResponse::from_canonical_bytes(&substituted.canonical_bytes())
                .expect("structurally canonical substitution");
        assert!(substituted.validate_for(&request).is_err());

        let next = QueryCampaignFindingsRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            request.snapshot(),
            response.next_after(),
            2,
        )
        .expect("next finding query");
        assert!(response.validate_for(&next).is_err());
    }

    #[test]
    fn finding_object_reads_authenticate_exact_child_kind_and_identity() {
        let backend = Arc::new(MemoryBlobBackend::new("finding-object-proof", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty finding index");
        let scenario = ScenarioDefId::from_hash(hash("finding-object-scenario"));
        let scenario_artifact = ScenarioArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Scenario,
            1,
            b"finding-object-scenario-artifact",
        ))
        .expect("scenario artifact ID");
        let configuration = ConfigurationId::from_hash(hash("finding-object-configuration"));
        let configuration_artifact =
            ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                ObjectKind::Configuration,
                1,
                b"finding-object-configuration-artifact",
            ))
            .expect("configuration artifact ID");
        let observation = Observation::new(
            AttemptId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"finding-object-attempt",
            ))
            .expect("attempt ID"),
            configuration,
            configuration_artifact,
            BranchPathId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                2,
                b"finding-object-path",
            ))
            .expect("path ID"),
            StopOutcome::ModeledTimeout("execution".to_owned()),
            MeasurementSetId::from_content_id(ContentId::for_bytes(
                ObjectKind::Observation,
                1,
                b"finding-object-measurements",
            ))
            .expect("measurement ID"),
            PropertyVerdictSetId::from_content_id(ContentId::for_bytes(
                ObjectKind::Observation,
                1,
                b"finding-object-properties",
            ))
            .expect("property ID"),
            CoverageProjectionId::from_content_id(ContentId::for_bytes(
                ObjectKind::Projection,
                1,
                b"finding-object-coverage",
            ))
            .expect("coverage ID"),
            BTreeSet::new(),
        )
        .expect("observation");
        let observation_id = observation.id().expect("observation ID");
        let reproduction = ReproductionArtifact::new(
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            hash("finding-object-fingerprint"),
            1,
            b"reproduce".to_vec(),
        )
        .expect("reproduction");
        let finding = Finding::new(
            FindingSignature::new(
                FindingKind::Timeout,
                hash("finding-object-fingerprint"),
                None,
                "timeout.execution".to_owned(),
                None,
                BTreeSet::new(),
            )
            .expect("finding signature"),
            observation_id,
            reproduction.id().expect("reproduction ID"),
            snapshot("finding-object-first-seen"),
            FindingOccurrenceSet::new(empty.content_id(), 1, observation_id)
                .expect("finding occurrences"),
            None,
            BTreeSet::new(),
        )
        .expect("finding");
        let finding_id = finding.id().expect("finding ID");
        let root = map
            .insert(
                empty.content_id(),
                crate::repository::finding_signature_key(finding.signature().cluster_key()),
                finding_id.content_id(),
            )
            .expect("finding index");
        let roots = CampaignRoots {
            graph: empty.content_id(),
            exploration: empty.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: root.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"finding-object-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"finding-object-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("finding object snapshot");
        let request = GetCampaignFindingObjectRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot ID"),
            finding_id,
            CampaignFindingObjectKind::Observation,
        )
        .expect("finding object request");
        let (_, proof) = map
            .get_with_proof(
                root.content_id(),
                crate::repository::finding_signature_key(finding.signature().cluster_key()),
            )
            .expect("finding lookup proof");
        let response = GetCampaignFindingObjectResponse::new(
            &request,
            snapshot_body,
            finding,
            CampaignFindingObject::Observation(observation),
            proof,
        )
        .expect("finding object response");
        response.validate_for(&request).expect("response binding");
        assert_eq!(
            GetCampaignFindingObjectRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("request decode"),
            request
        );
        assert_eq!(
            GetCampaignFindingObjectResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("response decode"),
            response
        );

        let mut wrong_kind = response.clone();
        let CampaignFindingObject::Observation(value) = wrong_kind.object else {
            unreachable!("fixture object kind")
        };
        wrong_kind.object = CampaignFindingObject::LatestOccurrence(value);
        assert!(wrong_kind.validate_for(&request).is_err());

        let reproduction_request = GetCampaignFindingObjectRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            request.snapshot(),
            request.finding(),
            CampaignFindingObjectKind::Reproduction,
        )
        .expect("reproduction request");
        assert!(response.validate_for(&reproduction_request).is_err());
    }

    #[test]
    fn attempt_explanations_authenticate_execution_proposal_selection_and_completion() {
        let backend = Arc::new(MemoryBlobBackend::new(
            "attempt-explanation-proof",
            u64::MAX,
        ));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty attempt indexes");
        let (_declaration, domain, opportunity) = choice_objects();
        let parent_configuration = ConfigurationId::from_hash(hash("attempt-parent"));
        let parent = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"attempt-parent-artifact",
        ))
        .expect("attempt parent artifact ID");
        let branch_point = opportunity.branch_point_id(parent_configuration);
        let value = ChoiceValue::Boolean(true);
        let selection =
            Selection::new_campaign_branch(&opportunity, &domain, value.clone(), branch_point)
                .expect("attempt selection");
        let selection_id = selection.id().expect("attempt selection ID");
        let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
            unreachable!("campaign branch selection origin")
        };
        let path = BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)])
            .expect("attempt branch path");
        let path_id = path.id().expect("attempt branch path ID");
        let request = BranchRequest::new(
            branch_point,
            parent,
            opportunity.id().expect("attempt opportunity ID"),
            domain.id().expect("attempt domain ID"),
            CandidateSource::finite(BTreeSet::from([value.clone()])).expect("attempt source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("attempt-command"))),
            BranchBudget::new(1, 1).expect("attempt budget"),
            StopCondition::NextChoice,
        )
        .expect("attempt request");
        let proposal = Proposal::new(
            branch_point,
            request.id().expect("attempt request ID"),
            domain.id().expect("attempt proposal domain"),
            value,
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"attempt-policy",
            ))
            .expect("attempt policy ID"),
            None,
            1,
            CampaignViewId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"attempt-guidance-view",
            ))
            .expect("attempt guidance view ID"),
        )
        .expect("attempt proposal");
        let proposal_id = proposal.id().expect("attempt proposal ID");
        let attempt = Attempt::new(
            AttemptStart::Branch {
                edge,
                parent,
                selection: selection_id,
            },
            path_id,
            StopCondition::NextChoice,
        )
        .expect("attempt");
        let attempt_id = attempt.id().expect("attempt ID");
        let admission = AttemptAdmission::new(
            attempt_id,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal_id),
                cause: request.cause(),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        );
        let admission_id = admission.id().expect("attempt admission ID");
        let observation = Observation::new(
            attempt_id,
            parent_configuration,
            parent,
            path_id,
            StopOutcome::TerminalSuccess,
            MeasurementSetId::from_content_id(ContentId::for_bytes(
                ObjectKind::Observation,
                1,
                b"attempt-explanation-measurements",
            ))
            .expect("attempt measurement ID"),
            PropertyVerdictSetId::from_content_id(ContentId::for_bytes(
                ObjectKind::Observation,
                1,
                b"attempt-explanation-properties",
            ))
            .expect("attempt property ID"),
            CoverageProjectionId::from_content_id(ContentId::for_bytes(
                ObjectKind::Projection,
                1,
                b"attempt-explanation-coverage",
            ))
            .expect("attempt coverage ID"),
            BTreeSet::new(),
        )
        .expect("attempt observation");
        let observation_id = observation.id().expect("attempt observation ID");

        let accounting_attempt = map
            .insert(
                empty.content_id(),
                crate::repository::attempt_index_key(attempt_id),
                attempt_id.content_id(),
            )
            .expect("attempt accounting membership");
        let accounting = map
            .insert(
                accounting_attempt.content_id(),
                crate::repository::attempt_execution_basis_key(attempt_id),
                admission_id.content_id(),
            )
            .expect("attempt accounting root");
        let exploration = map
            .insert(
                empty.content_id(),
                crate::repository::proposal_index_key(proposal_id),
                proposal_id.content_id(),
            )
            .expect("attempt proposal root");
        let observations = map
            .insert(
                empty.content_id(),
                crate::repository::attempt_observation_key(attempt_id),
                observation_id.content_id(),
            )
            .expect("attempt observation root");
        let roots = CampaignRoots {
            graph: empty.content_id(),
            exploration: exploration.content_id(),
            observations: observations.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: accounting.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"attempt-explanation-lineage",
            ))
            .expect("attempt lineage ID"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"attempt-explanation-snapshot-policy",
            ))
            .expect("attempt snapshot policy ID"),
            roots,
        )
        .expect("attempt explanation snapshot");
        let explanation_request = ExplainCampaignAttemptRequest::new(
            CampaignPrincipal::new("operator:alice").expect("attempt principal"),
            CampaignName::new("network-recovery").expect("attempt campaign"),
            snapshot_body.id().expect("attempt snapshot ID"),
            attempt_id,
        )
        .expect("attempt explanation request");
        let (_, attempt_proof) = map
            .get_with_proof(
                accounting.content_id(),
                crate::repository::attempt_index_key(attempt_id),
            )
            .expect("attempt membership proof");
        let (_, admission_proof) = map
            .get_with_proof(
                accounting.content_id(),
                crate::repository::attempt_execution_basis_key(attempt_id),
            )
            .expect("attempt admission proof");
        let (_, proposal_proof) = map
            .get_with_proof(
                exploration.content_id(),
                crate::repository::proposal_index_key(proposal_id),
            )
            .expect("attempt proposal proof");
        let (_, observation_proof) = map
            .get_with_proof(
                observations.content_id(),
                crate::repository::attempt_observation_key(attempt_id),
            )
            .expect("attempt observation proof");
        let response = ExplainCampaignAttemptResponse::new(
            &explanation_request,
            snapshot_body,
            attempt,
            admission,
            path,
            Some(selection),
            Some(proposal),
            Some(observation),
            attempt_proof,
            admission_proof,
            Some(proposal_proof),
            observation_proof,
        )
        .expect("attempt explanation response");
        response
            .validate_for(&explanation_request)
            .expect("attempt explanation binding");
        assert_eq!(
            ExplainCampaignAttemptRequest::from_canonical_bytes(
                &explanation_request.canonical_bytes()
            )
            .expect("attempt request decode"),
            explanation_request
        );
        assert_eq!(
            ExplainCampaignAttemptResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("attempt response decode"),
            response
        );

        let mut wrong = response.clone();
        let Some(proposal) = wrong.proposal.as_mut() else {
            unreachable!("branch proposal")
        };
        *proposal = Proposal::new(
            proposal.branch_point(),
            proposal.request(),
            proposal.domain(),
            ChoiceValue::Boolean(false),
            proposal.policy(),
            proposal.planner_invocation(),
            proposal.ordinal(),
            proposal.guidance_basis(),
        )
        .expect("wrong attempt proposal");
        assert!(wrong.validate_for(&explanation_request).is_err());
    }

    #[test]
    fn discovery_attempt_explanations_authenticate_absent_branch_and_completion_state() {
        let backend = Arc::new(MemoryBlobBackend::new(
            "discovery-attempt-explanation",
            u64::MAX,
        ));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty discovery explanation root");
        let configuration = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"discovery-explanation-configuration",
        ))
        .expect("discovery configuration ID");
        let path = BranchPath::new(Vec::new()).expect("discovery path");
        let attempt = Attempt::new(
            AttemptStart::Discover { configuration },
            path.id().expect("discovery path ID"),
            StopCondition::NextChoice,
        )
        .expect("discovery attempt");
        let attempt_id = attempt.id().expect("discovery attempt ID");
        let admission = AttemptAdmission::new(
            attempt_id,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::ExhaustivePolicy(
                    CampaignPolicyId::from_content_id(ContentId::for_bytes(
                        ObjectKind::Policy,
                        1,
                        b"discovery-explanation-policy",
                    ))
                    .expect("discovery policy ID"),
                ),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        );
        let accounting = map
            .insert(
                empty.content_id(),
                crate::repository::attempt_index_key(attempt_id),
                attempt_id.content_id(),
            )
            .expect("discovery attempt membership");
        let accounting = map
            .insert(
                accounting.content_id(),
                crate::repository::attempt_execution_basis_key(attempt_id),
                admission.id().expect("discovery admission ID").content_id(),
            )
            .expect("discovery admission membership");
        let roots = CampaignRoots {
            graph: empty.content_id(),
            exploration: empty.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: accounting.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"discovery-explanation-lineage",
            ))
            .expect("discovery lineage ID"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"discovery-explanation-active-policy",
            ))
            .expect("discovery active policy ID"),
            roots,
        )
        .expect("discovery explanation snapshot");
        let request = ExplainCampaignAttemptRequest::new(
            CampaignPrincipal::new("operator:alice").expect("discovery principal"),
            CampaignName::new("discovery-campaign").expect("discovery campaign"),
            snapshot_body.id().expect("discovery snapshot ID"),
            attempt_id,
        )
        .expect("discovery explanation request");
        let (_, attempt_proof) = map
            .get_with_proof(
                accounting.content_id(),
                crate::repository::attempt_index_key(attempt_id),
            )
            .expect("discovery attempt proof");
        let (_, admission_proof) = map
            .get_with_proof(
                accounting.content_id(),
                crate::repository::attempt_execution_basis_key(attempt_id),
            )
            .expect("discovery admission proof");
        let (_, observation_proof) = map
            .get_with_proof(
                empty.content_id(),
                crate::repository::attempt_observation_key(attempt_id),
            )
            .expect("discovery absence proof");
        let response = ExplainCampaignAttemptResponse::new(
            &request,
            snapshot_body,
            attempt,
            admission,
            path,
            None,
            None,
            None,
            attempt_proof,
            admission_proof,
            None,
            observation_proof,
        )
        .expect("discovery explanation response");

        response
            .validate_for(&request)
            .expect("discovery explanation binding");
        assert!(response.selection().is_none());
        assert!(response.proposal().is_none());
        assert!(response.observation().is_none());
    }

    #[test]
    fn graph_object_response_authenticates_snapshot_key_and_exact_envelope() {
        let backend = Arc::new(MemoryBlobBackend::new("graph-object-query", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty graph");
        let key = CampaignHash::derive("campaign-query-test-key", b"configuration");
        let object = configuration_envelope("configuration");
        let graph = map
            .insert(empty.content_id(), key, object.content_id())
            .expect("graph insert");
        let roots = CampaignRoots {
            graph: graph.content_id(),
            exploration: empty.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"graph-object-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"graph-object-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("snapshot");
        let request = GetCampaignGraphObjectRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            key,
        )
        .expect("request");
        let (_, proof) = map
            .get_with_proof(graph.content_id(), key)
            .expect("lookup proof");
        let response = GetCampaignGraphObjectResponse::new(&request, snapshot_body, object, proof)
            .expect("response");
        let decoded =
            GetCampaignGraphObjectResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response");
        decoded.validate_for(&request).expect("verify response");

        let mut substituted = decoded;
        substituted.object = configuration_envelope("substituted");
        assert!(substituted.validate_for(&request).is_err());
        let wrong_key = GetCampaignGraphObjectRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            request.snapshot(),
            CampaignHash::derive("campaign-query-test-key", b"other"),
        )
        .expect("wrong-key request");
        assert!(response.validate_for(&wrong_key).is_err());
    }

    #[test]
    fn choice_pages_authenticate_the_nested_index_and_exact_eof() {
        assert!(
            QueryCampaignChoicesRequest::new(
                CampaignPrincipal::new("operator:alice").expect("principal"),
                CampaignName::new("network-recovery").expect("campaign"),
                snapshot("choice-limit"),
                None,
                MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS + 1,
            )
            .is_err()
        );
        let backend = Arc::new(MemoryBlobBackend::new("choice-query", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty root");
        let choices = ["first", "second"].map(|label| {
            ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                label.as_bytes(),
            ))
            .expect("choice id")
        });
        let mut choice_index = empty;
        for choice in choices {
            choice_index = map
                .insert(
                    choice_index.content_id(),
                    crate::repository::choice_index_order_key(choice),
                    choice.content_id(),
                )
                .expect("choice insert");
        }
        let graph = map
            .insert(
                empty.content_id(),
                crate::repository::choice_index_anchor_key(),
                choice_index.content_id(),
            )
            .expect("choice-index anchor");
        let roots = CampaignRoots {
            graph: graph.content_id(),
            exploration: empty.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"choice-query-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"choice-query-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("snapshot");
        let request = QueryCampaignChoicesRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            None,
            1,
        )
        .expect("request");
        let (_, index_proof) = map
            .get_with_proof(
                graph.content_id(),
                crate::repository::choice_index_anchor_key(),
            )
            .expect("index proof");
        let (page, page_proof) = map
            .scan_with_proof(choice_index.content_id(), None, 1)
            .expect("page proof");
        let entries = page
            .entries()
            .iter()
            .map(|(_, value)| {
                ChoiceOpportunityId::from_content_id(*value)
                    .map(CampaignChoiceEntry::new)
                    .expect("choice entry")
            })
            .collect::<Vec<_>>();
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.opportunity()));
        let response = QueryCampaignChoicesResponse::new(
            &request,
            snapshot_body,
            entries,
            next_after,
            index_proof,
            page_proof,
        )
        .expect("response");
        let decoded =
            QueryCampaignChoicesResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response");
        decoded.validate_for(&request).expect("verify response");
        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("3d04a1a5b7687ffd4398b162b8b14566e1c56a16b47446db3dc734ac1b318eee"),
                String::from("9b5d7589cad830b6f816c31d5a4c8e9edae7deea41703d4993ec337833e0172f"),
            ]
        );

        let mut forged_eof = decoded.clone();
        forged_eof.next_after = None;
        assert!(forged_eof.validate_for(&request).is_err());
        let mut substituted = decoded;
        substituted.entries[0] = CampaignChoiceEntry::new(
            ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"unrelated-choice",
            ))
            .expect("unrelated choice"),
        );
        assert!(substituted.validate_for(&request).is_err());
    }

    #[test]
    fn frontier_pages_authenticate_projection_bodies_and_exact_eof() {
        assert!(
            QueryCampaignFrontierRequest::new(
                CampaignPrincipal::new("operator:alice").expect("principal"),
                CampaignName::new("network-recovery").expect("campaign"),
                snapshot("frontier-limit"),
                None,
                MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS + 1,
            )
            .is_err()
        );
        let backend = Arc::new(MemoryBlobBackend::new("frontier-query", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty root");
        let projections = [
            ("first", ContinuationState::Ready),
            ("second", ContinuationState::Open),
        ]
        .map(|(label, state)| {
            let request = BranchRequestId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                label.as_bytes(),
            ))
            .expect("request id");
            ContinuationProjection::new(
                request,
                BranchPointId::from_hash(CampaignHash::derive(
                    "campaign-frontier-query-branch-point",
                    label.as_bytes(),
                )),
                state,
            )
        });
        let mut frontier_index = empty;
        for projection in projections {
            frontier_index = map
                .insert(
                    frontier_index.content_id(),
                    crate::repository::frontier_index_order_key(projection.request()),
                    projection.id().expect("projection id").content_id(),
                )
                .expect("frontier insert");
        }
        let exploration = map
            .insert(
                empty.content_id(),
                crate::repository::frontier_index_anchor_key(),
                frontier_index.content_id(),
            )
            .expect("frontier-index anchor");
        let roots = CampaignRoots {
            graph: empty.content_id(),
            exploration: exploration.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"frontier-query-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"frontier-query-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("snapshot");
        let request = QueryCampaignFrontierRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            None,
            1,
        )
        .expect("request");
        let (_, index_proof) = map
            .get_with_proof(
                exploration.content_id(),
                crate::repository::frontier_index_anchor_key(),
            )
            .expect("index proof");
        let (page, page_proof) = map
            .scan_with_proof(frontier_index.content_id(), None, 1)
            .expect("page proof");
        let entries = page
            .entries()
            .iter()
            .map(|(_, value)| {
                projections
                    .iter()
                    .copied()
                    .find(|projection| {
                        projection.id().expect("projection id").content_id() == *value
                    })
                    .expect("projection body")
            })
            .collect::<Vec<_>>();
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.request()));
        let response = QueryCampaignFrontierResponse::new(
            &request,
            snapshot_body,
            entries,
            next_after,
            index_proof,
            page_proof,
        )
        .expect("response");
        let decoded =
            QueryCampaignFrontierResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response");
        decoded.validate_for(&request).expect("verify response");
        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("483028d0eea2e19495841dd35e1d12e209c7f6ab06e37f659e5e1dcd98edbca4"),
                String::from("ff72a3caeb93adf388ca3bdd3a7a7fed45479a7b033ed3dfac0fdd4ed2485c26"),
            ]
        );

        let mut forged_eof = decoded.clone();
        forged_eof.next_after = None;
        assert!(forged_eof.validate_for(&request).is_err());
        let mut substituted = decoded;
        substituted.entries[0] = ContinuationProjection::new(
            substituted.entries[0].request(),
            substituted.entries[0].branch_point(),
            ContinuationState::Closed,
        );
        assert!(substituted.validate_for(&request).is_err());
    }

    #[test]
    fn frontier_object_reads_authenticate_exact_request_membership() {
        let backend = Arc::new(MemoryBlobBackend::new("frontier-object-query", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty root");
        let object = branch_request("frontier-object");
        let object_id = object.id().expect("request id");
        let projection =
            ContinuationProjection::new(object_id, object.branch_point(), ContinuationState::Ready);
        let frontier_index = map
            .insert(
                empty.content_id(),
                crate::repository::frontier_index_order_key(object_id),
                projection.id().expect("projection id").content_id(),
            )
            .expect("frontier insert");
        let exploration = map
            .insert(
                empty.content_id(),
                crate::repository::frontier_index_anchor_key(),
                frontier_index.content_id(),
            )
            .expect("frontier anchor");
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"frontier-object-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"frontier-object-policy",
            ))
            .expect("policy"),
            CampaignRoots {
                graph: empty.content_id(),
                exploration: exploration.content_id(),
                observations: empty.content_id(),
                corpus: empty.content_id(),
                coverage: empty.content_id(),
                findings: empty.content_id(),
                pins: empty.content_id(),
                accounting: empty.content_id(),
                coordination: empty.content_id(),
            },
        )
        .expect("snapshot");
        let request = GetCampaignFrontierObjectRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            object_id,
        )
        .expect("request");
        let (_, index_proof) = map
            .get_with_proof(
                exploration.content_id(),
                crate::repository::frontier_index_anchor_key(),
            )
            .expect("index proof");
        let (_, object_proof) = map
            .get_with_proof(
                frontier_index.content_id(),
                crate::repository::frontier_index_order_key(object_id),
            )
            .expect("object proof");
        let response = GetCampaignFrontierObjectResponse::new(
            &request,
            snapshot_body,
            projection,
            object,
            index_proof,
            object_proof,
        )
        .expect("response");
        let decoded =
            GetCampaignFrontierObjectResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response");
        decoded.validate_for(&request).expect("verify response");
        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("152336429f4924a4efe80b4125f12ef9f916cfe47447289517392e77d7163b71"),
                String::from("f8b78b4673f51beec04d43ffd8bb51e0562d3cebcc1a53cb66d4946a80856113"),
            ]
        );

        let mut forged_projection = decoded.clone();
        forged_projection.projection = ContinuationProjection::new(
            object_id,
            forged_projection.projection.branch_point(),
            ContinuationState::Closed,
        );
        assert!(forged_projection.validate_for(&request).is_err());
        let mut substituted = decoded;
        substituted.object = branch_request("substituted-frontier-object");
        assert!(substituted.validate_for(&request).is_err());
    }

    #[test]
    fn choice_object_reads_authenticate_exact_opportunity_dependencies() {
        let backend = Arc::new(MemoryBlobBackend::new("choice-object-query", u64::MAX));
        let map = MerkleMap::new(backend);
        let empty = map.empty().expect("empty root");
        let (declaration, domain, opportunity) = choice_objects();
        let opportunity_id = opportunity.id().expect("opportunity id");
        let graph = map
            .insert(
                empty.content_id(),
                crate::repository::authoritative_choice_key(opportunity_id),
                opportunity_id.content_id(),
            )
            .expect("opportunity membership");
        let roots = CampaignRoots {
            graph: graph.content_id(),
            exploration: empty.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        };
        let snapshot_body = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"choice-object-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"choice-object-policy",
            ))
            .expect("policy"),
            roots,
        )
        .expect("snapshot");
        let request = GetCampaignChoiceObjectRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot_body.id().expect("snapshot id"),
            opportunity_id,
            CampaignChoiceObjectKind::Declaration,
        )
        .expect("request");
        let mut unknown_kind = request.canonical_bytes();
        let kind = unknown_kind.last_mut().expect("choice object kind byte");
        *kind = 2;
        assert!(matches!(
            GetCampaignChoiceObjectRequest::from_canonical_bytes(&unknown_kind),
            Err(CampaignCodecError::UnknownTag {
                kind: "campaign-choice-object-kind",
                tag: 2,
            })
        ));
        let (_, proof) = map
            .get_with_proof(
                graph.content_id(),
                crate::repository::authoritative_choice_key(opportunity_id),
            )
            .expect("opportunity proof");
        let response = GetCampaignChoiceObjectResponse::new(
            &request,
            snapshot_body.clone(),
            opportunity.clone(),
            CampaignChoiceObject::Declaration(declaration),
            proof.clone(),
        )
        .expect("declaration response");
        let decoded =
            GetCampaignChoiceObjectResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response");
        decoded.validate_for(&request).expect("verify response");

        let domain_request = GetCampaignChoiceObjectRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            request.snapshot(),
            opportunity_id,
            CampaignChoiceObjectKind::Domain,
        )
        .expect("domain request");
        let domain_response = GetCampaignChoiceObjectResponse::new(
            &domain_request,
            snapshot_body,
            opportunity,
            CampaignChoiceObject::Domain(domain),
            proof,
        )
        .expect("domain response");
        domain_response
            .validate_for(&domain_request)
            .expect("verify domain response");
        assert!(domain_response.validate_for(&request).is_err());
        let mut substituted = domain_response;
        substituted.object = CampaignChoiceObject::Domain(ChoiceDomain::Boolean(
            BooleanDomain::new(2).expect("unrelated domain"),
        ));
        assert!(substituted.validate_for(&domain_request).is_err());

        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("b3a99f45d1c4d84be0175b9f4b2408877d93a6ea4796466e48350ae035d6da38"),
                String::from("74abc6ab91c7dec2cb1cde83dad1afc81e1707bf9f0717ebab4b008792a92286"),
            ]
        );
    }
}
