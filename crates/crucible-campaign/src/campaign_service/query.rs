//! Strict snapshot-bound campaign graph, frontier, object, and choice queries.

use crucible_cas::content_store::ContentId;

use super::*;
use crate::{
    Attempt, AttemptAdmission, AttemptAdmissionRole, AttemptId, AttemptStart, BranchPath,
    BranchRequestId, ChoiceDomain, ChoiceOpportunity, ContinuationProjection, Finding, FindingId,
    Observation, PlannerStep, Proposal, ReproductionArtifact, SelectableDeclaration, Selection,
    SelectionOrigin,
};

const EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION: u32 = 2;

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
    planner_step: Option<PlannerStep>,
    observation: Option<Observation>,
    attempt_proof: MerkleMapLookupProof,
    admission_proof: MerkleMapLookupProof,
    proposal_proof: Option<MerkleMapLookupProof>,
    planner_step_proof: Option<MerkleMapLookupProof>,
    observation_proof: MerkleMapLookupProof,
}

impl ExplainCampaignAttemptResponse {
    /// Builds one authenticated attempt-explanation response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when any snapshot, accounting,
    /// exploration, coordination, path, selection, proposal, planner-step,
    /// completion, or encoded-size invariant is invalid.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ExplainCampaignAttemptRequest,
        snapshot_body: CampaignSnapshot,
        attempt: Attempt,
        admission: AttemptAdmission,
        path: BranchPath,
        selection: Option<Selection>,
        proposal: Option<Proposal>,
        planner_step: Option<PlannerStep>,
        observation: Option<Observation>,
        attempt_proof: MerkleMapLookupProof,
        admission_proof: MerkleMapLookupProof,
        proposal_proof: Option<MerkleMapLookupProof>,
        planner_step_proof: Option<MerkleMapLookupProof>,
        observation_proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            attempt,
            admission,
            path,
            selection,
            proposal,
            planner_step,
            observation,
            attempt_proof,
            admission_proof,
            proposal_proof,
            planner_step_proof,
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

    /// Returns the coordinator-accepted planner step that selected the proposal.
    ///
    /// Operator and exhaustive proposals have no planner step. Legacy
    /// version-one responses also omit this evidence.
    #[must_use]
    pub const fn planner_step(&self) -> Option<&PlannerStep> {
        self.planner_step.as_ref()
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
        self.validate_planner_evidence()?;

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

    fn validate_planner_evidence(&self) -> Result<(), CampaignCodecError> {
        if self.schema_version == 1 {
            if self.planner_step.is_some() || self.planner_step_proof.is_some() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "legacy campaign attempt explanation carries planner evidence",
                });
            }
            return Ok(());
        }

        let invocation = self
            .proposal
            .as_ref()
            .and_then(Proposal::planner_invocation);
        match (invocation, &self.planner_step, &self.planner_step_proof) {
            (None, None, None) => Ok(()),
            (Some(invocation), Some(step), Some(proof)) => {
                let proposal = self
                    .proposal
                    .as_ref()
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "campaign planner evidence has no proposal",
                    })?;
                let proposal_id = proposal.id()?;
                let step_id = step.id()?;
                verify_exact_lookup(
                    self.snapshot_body.roots().coordination,
                    crate::repository::planner_invocation_result_key(invocation),
                    proof,
                    Some(step_id.content_id()),
                    "campaign planner-step proof is invalid",
                )?;
                if step.invocation() != invocation
                    || step.policy() != proposal.policy()
                    || step.input_view() != proposal.guidance_basis()
                    || step.selected_branch_point() != Some(proposal.branch_point())
                    || step.selected_source() != Some(proposal.request())
                    || !step.issued_proposals().contains(&proposal_id)
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "campaign planner evidence disagrees with selected proposal",
                    });
                }
                Ok(())
            }
            _ => Err(CampaignCodecError::InvalidValue {
                reason: "campaign planner evidence presence disagrees with proposal authority",
            }),
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
        if self.schema_version >= EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION {
            self.planner_step.encode(encoder);
        }
        self.observation.encode(encoder);
        self.attempt_proof.encode(encoder);
        self.admission_proof.encode(encoder);
        self.proposal_proof.encode(encoder);
        if self.schema_version >= EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION {
            self.planner_step_proof.encode(encoder);
        }
        self.observation_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != 1 && schema_version != EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign attempt explanation response version",
            });
        }
        let response = Self {
            schema_version,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            attempt: Attempt::decode(decoder)?,
            admission: AttemptAdmission::decode(decoder)?,
            path: BranchPath::decode(decoder)?,
            selection: Option::decode(decoder)?,
            proposal: Option::decode(decoder)?,
            planner_step: if schema_version >= EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION {
                Option::decode(decoder)?
            } else {
                None
            },
            observation: Option::decode(decoder)?,
            attempt_proof: MerkleMapLookupProof::decode(decoder)?,
            admission_proof: MerkleMapLookupProof::decode(decoder)?,
            proposal_proof: Option::decode(decoder)?,
            planner_step_proof: if schema_version
                >= EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_SCHEMA_VERSION
            {
                Option::decode(decoder)?
            } else {
                None
            },
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

    /// Returns the exact named-history snapshot that anchors the opportunity.
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

mod graph;
pub use graph::{
    CampaignGraphEntry, GetCampaignGraphObjectRequest, GetCampaignGraphObjectResponse,
    QueryCampaignGraphRequest, QueryCampaignGraphResponse,
};

#[cfg(test)]
mod tests;
