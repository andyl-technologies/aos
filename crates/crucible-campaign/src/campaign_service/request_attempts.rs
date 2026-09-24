//! Proof-bearing pages of attempts admitted for one branch request.

use super::*;
use crate::{
    AttemptAdmission, AttemptAdmissionRole, AttemptId, BranchRequestId, CampaignBudgetLedger,
};

/// Maximum execution-basis admissions returned in one request-local page.
pub const MAX_CAMPAIGN_REQUEST_ATTEMPT_PAGE_ITEMS: u32 = 8;

/// Snapshot-bound request for one page of a branch request's admitted attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignRequestAttemptsRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    branch_request: BranchRequestId,
    after: Option<AttemptId>,
    limit: u32,
}

impl QueryCampaignRequestAttemptsRequest {
    /// Builds a bounded request-local attempt query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty or oversized page limit or
    /// a request exceeding the service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        branch_request: BranchRequestId,
        after: Option<AttemptId>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_REQUEST_ATTEMPT_PAGE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-request-attempt-page-items",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            branch_request,
            after,
            limit,
        };
        ensure_message_size(&request, "query-campaign-request-attempts-request-bytes")?;
        Ok(request)
    }

    /// Returns the operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact current snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the branch request whose spending index is queried.
    #[must_use]
    pub const fn branch_request(&self) -> BranchRequestId {
        self.branch_request
    }

    /// Returns the exclusive attempt cursor.
    #[must_use]
    pub const fn after(&self) -> Option<AttemptId> {
        self.after
    }

    /// Returns the maximum admissions in this page.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns a digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-request-attempts", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, or
    /// unsupported input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-request-attempts-request-bytes")
    }
}

impl Canonical for QueryCampaignRequestAttemptsRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.branch_request.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            BranchRequestId::decode(decoder)?,
            Option::<AttemptId>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Authenticated request-local page of execution-basis admissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignRequestAttemptsResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    budget_ledger: CampaignBudgetLedger,
    entries: Vec<AttemptAdmission>,
    next_after: Option<AttemptId>,
    index_proof: MerkleMapLookupProof,
    page_proof: MerkleMapPageProof,
}

impl QueryCampaignRequestAttemptsResponse {
    /// Builds a response bound to the snapshot's request-spending index.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the budget ledger, request index,
    /// page proof, entry identities, cursor, or message bound is invalid.
    pub fn new(
        request: &QueryCampaignRequestAttemptsRequest,
        snapshot_body: CampaignSnapshot,
        budget_ledger: CampaignBudgetLedger,
        entries: Vec<AttemptAdmission>,
        next_after: Option<AttemptId>,
        index_proof: MerkleMapLookupProof,
        page_proof: MerkleMapPageProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            budget_ledger,
            entries,
            next_after,
            index_proof,
            page_proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(&response, "query-campaign-request-attempts-response-bytes")?;
        Ok(response)
    }

    /// Returns the exact admitted attempts in this page.
    #[must_use]
    pub fn entries(&self) -> &[AttemptAdmission] {
        &self.entries
    }

    /// Returns the exclusive next-page cursor, if the page is not complete.
    #[must_use]
    pub const fn next_after(&self) -> Option<AttemptId> {
        self.next_after
    }

    /// Validates every request, snapshot, index, entry, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response differs from its
    /// authenticated Merkle proofs or the exact request.
    pub fn validate_for(
        &self,
        request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict bounded response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, or
    /// unsupported input. Call [`Self::validate_for`] before using entries.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-request-attempts-response-bytes")
    }

    fn validate_body_for(
        &self,
        request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<(), CampaignCodecError> {
        let limit =
            usize::try_from(request.limit()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "campaign-request-attempt-page-items",
            })?;
        if self.snapshot_body.id()? != request.snapshot()
            || self.budget_ledger.id()? != self.snapshot_body.budget_ledger()
            || self.entries.len() > limit
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "request-attempt page snapshot, ledger, or limit mismatch",
            });
        }
        let index_root = MerkleMap::verify_lookup_proof(
            self.budget_ledger.request_spending(),
            crate::repository::request_spending_key(request.branch_request()),
            &self.index_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "request-attempt index proof is invalid",
        })?
        .unwrap_or(MerkleMap::empty_content_id().map_err(|_| {
            CampaignCodecError::InvalidValue {
                reason: "request-attempt empty index identity is invalid",
            }
        })?);
        let verified = MerkleMap::verify_scan_proof(
            index_root,
            request.after().map(crate::repository::request_attempt_key),
            limit,
            &self.page_proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "request-attempt page proof is invalid",
        })?;
        if verified.entries().len() != self.entries.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "request-attempt page length differs from its proof",
            });
        }
        let verified_entries = verified
            .entries()
            .iter()
            .zip(&self.entries)
            .map(|((key, value), admission)| {
                if !matches!(
                    admission.role(),
                    AttemptAdmissionRole::ExecutionBasis { .. }
                ) || *key != crate::repository::request_attempt_key(admission.attempt())
                    || *value != admission.id()?.content_id()
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "request-attempt entry differs from its authenticated index",
                    });
                }
                Ok(*admission)
            })
            .collect::<Result<Vec<_>, CampaignCodecError>>()?;
        let verified_next = verified
            .next_after()
            .map(|_| {
                verified_entries
                    .last()
                    .map(|admission| admission.attempt())
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "request-attempt page has cursor without entries",
                    })
            })
            .transpose()?;
        if self.entries != verified_entries || self.next_after != verified_next {
            return Err(CampaignCodecError::InvalidValue {
                reason: "request-attempt page or cursor differs from its proof",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignRequestAttemptsResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.budget_ledger.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.index_proof.encode(encoder);
        self.page_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Ok(Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            budget_ledger: CampaignBudgetLedger::decode(decoder)?,
            entries: decoder.sequence_bounded(
                MAX_CAMPAIGN_REQUEST_ATTEMPT_PAGE_ITEMS as usize,
                "campaign-request-attempt-response-entries",
                AttemptAdmission::decode,
            )?,
            next_after: Option::<AttemptId>::decode(decoder)?,
            index_proof: MerkleMapLookupProof::decode(decoder)?,
            page_proof: MerkleMapPageProof::decode(decoder)?,
        })
    }
}
