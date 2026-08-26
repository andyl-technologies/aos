//! Bounded authenticated campaign-catalog request and response messages.

use super::*;

/// Maximum campaign heads returned by one catalog page.
pub const MAX_CAMPAIGN_LIST_PAGE_ITEMS: u32 = 256;

/// Strict request for one ordered page of authenticated campaign heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListCampaignsRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    after: Option<CampaignName>,
    limit: u32,
}

impl ListCampaignsRequest {
    /// Builds one bounded exclusive-cursor campaign-catalog request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `limit` is zero, exceeds the page
    /// ceiling, or the encoded message exceeds the service-message bound.
    pub fn new(
        principal: CampaignPrincipal,
        after: Option<CampaignName>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_LIST_PAGE_ITEMS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign list page size is invalid",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            after,
            limit,
        };
        ensure_message_size(&request, "list-campaigns-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the exclusive campaign-name cursor.
    #[must_use]
    pub const fn after(&self) -> Option<&CampaignName> {
        self.after.as_ref()
    }

    /// Returns the maximum number of campaign heads requested.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("list-campaigns", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "list-campaigns-request-encoded-bytes")
    }
}

impl Canonical for ListCampaignsRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            Option::<CampaignName>::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// One authenticated current campaign description in catalog order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignListEntry {
    name: CampaignName,
    snapshot: CampaignSnapshotId,
    lineage: CampaignLineageId,
    policy: CampaignPolicyId,
    state: CampaignState,
}

impl CampaignListEntry {
    /// Builds one authenticated campaign-catalog entry.
    #[must_use]
    pub const fn new(
        name: CampaignName,
        snapshot: CampaignSnapshotId,
        lineage: CampaignLineageId,
        policy: CampaignPolicyId,
        state: CampaignState,
    ) -> Self {
        Self {
            name,
            snapshot,
            lineage,
            policy,
            state,
        }
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn name(&self) -> &CampaignName {
        &self.name
    }

    /// Returns the authenticated current snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the current snapshot's immutable lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the policy active for future work.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the projected durable lifecycle state.
    #[must_use]
    pub const fn state(&self) -> CampaignState {
        self.state
    }
}

impl Canonical for CampaignListEntry {
    fn encode(&self, encoder: &mut Encoder) {
        self.name.encode(encoder);
        self.snapshot.encode(encoder);
        self.lineage.encode(encoder);
        self.policy.encode(encoder);
        self.state.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            name: CampaignName::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            policy: CampaignPolicyId::decode(decoder)?,
            state: CampaignState::decode(decoder)?,
        })
    }
}

/// Request-bound ordered page of authenticated current campaign descriptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListCampaignsResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    entries: Vec<CampaignListEntry>,
    next_after: Option<CampaignName>,
    visited_refs: u64,
}

impl ListCampaignsResponse {
    /// Builds and validates one exact catalog response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when entry order, cursor, page bounds,
    /// ref-work accounting, or encoded-size constraints are violated.
    pub fn new(
        request: &ListCampaignsRequest,
        entries: Vec<CampaignListEntry>,
        next_after: Option<CampaignName>,
        visited_refs: u64,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            entries,
            next_after,
            visited_refs,
        };
        response.validate_for(request)?;
        ensure_message_size(&response, "list-campaigns-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns campaign descriptions in strict canonical name order.
    #[must_use]
    pub fn entries(&self) -> &[CampaignListEntry] {
        &self.entries
    }

    /// Returns the exclusive campaign-name cursor for another page.
    #[must_use]
    pub const fn next_after(&self) -> Option<&CampaignName> {
        self.next_after.as_ref()
    }

    /// Returns authoritative reference entries inspected for this page.
    #[must_use]
    pub const fn visited_refs(&self) -> u64 {
        self.visited_refs
    }

    /// Validates exact request, order, cursor, and bounded-work binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or violates the catalog page contract.
    pub fn validate_for(&self, request: &ListCampaignsRequest) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.entries.len() > request.limit as usize
            || self.entries.len() > MAX_CAMPAIGN_LIST_PAGE_ITEMS as usize
            || self.visited_refs > crucible_cas::content_store::MAX_REF_SCAN_VISITS
            || self.visited_refs < self.entries.len() as u64
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign list response bounds are invalid",
            });
        }
        if self
            .entries
            .windows(2)
            .any(|entries| entries[0].name.as_str() >= entries[1].name.as_str())
            || self.entries.first().is_some_and(|entry| {
                request
                    .after
                    .as_ref()
                    .is_some_and(|after| entry.name.as_str() <= after.as_str())
            })
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign list response order is invalid",
            });
        }
        match (&self.next_after, self.entries.last()) {
            (Some(next), Some(last)) if next == &last.name => Ok(()),
            (None, _) => Ok(()),
            _ => Err(CampaignCodecError::InvalidValue {
                reason: "campaign list response cursor is invalid",
            }),
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Exact request validation remains
    /// required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "list-campaigns-response-encoded-bytes")
    }
}

impl Canonical for ListCampaignsResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.entries.encode(encoder);
        self.next_after.encode(encoder);
        self.visited_refs.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            entries: decoder.sequence_bounded(
                MAX_CAMPAIGN_LIST_PAGE_ITEMS as usize,
                "campaign-list-response-entries",
                CampaignListEntry::decode,
            )?,
            next_after: Option::<CampaignName>::decode(decoder)?,
            visited_refs: u64::decode(decoder)?,
        };
        ensure_message_size(&response, "list-campaigns-response-encoded-bytes")?;
        Ok(response)
    }
}
