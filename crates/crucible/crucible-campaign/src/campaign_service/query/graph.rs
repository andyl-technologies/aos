//! Proof-bearing reads over one authenticated campaign graph root.

use super::*;

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
    pub(super) entries: Vec<CampaignGraphEntry>,
    pub(super) next_after: Option<CampaignHash>,
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
    pub(super) object: ObjectEnvelope,
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
