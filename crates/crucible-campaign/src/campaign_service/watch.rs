//! Strict resumable watch messages for the user-facing campaign service.

use super::*;

/// Strict request for the latest coalesced campaign head after a snapshot cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchCampaignRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    after: Option<CampaignSnapshotId>,
}

impl WatchCampaignRequest {
    /// Builds one bounded watch request.
    ///
    /// `after` is an advisory cursor. A stale, unknown, or coalesced cursor
    /// never hides state: the service returns the current authenticated head.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the canonical message exceeds the
    /// service bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        after: Option<CampaignSnapshotId>,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            after,
        };
        ensure_message_size(&request, "watch-campaign-request-encoded-bytes")?;
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

    /// Returns the last snapshot observed by the caller, if any.
    #[must_use]
    pub const fn after(&self) -> Option<CampaignSnapshotId> {
        self.after
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("watch-campaign", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded watch request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "watch-campaign-request-encoded-bytes")
    }
}

impl Canonical for WatchCampaignRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.after.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            Option::<CampaignSnapshotId>::decode(decoder)?,
        )
    }
}

/// Request-bound latest campaign head and resumable coalesced cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchCampaignResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshotId,
    lineage: CampaignLineageId,
    policy: CampaignPolicyId,
    state: CampaignState,
    advanced: bool,
}

impl WatchCampaignResponse {
    /// Builds a response bound to one exact watch request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded response exceeds the
    /// campaign-service bound.
    pub fn new(
        request: &WatchCampaignRequest,
        snapshot: CampaignSnapshotId,
        lineage: CampaignLineageId,
        policy: CampaignPolicyId,
        state: CampaignState,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot,
            lineage,
            policy,
            state,
            advanced: request.after() != Some(snapshot),
        };
        ensure_message_size(&response, "watch-campaign-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authoritative current snapshot and next watch cursor.
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

    /// Returns whether the current head differs from the supplied cursor.
    #[must_use]
    pub const fn advanced(&self) -> bool {
        self.advanced
    }

    /// Validates exact request and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or reports an inconsistent cursor relation.
    pub fn validate_for(&self, request: &WatchCampaignRequest) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.advanced != (request.after() != Some(self.snapshot)) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign watch response cursor relation mismatch",
            });
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded watch response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "watch-campaign-response-encoded-bytes")
    }
}

impl Canonical for WatchCampaignResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.lineage.encode(encoder);
        self.policy.encode(encoder);
        self.state.encode(encoder);
        self.advanced.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            policy: CampaignPolicyId::decode(decoder)?,
            state: CampaignState::decode(decoder)?,
            advanced: bool::decode(decoder)?,
        };
        ensure_message_size(&response, "watch-campaign-response-encoded-bytes")?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

    fn snapshot(label: &str) -> CampaignSnapshotId {
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            2,
            label.as_bytes(),
        ))
        .expect("snapshot")
    }

    #[test]
    fn watch_messages_are_canonical_request_and_cursor_bound() {
        let request = WatchCampaignRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            Some(snapshot("prior")),
        )
        .expect("watch request");
        assert_eq!(
            WatchCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        let response = WatchCampaignResponse::new(
            &request,
            snapshot("current"),
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"policy",
            ))
            .expect("policy"),
            CampaignState::Running,
        )
        .expect("watch response");
        assert!(response.advanced());
        response.validate_for(&request).expect("response binding");
        assert_eq!(
            WatchCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
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
                String::from("e12f1876660476d8dd6f4fa59b18ffa3d9f1ddcdbb50e8b87443098a7e43d3e7"),
                String::from("3ea9397acced854c6193c7fc9de59bc8e559e8a30c84fab1aa5ae7b77ec3843c"),
            ]
        );

        let mut wrong_relation_bytes = response.canonical_bytes();
        let relation = wrong_relation_bytes
            .last_mut()
            .expect("response contains advanced flag");
        *relation = 0;
        let wrong_relation = WatchCampaignResponse::from_canonical_bytes(&wrong_relation_bytes)
            .expect("decode structurally valid wrong relation");
        assert!(wrong_relation.validate_for(&request).is_err());

        let current_request = WatchCampaignRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            Some(response.snapshot()),
        )
        .expect("current request");
        let unchanged = WatchCampaignResponse::new(
            &current_request,
            response.snapshot(),
            response.lineage(),
            response.policy(),
            response.state(),
        )
        .expect("unchanged response");
        assert!(!unchanged.advanced());
        assert!(unchanged.validate_for(&request).is_err());
        unchanged
            .validate_for(&current_request)
            .expect("unchanged cursor binding");
    }
}
