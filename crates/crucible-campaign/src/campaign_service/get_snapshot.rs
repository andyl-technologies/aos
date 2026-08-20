//! Strict request-bound campaign snapshot lookup messages.

use super::*;

/// Strict request for one exact snapshot in a named campaign history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignSnapshotRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
}

impl GetCampaignSnapshotRequest {
    /// Builds one exact named-history snapshot request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
        };
        ensure_message_size(&request, "get-campaign-snapshot-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name whose history is queried.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact requested snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-snapshot", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded snapshot request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-snapshot-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignSnapshotRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
        )
    }
}

/// Request-bound canonical body of one snapshot in a named campaign history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignSnapshotResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshotId,
    snapshot_body: CampaignSnapshot,
}

impl GetCampaignSnapshotResponse {
    /// Builds one response bound to an exact historical snapshot request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the body identity differs from the
    /// requested snapshot or the encoded response exceeds the service bound.
    pub fn new(
        request: &GetCampaignSnapshotRequest,
        snapshot_body: CampaignSnapshot,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot: request.snapshot(),
            snapshot_body,
        };
        response.validate_for(request)?;
        ensure_message_size(&response, "get-campaign-snapshot-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the exact snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the authenticated canonical snapshot body.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Validates exact request and snapshot-body binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or the body does not reconstruct the requested snapshot ID.
    pub fn validate_for(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.snapshot != request.snapshot() || self.snapshot_body.id()? != request.snapshot() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign snapshot response identity mismatch",
            });
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded snapshot response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-snapshot-response-encoded-bytes")
    }
}

impl Canonical for GetCampaignSnapshotResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.snapshot_body.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
        };
        ensure_message_size(&response, "get-campaign-snapshot-response-encoded-bytes")?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

    fn snapshot_body() -> CampaignSnapshot {
        let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"snapshot-root");
        CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"snapshot-lineage",
            ))
            .expect("lineage"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"snapshot-policy",
            ))
            .expect("policy"),
            crate::CampaignRoots {
                graph: root,
                exploration: root,
                observations: root,
                corpus: root,
                coverage: root,
                findings: root,
                pins: root,
                accounting: root,
                coordination: root,
            },
        )
        .expect("snapshot body")
    }

    #[test]
    fn snapshot_messages_are_canonical_and_exact_request_bound() {
        let body = snapshot_body();
        let request = GetCampaignSnapshotRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            body.id().expect("snapshot id"),
        )
        .expect("request");
        let response = GetCampaignSnapshotResponse::new(&request, body.clone()).expect("response");

        assert_eq!(
            GetCampaignSnapshotRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        assert_eq!(
            GetCampaignSnapshotResponse::from_canonical_bytes(&response.canonical_bytes())
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
                String::from("75e8233c5ff25c4022d1dcbd00fcf5de9c4a41e45d095540e497212e59615a9a"),
                String::from("bdbe07303ae7cb986ccaf9da6ba2a71b23861139de30c100fa8c70e501e0afe0"),
            ]
        );

        let other_request = GetCampaignSnapshotRequest::new(
            request.principal().clone(),
            CampaignName::new("other-campaign").expect("other campaign"),
            request.snapshot(),
        )
        .expect("other request");
        assert!(response.validate_for(&other_request).is_err());

        let mut forged = response;
        forged.snapshot_body = CampaignSnapshot::genesis(
            body.lineage(),
            body.active_policy(),
            crate::CampaignRoots {
                graph: ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"other-root"),
                ..body.roots()
            },
        )
        .expect("forged body");
        assert!(forged.validate_for(&request).is_err());
    }
}
