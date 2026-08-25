//! Strict derivation messages for the user-facing campaign service.

use super::*;
use crate::{CampaignDerivationResult, CampaignPolicy};

/// Strict request for one atomic name-based campaign derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeriveCampaignRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    source_campaign: CampaignName,
    source_snapshot: CampaignSnapshotId,
    target_campaign: CampaignName,
    policy: Option<CampaignPolicy>,
}

impl DeriveCampaignRequest {
    /// Builds one bounded derivation request.
    ///
    /// A supplied policy is activated only for the new ref and must reference
    /// an already imported transitive generator closure. Omitting it preserves
    /// the policy active at the source snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when source and target names are equal or
    /// the canonical message exceeds the service bound.
    pub fn new(
        principal: CampaignPrincipal,
        source_campaign: CampaignName,
        source_snapshot: CampaignSnapshotId,
        target_campaign: CampaignName,
        policy: Option<CampaignPolicy>,
    ) -> Result<Self, CampaignCodecError> {
        if source_campaign == target_campaign {
            return Err(CampaignCodecError::InvalidValue {
                reason: "derived campaign name must differ from its source",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            source_campaign,
            source_snapshot,
            target_campaign,
            policy,
        };
        ensure_message_size(&request, "derive-campaign-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the named source campaign.
    #[must_use]
    pub const fn source_campaign(&self) -> &CampaignName {
        &self.source_campaign
    }

    /// Returns the exact authenticated source snapshot.
    #[must_use]
    pub const fn source_snapshot(&self) -> CampaignSnapshotId {
        self.source_snapshot
    }

    /// Returns the new campaign name.
    #[must_use]
    pub const fn target_campaign(&self) -> &CampaignName {
        &self.target_campaign
    }

    /// Returns the optional policy to activate atomically for the new ref.
    #[must_use]
    pub const fn policy(&self) -> Option<&CampaignPolicy> {
        self.policy.as_ref()
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("derive-campaign", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded derivation request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, semantically invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "derive-campaign-request-encoded-bytes")
    }
}

impl Canonical for DeriveCampaignRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.source_campaign.encode(encoder);
        self.source_snapshot.encode(encoder);
        self.target_campaign.encode(encoder);
        self.policy.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            CampaignName::decode(decoder)?,
            Option::<CampaignPolicy>::decode(decoder)?,
        )
    }
}

/// Strict response for a newly derived or exactly replayed campaign ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeriveCampaignResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    source_snapshot: CampaignSnapshotId,
    new_snapshot: CampaignSnapshotId,
    active_policy: CampaignPolicyId,
    replayed: bool,
}

impl DeriveCampaignResponse {
    /// Builds a response bound to one exact derivation request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the repository result disagrees
    /// with the request or the encoded message exceeds its bound.
    pub fn new(
        request: &DeriveCampaignRequest,
        result: CampaignDerivationResult,
    ) -> Result<Self, CampaignCodecError> {
        if result.source_snapshot != request.source_snapshot {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign derivation response source mismatch",
            });
        }
        if let Some(policy) = request.policy()
            && result.active_policy != policy.id()?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign derivation response policy mismatch",
            });
        }
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            source_snapshot: result.source_snapshot,
            new_snapshot: result.new_snapshot,
            active_policy: result.active_policy,
            replayed: result.replayed,
        };
        ensure_message_size(&response, "derive-campaign-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the exact source snapshot.
    #[must_use]
    pub const fn source_snapshot(&self) -> CampaignSnapshotId {
        self.source_snapshot
    }

    /// Returns the first snapshot owned by the derived ref.
    #[must_use]
    pub const fn new_snapshot(&self) -> CampaignSnapshotId {
        self.new_snapshot
    }

    /// Returns the policy active at the derived snapshot.
    #[must_use]
    pub const fn active_policy(&self) -> CampaignPolicyId {
        self.active_policy
    }

    /// Returns whether this response replayed an existing derivation.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Validates exact request and semantic-basis binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request, source snapshot, or supplied policy.
    pub fn validate_for(&self, request: &DeriveCampaignRequest) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.source_snapshot != request.source_snapshot {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign derivation response source mismatch",
            });
        }
        if let Some(policy) = request.policy()
            && self.active_policy != policy.id()?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign derivation response policy mismatch",
            });
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded derivation response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "derive-campaign-response-encoded-bytes")
    }
}

impl Canonical for DeriveCampaignResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.source_snapshot.encode(encoder);
        self.new_snapshot.encode(encoder);
        self.active_policy.encode(encoder);
        self.replayed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            source_snapshot: CampaignSnapshotId::decode(decoder)?,
            new_snapshot: CampaignSnapshotId::decode(decoder)?,
            active_policy: CampaignPolicyId::decode(decoder)?,
            replayed: bool::decode(decoder)?,
        };
        ensure_message_size(&response, "derive-campaign-response-encoded-bytes")?;
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

    fn policy(label: &str) -> CampaignPolicyId {
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            label.as_bytes(),
        ))
        .expect("policy")
    }

    fn derive_request(target: &str) -> DeriveCampaignRequest {
        DeriveCampaignRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("source"),
            snapshot("source-snapshot"),
            CampaignName::new(target).expect("target"),
            None,
        )
        .expect("request")
    }

    #[test]
    fn derivation_messages_are_canonical_and_request_bound() {
        let request = derive_request("network-recovery-derived");
        assert_eq!(
            DeriveCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        let response = DeriveCampaignResponse::new(
            &request,
            CampaignDerivationResult {
                source_snapshot: request.source_snapshot(),
                new_snapshot: snapshot("derived-snapshot"),
                active_policy: policy("active-policy"),
                replayed: false,
            },
        )
        .expect("response");
        assert_eq!(
            DeriveCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );
        response.validate_for(&request).expect("request binding");
        assert!(
            response
                .validate_for(&derive_request("other-derived"))
                .is_err()
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
                String::from("a06941ed5569c83a6bde638b814c1b449feef68381c5e0db4ca47ad553e298e2"),
                String::from("00aa874cd88c2551e833fa214ac7f525a933c5a26ff2bfcbeca2bd16f9a422a1"),
            ]
        );
    }
}
