//! Explicit discovery messages for the user-facing campaign service.

use super::*;
use crate::{CampaignDiscoveryResult, DiscoveryRequest};

/// Strict principal-bound request for one idempotent discovery admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitCampaignDiscoveryRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    command: DiscoveryRequest,
}

impl SubmitCampaignDiscoveryRequest {
    /// Builds one bounded principal-bound discovery request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the canonical request exceeds the
    /// campaign-service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        command: DiscoveryRequest,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            command,
        };
        ensure_message_size(&request, "submit-campaign-discovery-request-encoded-bytes")?;
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

    /// Returns the exact semantic discovery command.
    #[must_use]
    pub const fn command(&self) -> &DiscoveryRequest {
        &self.command
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("submit-campaign-discovery", self)
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
        decode_message(bytes, "submit-campaign-discovery-request-encoded-bytes")
    }
}

impl Canonical for SubmitCampaignDiscoveryRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.command.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            DiscoveryRequest::decode(decoder)?,
        )
    }
}

/// Request-bound result of one accepted explicit discovery command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitCampaignDiscoveryResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    prior_snapshot: CampaignSnapshotId,
    new_snapshot: CampaignSnapshotId,
    attempt: crate::AttemptId,
    admission: crate::AttemptAdmissionId,
    replayed: bool,
}

impl SubmitCampaignDiscoveryResponse {
    /// Builds a response from one exact repository result.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the result's parent differs from the
    /// request precondition or the canonical response exceeds its bound.
    pub fn new(
        request: &SubmitCampaignDiscoveryRequest,
        result: CampaignDiscoveryResult,
    ) -> Result<Self, CampaignCodecError> {
        if result.prior_snapshot != request.command.expected_snapshot {
            return Err(CampaignCodecError::InvalidValue {
                reason: "discovery response prior snapshot mismatch",
            });
        }
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            prior_snapshot: result.prior_snapshot,
            new_snapshot: result.new_snapshot,
            attempt: result.attempt,
            admission: result.admission,
            replayed: result.replayed,
        };
        ensure_message_size(
            &response,
            "submit-campaign-discovery-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the snapshot named by the discovery precondition.
    #[must_use]
    pub const fn prior_snapshot(&self) -> CampaignSnapshotId {
        self.prior_snapshot
    }

    /// Returns the snapshot first produced by the discovery command.
    #[must_use]
    pub const fn new_snapshot(&self) -> CampaignSnapshotId {
        self.new_snapshot
    }

    /// Returns the admitted semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> crate::AttemptId {
        self.attempt
    }

    /// Returns the admission record that owns the execution basis.
    #[must_use]
    pub const fn admission(&self) -> crate::AttemptAdmissionId {
        self.admission
    }

    /// Returns whether the service observed an idempotent replay.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Validates exact request and precondition binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or names another prior snapshot.
    pub fn validate_for(
        &self,
        request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.prior_snapshot == request.command.expected_snapshot {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "discovery response prior snapshot mismatch",
            })
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
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "submit-campaign-discovery-response-encoded-bytes")
    }
}

impl Canonical for SubmitCampaignDiscoveryResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.prior_snapshot.encode(encoder);
        self.new_snapshot.encode(encoder);
        self.attempt.encode(encoder);
        self.admission.encode(encoder);
        self.replayed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            prior_snapshot: CampaignSnapshotId::decode(decoder)?,
            new_snapshot: CampaignSnapshotId::decode(decoder)?,
            attempt: crate::AttemptId::decode(decoder)?,
            admission: crate::AttemptAdmissionId::decode(decoder)?,
            replayed: bool::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "submit-campaign-discovery-response-encoded-bytes",
        )?;
        Ok(response)
    }
}
