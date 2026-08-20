//! Strict creation messages for the user-facing campaign service.

use super::*;
use crate::{CampaignLineage, CampaignPolicy};

/// Maximum generator records reachable from one imported creation policy.
pub const MAX_CREATE_CAMPAIGN_GENERATORS: usize = 4_096;
/// Maximum aggregate canonical generator bytes reachable during creation.
pub const MAX_CREATE_CAMPAIGN_GENERATOR_BYTES: usize = 128 * 1024 * 1024;

/// Strict request for one idempotent named campaign creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateCampaignRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    lineage: CampaignLineage,
    policy: CampaignPolicy,
}

impl CreateCampaignRequest {
    /// Builds one complete bounded creation request.
    ///
    /// The lineage's large scenario/genesis artifacts and the policy's exact
    /// transitive generator closure travel through a verifier-backed immutable
    /// content-import capability and must already exist by ID.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a lineage/policy scenario mismatch,
    /// or an oversized canonical message.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        lineage: CampaignLineage,
        policy: CampaignPolicy,
    ) -> Result<Self, CampaignCodecError> {
        if lineage.scenario() != policy.scenario() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign creation lineage and policy scenarios differ",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            lineage,
            policy,
        };
        ensure_message_size(&request, "create-campaign-request-encoded-bytes")?;
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

    /// Returns the complete lineage value.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }

    /// Returns the initial policy value.
    #[must_use]
    pub const fn policy(&self) -> &CampaignPolicy {
        &self.policy
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("create-campaign", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded creation request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, semantically invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "create-campaign-request-encoded-bytes")
    }
}

impl Canonical for CreateCampaignRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.lineage.encode(encoder);
        self.policy.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignLineage::decode(decoder)?,
            CampaignPolicy::decode(decoder)?,
        )
    }
}

/// Strict response for a newly created or genesis-compatible campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateCampaignResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshotId,
    lineage: CampaignLineageId,
    active_policy: CampaignPolicyId,
    replayed: bool,
}

impl CreateCampaignResponse {
    /// Builds a response bound to the exact creation request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the response lineage or policy differs
    /// from the request, or the canonical message exceeds its bound.
    pub fn new(
        request: &CreateCampaignRequest,
        snapshot: CampaignSnapshotId,
        replayed: bool,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot,
            lineage: request.lineage.id()?,
            active_policy: request.policy.id()?,
            replayed,
        };
        ensure_message_size(&response, "create-campaign-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the exact request digest.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the canonical genesis snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the exact lineage identity.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the initial policy identity.
    #[must_use]
    pub const fn active_policy(&self) -> CampaignPolicyId {
        self.active_policy
    }

    /// Returns whether this response replayed an existing creation.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Validates exact request and semantic-basis binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request, lineage, or policy.
    pub fn validate_for(&self, request: &CreateCampaignRequest) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.lineage != request.lineage.id()? || self.active_policy != request.policy.id()? {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign creation response semantic basis mismatch",
            });
        }
        Ok(())
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
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input. Use [`Self::validate_for`] before exposing it.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "create-campaign-response-encoded-bytes")
    }
}

impl Canonical for CreateCampaignResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.lineage.encode(encoder);
        self.active_policy.encode(encoder);
        self.replayed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            active_policy: CampaignPolicyId::decode(decoder)?,
            replayed: bool::decode(decoder)?,
        };
        ensure_message_size(&response, "create-campaign-response-encoded-bytes")?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;
    use crate::{
        CampaignMode, CampaignSeed, ConfigurationArtifact, ConfigurationId, ExactRational,
        ExplorerPolicy, FairnessPolicy, ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
        ScenarioArtifact, ScenarioDefId,
    };

    fn hash(label: &str) -> CampaignHash {
        CampaignHash::derive("campaign-create-message-test", label.as_bytes())
    }

    fn create_request(name: &str) -> CreateCampaignRequest {
        let scenario = ScenarioDefId::from_hash(hash("scenario"));
        let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario-artifact".to_vec())
            .expect("scenario artifact");
        let scenario_artifact_id = scenario_artifact.id().expect("scenario artifact id");
        let genesis = ConfigurationId::from_hash(hash("genesis"));
        let genesis_artifact = ConfigurationArtifact::new(
            scenario,
            scenario_artifact_id,
            genesis,
            1,
            b"genesis-artifact".to_vec(),
        )
        .expect("genesis artifact");
        let genesis_artifact_id = genesis_artifact.id().expect("genesis artifact id");
        let lineage = CampaignLineage::new(
            scenario,
            scenario_artifact_id,
            genesis,
            genesis_artifact_id,
            "crucible-test",
            "qemu-test",
            BTreeMap::from([("control".to_owned(), 1)]),
            1,
            1,
        )
        .expect("lineage");
        let widening = ProgressiveWideningPolicy::new(
            ExactRational::new(1, 1).expect("widening constant"),
            ExactRational::new(1, 2).expect("widening exponent"),
            1,
            100,
            1,
        )
        .expect("widening");
        let policy = CampaignPolicy::new(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("policy");
        CreateCampaignRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new(name).expect("campaign name"),
            lineage,
            policy,
        )
        .expect("create request")
    }

    #[test]
    fn creation_messages_are_canonical_and_request_bound() {
        let request = create_request("network-recovery");
        assert_eq!(
            CreateCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        let response = CreateCampaignResponse::new(
            &request,
            CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignSnapshot,
                2,
                b"genesis-snapshot",
            ))
            .expect("snapshot"),
            false,
        )
        .expect("response");
        assert_eq!(
            CreateCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );
        response.validate_for(&request).expect("request binding");
        assert!(
            response
                .validate_for(&create_request("other-campaign"))
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
                String::from("0c2444cb54ddd52b1035f7971223fceee611392d8085825076abd10a0b5f35d2"),
                String::from("2da35bec9e5dfbf8757a373ca586ba799a3a0dddb55732de9b553d404d2ae404"),
            ]
        );
    }

    #[test]
    fn creation_rejects_failures_from_other_operations() {
        for failure in [
            CampaignServiceFailure::NotFound,
            CampaignServiceFailure::Stale {
                expected: CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                    ObjectKind::CampaignSnapshot,
                    2,
                    b"expected",
                ))
                .expect("expected snapshot"),
                current: CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                    ObjectKind::CampaignSnapshot,
                    2,
                    b"current",
                ))
                .expect("current snapshot"),
            },
            CampaignServiceFailure::CommandReuse,
            CampaignServiceFailure::ConcurrentUpdate,
            CampaignServiceFailure::InvalidTransition {
                state: crate::CampaignState::Sealed,
            },
        ] {
            assert!(failure.validate_for_create_campaign().is_err());
        }
        CampaignServiceFailure::AlreadyExists
            .validate_for_create_campaign()
            .expect("create-specific failure");
    }
}
