//! Proof-bearing access to accepted planner requests and their PUCT rankings.
//!
//! Each response carries one accepted planner step, its complete retained
//! request, and the minimal coordination-root lookup proof. Callers traverse a
//! multi-page planner invocation by requesting the returned parent step. This
//! keeps every component message bounded while preserving exact owner
//! authentication for each page.

use super::*;
use crate::{PlannerCandidateRanking, PlannerRequest, PlannerStep, PlannerStepId};

/// Strict request for one accepted planner-step ranking page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignPlannerRankingsRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    step: PlannerStepId,
}

impl GetCampaignPlannerRankingsRequest {
    /// Builds one snapshot-bound planner-ranking request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded request exceeds the
    /// campaign-service message bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        step: PlannerStepId,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            step,
        };
        ensure_message_size(
            &request,
            "get-campaign-planner-rankings-request-encoded-bytes",
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

    /// Returns the exact current snapshot that anchors the membership proof.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the accepted planner step to explain.
    #[must_use]
    pub const fn step(&self) -> PlannerStepId {
        self.step
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-planner-rankings", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded planner-ranking request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-planner-rankings-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignPlannerRankingsRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.step.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            PlannerStepId::decode(decoder)?,
        )
    }
}

/// One owner-authenticated planner step and its complete retained request.
///
/// Authorization for this response grants visibility of every root ID and
/// transition in the snapshot body, plus the complete retained planner request
/// and its bounded interpretation bundle. Object bodies outside that retained
/// request remain separately authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignPlannerRankingsResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    step: PlannerStep,
    planner_request: PlannerRequest,
    proof: MerkleMapLookupProof,
}

impl GetCampaignPlannerRankingsResponse {
    /// Builds one proof-bearing planner-ranking page.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, step, retained
    /// request, proof, ranking basis, or encoded-size contract is invalid.
    pub fn new(
        request: &GetCampaignPlannerRankingsRequest,
        snapshot_body: CampaignSnapshot,
        step: PlannerStep,
        planner_request: PlannerRequest,
        proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            step,
            planner_request,
            proof,
        };
        response.validate_body_for(request)?;
        ensure_message_size(
            &response,
            "get-campaign-planner-rankings-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body, including all snapshot roots.
    #[must_use]
    pub const fn snapshot_body(&self) -> &CampaignSnapshot {
        &self.snapshot_body
    }

    /// Returns the accepted planner step.
    #[must_use]
    pub const fn step(&self) -> &PlannerStep {
        &self.step
    }

    /// Returns the complete retained planner request.
    #[must_use]
    pub const fn planner_request(&self) -> &PlannerRequest {
        &self.planner_request
    }

    /// Returns the preceding accepted planner step, if another page exists.
    #[must_use]
    pub const fn parent(&self) -> Option<PlannerStepId> {
        self.step.parent()
    }

    /// Recomputes this page's PUCT rankings in deterministic best-first order.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the retained request does not carry
    /// valid canonical PUCT guidance.
    pub fn ranked_candidates(&self) -> Result<Vec<PlannerCandidateRanking>, CampaignCodecError> {
        self.planner_request.ranked_candidates()
    }

    /// Validates exact request, snapshot, step, retained request, and proof binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or any authenticated response component disagrees.
    pub fn validate_for(
        &self,
        request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded planner-ranking response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(
            bytes,
            "get-campaign-planner-rankings-response-encoded-bytes",
        )
    }

    fn validate_body_for(
        &self,
        request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot_body.id()? != request.snapshot()
            || self.step.id()? != request.step()
            || self.planner_request.id()? != self.step.request()
            || self.planner_request.request_digest() != self.step.request_digest()
            || self.planner_request.invocation_id()? != self.step.invocation()
            || self.planner_request.policy().id()? != self.step.policy()
            || self.planner_request.engine().id()? != self.step.engine()
            || self.planner_request.policy_artifact().id()? != self.step.policy_artifact()
            || self.planner_request.input_view().id()? != self.step.input_view()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign planner-ranking response basis mismatch",
            });
        }
        let indexed = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().coordination,
            crate::repository::planner_step_key(request.step()),
            &self.proof,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "campaign planner-ranking response Merkle proof is invalid",
        })?;
        if indexed != Some(request.step().content_id()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign planner-ranking step differs from its Merkle proof",
            });
        }
        self.planner_request.ranked_candidates()?;
        Ok(())
    }
}

impl Canonical for GetCampaignPlannerRankingsResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.step.encode(encoder);
        self.planner_request.encode(encoder);
        self.proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            step: PlannerStep::decode(decoder)?,
            planner_request: PlannerRequest::decode(decoder)?,
            proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(
            &response,
            "get-campaign-planner-rankings-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use crucible_cas::content_store::ContentId;

    use super::*;

    #[test]
    fn planner_ranking_request_round_trips_with_a_frozen_digest() {
        let step = PlannerStepId::from_content_id(ContentId::for_bytes(
            crate::CampaignRecordKind::PlannerStep.object_kind(),
            crate::CampaignRecordKind::PlannerStep.schema_version(),
            b"planner ranking request step",
        ))
        .expect("planner step ID");
        let request = GetCampaignPlannerRankingsRequest::new(
            CampaignPrincipal::new("operator").expect("principal"),
            CampaignName::new("campaign/ranking").expect("campaign"),
            CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                crate::CampaignRecordKind::Snapshot.object_kind(),
                crate::CampaignRecordKind::Snapshot.schema_version(),
                b"planner ranking request snapshot",
            ))
            .expect("snapshot ID"),
            step,
        )
        .expect("ranking request");
        assert_eq!(
            GetCampaignPlannerRankingsRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode ranking request"),
            request
        );
        assert_eq!(
            request.request_digest().to_hex(),
            "85f79b6646c3631711943e55b8c32f39a997101e26c222a91f2e32b9e54bd194"
        );
    }
}
