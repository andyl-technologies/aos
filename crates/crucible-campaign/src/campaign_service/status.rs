//! Snapshot-bound semantic and operational campaign status.
//!
//! Status keeps immutable repository evidence separate from daemon-local
//! executor evidence. Semantic counts name the exact campaign snapshot.
//! Operational counts are present only when an owner binds them to one daemon
//! epoch and one durable inventory generation.

use super::*;
use crate::DaemonEpoch;

/// Maximum continuation records read for one semantic status projection.
pub const MAX_CAMPAIGN_STATUS_CONTINUATIONS: u64 = 1_000_000;

/// Maximum aggregate continuation bytes read for one status projection.
pub const MAX_CAMPAIGN_STATUS_CONTINUATION_BYTES: u64 = 128 * 1024 * 1024;

/// Strict request for status at one exact current campaign snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignStatusRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
}

impl GetCampaignStatusRequest {
    /// Builds one snapshot-bound campaign status request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded request exceeds the
    /// campaign-service bound.
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
        ensure_message_size(&request, "get-campaign-status-request-encoded-bytes")?;
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

    /// Returns the exact current snapshot that anchors the projection.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-status", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded status request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-status-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignStatusRequest {
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

/// Exact continuation-state counts at one campaign snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignContinuationStatus {
    ready: u64,
    waiting_for_feedback: u64,
    open: u64,
    exhausted: u64,
    closed: u64,
}

impl CampaignContinuationStatus {
    /// Builds exact counts for every continuation state.
    #[must_use]
    pub const fn new(
        ready: u64,
        waiting_for_feedback: u64,
        open: u64,
        exhausted: u64,
        closed: u64,
    ) -> Self {
        Self {
            ready,
            waiting_for_feedback,
            open,
            exhausted,
            closed,
        }
    }

    /// Returns continuations currently eligible to yield.
    #[must_use]
    pub const fn ready(self) -> u64 {
        self.ready
    }

    /// Returns continuations suspended on semantic feedback.
    #[must_use]
    pub const fn waiting_for_feedback(self) -> u64 {
        self.waiting_for_feedback
    }

    /// Returns open continuations not currently eligible to yield.
    #[must_use]
    pub const fn open(self) -> u64 {
        self.open
    }

    /// Returns continuations with authenticated source exhaustion.
    #[must_use]
    pub const fn exhausted(self) -> u64 {
        self.exhausted
    }

    /// Returns continuations permanently closed by budget or policy.
    #[must_use]
    pub const fn closed(self) -> u64 {
        self.closed
    }

    /// Returns all latent or open continuations.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the exact sum exceeds `u64`.
    pub fn latent_or_open(self) -> Result<u64, CampaignCodecError> {
        self.ready
            .checked_add(self.waiting_for_feedback)
            .and_then(|count| count.checked_add(self.open))
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "campaign continuation status count overflowed",
            })
    }

    fn total(self) -> Result<u64, CampaignCodecError> {
        self.latent_or_open()?
            .checked_add(self.exhausted)
            .and_then(|count| count.checked_add(self.closed))
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "campaign continuation status count overflowed",
            })
    }
}

impl Canonical for CampaignContinuationStatus {
    fn encode(&self, encoder: &mut Encoder) {
        self.ready.encode(encoder);
        self.waiting_for_feedback.encode(encoder);
        self.open.encode(encoder);
        self.exhausted.encode(encoder);
        self.closed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let status = Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        );
        status.total()?;
        Ok(status)
    }
}

/// Exact immutable counts derived from one authenticated snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignSemanticStatus {
    continuations: CampaignContinuationStatus,
    admitted_attempts: u64,
    stored_graph_nodes: u64,
    continuation_records_scanned: u64,
    continuation_bytes_scanned: u64,
}

impl CampaignSemanticStatus {
    /// Builds a bounded semantic status projection.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when scan evidence is inconsistent with
    /// the continuation counts or exceeds the registered work bounds.
    pub fn new(
        continuations: CampaignContinuationStatus,
        admitted_attempts: u64,
        stored_graph_nodes: u64,
        continuation_records_scanned: u64,
        continuation_bytes_scanned: u64,
    ) -> Result<Self, CampaignCodecError> {
        if continuation_records_scanned != continuations.total()?
            || continuation_records_scanned > MAX_CAMPAIGN_STATUS_CONTINUATIONS
            || continuation_bytes_scanned > MAX_CAMPAIGN_STATUS_CONTINUATION_BYTES
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign semantic status scan evidence is invalid",
            });
        }
        Ok(Self {
            continuations,
            admitted_attempts,
            stored_graph_nodes,
            continuation_records_scanned,
            continuation_bytes_scanned,
        })
    }

    /// Returns exact continuation-state counts.
    #[must_use]
    pub const fn continuations(self) -> CampaignContinuationStatus {
        self.continuations
    }

    /// Returns the number of durably admitted semantic attempts.
    #[must_use]
    pub const fn admitted_attempts(self) -> u64 {
        self.admitted_attempts
    }

    /// Returns the number of stored configuration nodes in the campaign graph.
    #[must_use]
    pub const fn stored_graph_nodes(self) -> u64 {
        self.stored_graph_nodes
    }

    /// Returns the continuation records authenticated by the projection.
    #[must_use]
    pub const fn continuation_records_scanned(self) -> u64 {
        self.continuation_records_scanned
    }

    /// Returns aggregate canonical continuation bytes authenticated by the projection.
    #[must_use]
    pub const fn continuation_bytes_scanned(self) -> u64 {
        self.continuation_bytes_scanned
    }
}

impl Canonical for CampaignSemanticStatus {
    fn encode(&self, encoder: &mut Encoder) {
        self.continuations.encode(encoder);
        self.admitted_attempts.encode(encoder);
        self.stored_graph_nodes.encode(encoder);
        self.continuation_records_scanned.encode(encoder);
        self.continuation_bytes_scanned.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignContinuationStatus::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Daemon-local world phases proven by one operational inventory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignWorldStatus {
    preparing: u64,
    running: u64,
    checkpointing: u64,
    publishing: u64,
    canceling: u64,
    paused: u64,
}

impl CampaignWorldStatus {
    /// Builds exact world-phase counts.
    #[must_use]
    pub const fn new(
        preparing: u64,
        running: u64,
        checkpointing: u64,
        publishing: u64,
        canceling: u64,
        paused: u64,
    ) -> Self {
        Self {
            preparing,
            running,
            checkpointing,
            publishing,
            canceling,
            paused,
        }
    }

    /// Returns worlds reserved but not yet running.
    #[must_use]
    pub const fn preparing(self) -> u64 {
        self.preparing
    }

    /// Returns worlds actively executing guest work.
    #[must_use]
    pub const fn running(self) -> u64 {
        self.running
    }

    /// Returns worlds capturing or promoting exact checkpoints.
    #[must_use]
    pub const fn checkpointing(self) -> u64 {
        self.checkpointing
    }

    /// Returns worlds publishing completed observations.
    #[must_use]
    pub const fn publishing(self) -> u64 {
        self.publishing
    }

    /// Returns worlds awaiting terminal cancellation reconciliation.
    #[must_use]
    pub const fn canceling(self) -> u64 {
        self.canceling
    }

    /// Returns durable paused worlds with an exact checkpoint.
    #[must_use]
    pub const fn paused(self) -> u64 {
        self.paused
    }
}

impl Canonical for CampaignWorldStatus {
    fn encode(&self, encoder: &mut Encoder) {
        self.preparing.encode(encoder);
        self.running.encode(encoder);
        self.checkpointing.encode(encoder);
        self.publishing.encode(encoder);
        self.canceling.encode(encoder);
        self.paused.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        ))
    }
}

/// Generation-bound operational evidence from one daemon owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignOperationalEvidence {
    daemon_epoch: DaemonEpoch,
    inventory_generation: CampaignHash,
    worlds: CampaignWorldStatus,
    retained_checkpoint_roots: u64,
    materialized_checkpoints: u64,
}

impl CampaignOperationalEvidence {
    /// Builds exact operational evidence for one owner inventory.
    #[must_use]
    pub const fn new(
        daemon_epoch: DaemonEpoch,
        inventory_generation: CampaignHash,
        worlds: CampaignWorldStatus,
        retained_checkpoint_roots: u64,
        materialized_checkpoints: u64,
    ) -> Self {
        Self {
            daemon_epoch,
            inventory_generation,
            worlds,
            retained_checkpoint_roots,
            materialized_checkpoints,
        }
    }

    /// Returns the daemon incarnation that owns these counts.
    #[must_use]
    pub const fn daemon_epoch(self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the durable operational inventory generation.
    #[must_use]
    pub const fn inventory_generation(self) -> CampaignHash {
        self.inventory_generation
    }

    /// Returns exact world-phase counts.
    #[must_use]
    pub const fn worlds(self) -> CampaignWorldStatus {
        self.worlds
    }

    /// Returns distinct exact-checkpoint roots retained for this campaign.
    #[must_use]
    pub const fn retained_checkpoint_roots(self) -> u64 {
        self.retained_checkpoint_roots
    }

    /// Returns distinct complete checkpoints materialized for this campaign.
    #[must_use]
    pub const fn materialized_checkpoints(self) -> u64 {
        self.materialized_checkpoints
    }
}

impl Canonical for CampaignOperationalEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.daemon_epoch.encode(encoder);
        self.inventory_generation.encode(encoder);
        self.worlds.encode(encoder);
        self.retained_checkpoint_roots.encode(encoder);
        self.materialized_checkpoints.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            DaemonEpoch::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            CampaignWorldStatus::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        ))
    }
}

/// Availability of daemon-local evidence for the named campaign.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CampaignOperationalStatus {
    /// No owner supplied epoch- and generation-bound operational evidence.
    #[default]
    Unavailable,
    /// One owner supplied complete exact operational evidence.
    Observed(CampaignOperationalEvidence),
}

impl Canonical for CampaignOperationalStatus {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Unavailable => encoder.u8(0),
            Self::Observed(evidence) => {
                encoder.u8(1);
                evidence.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Unavailable),
            1 => Ok(Self::Observed(CampaignOperationalEvidence::decode(
                decoder,
            )?)),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-operational-status",
                tag,
            }),
        }
    }
}

/// Complete CAPI-6 status at one exact campaign snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignStatusSummary {
    semantic: CampaignSemanticStatus,
    operational: CampaignOperationalStatus,
}

impl CampaignStatusSummary {
    /// Builds a status summary from separate semantic and operational owners.
    #[must_use]
    pub const fn new(
        semantic: CampaignSemanticStatus,
        operational: CampaignOperationalStatus,
    ) -> Self {
        Self {
            semantic,
            operational,
        }
    }

    /// Returns snapshot-derived semantic counts.
    #[must_use]
    pub const fn semantic(self) -> CampaignSemanticStatus {
        self.semantic
    }

    /// Returns generation-bound operational evidence when available.
    #[must_use]
    pub const fn operational(self) -> CampaignOperationalStatus {
        self.operational
    }
}

impl Canonical for CampaignStatusSummary {
    fn encode(&self, encoder: &mut Encoder) {
        self.semantic.encode(encoder);
        self.operational.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            CampaignSemanticStatus::decode(decoder)?,
            CampaignOperationalStatus::decode(decoder)?,
        ))
    }
}

/// Supplies complete daemon-local evidence for one exact campaign snapshot.
///
/// Implementations return [`CampaignOperationalStatus::Unavailable`] unless
/// they can bind every reported count to one daemon epoch and stable inventory
/// generation.
pub trait CampaignOperationalStatusProvider: Send + Sync {
    /// Returns daemon-local evidence for one exact current campaign snapshot.
    fn operational_status(
        &self,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
    ) -> CampaignOperationalStatus;
}

/// Request-bound semantic and operational status at one campaign snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetCampaignStatusResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshotId,
    status: CampaignStatusSummary,
}

impl GetCampaignStatusResponse {
    /// Builds status bound to every field of one exact request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded response exceeds the
    /// campaign-service bound.
    pub fn new(
        request: &GetCampaignStatusRequest,
        status: CampaignStatusSummary,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot: request.snapshot(),
            status,
        };
        ensure_message_size(&response, "get-campaign-status-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the exact campaign snapshot that anchors all semantic counts.
    #[must_use]
    pub const fn snapshot(self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the complete status projection.
    #[must_use]
    pub const fn status(self) -> CampaignStatusSummary {
        self.status
    }

    /// Validates exact request and snapshot binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or snapshot.
    pub fn validate_for(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.snapshot != request.snapshot() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign status response snapshot mismatch",
            });
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded status response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Exact request validation remains
    /// required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-status-response-encoded-bytes")
    }
}

impl Canonical for GetCampaignStatusResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.status.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            status: CampaignStatusSummary::decode(decoder)?,
        };
        ensure_message_size(&response, "get-campaign-status-response-encoded-bytes")?;
        Ok(response)
    }
}
