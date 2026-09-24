//! Bounded reads of trace leaves owned by authenticated attempt observations.

use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;
use crate::{AttemptId, MeasurementSet, Observation};

/// Maximum trace bytes returned by one campaign service response.
pub const MAX_CAMPAIGN_TRACE_CHUNK_BYTES: u32 = 1024 * 1024;

/// Maximum logical bytes admitted for one observation-linked trace.
pub const MAX_CAMPAIGN_TRACE_BYTES: u64 = 64 * 1024 * 1024;

/// Trace leaf selected from one authenticated attempt observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignTraceKind {
    /// The canonical trace of resolved environment and guest effects.
    ResolvedEffect,
    /// The canonical measurement event log retained by the measurement set.
    MeasurementEventLog,
}

impl Canonical for CampaignTraceKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::ResolvedEffect => 0,
            Self::MeasurementEventLog => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ResolvedEffect),
            1 => Ok(Self::MeasurementEventLog),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-trace-kind",
                tag,
            }),
        }
    }
}

/// Snapshot- and attempt-bound request for one bounded trace byte range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignTraceChunkRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    attempt: AttemptId,
    kind: CampaignTraceKind,
    offset: u64,
    limit: u32,
}

impl GetCampaignTraceChunkRequest {
    /// Builds one exact trace-range request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the range exceeds the trace or
    /// response bounds, or the request exceeds the service message bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        attempt: AttemptId,
        kind: CampaignTraceKind,
        offset: u64,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > MAX_CAMPAIGN_TRACE_CHUNK_BYTES || offset > MAX_CAMPAIGN_TRACE_BYTES
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign trace chunk range is invalid",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            attempt,
            kind,
            offset,
            limit,
        };
        ensure_message_size(&request, "get-campaign-trace-chunk-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the named campaign.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact current snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the admitted attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the selected observation-linked trace kind.
    #[must_use]
    pub const fn kind(&self) -> CampaignTraceKind {
        self.kind
    }

    /// Returns the requested zero-based byte offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the maximum bytes requested.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign-trace-chunk", self)
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid, unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-trace-chunk-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignTraceChunkRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.attempt.encode(encoder);
        self.kind.encode(encoder);
        self.offset.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            AttemptId::decode(decoder)?,
            CampaignTraceKind::decode(decoder)?,
            u64::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// One trace range with proof of the owning observation and attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignTraceChunkResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot_body: CampaignSnapshot,
    observation: Observation,
    measurement_set: Option<MeasurementSet>,
    trace: ContentId,
    total_bytes: u64,
    offset: u64,
    chunk: Vec<u8>,
    attempt_proof: MerkleMapLookupProof,
    observation_proof: MerkleMapLookupProof,
}

impl GetCampaignTraceChunkResponse {
    /// Builds a proof-bearing trace-range response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when ownership, range, or encoding is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &GetCampaignTraceChunkRequest,
        snapshot_body: CampaignSnapshot,
        observation: Observation,
        measurement_set: Option<MeasurementSet>,
        trace: ContentId,
        total_bytes: u64,
        chunk: Vec<u8>,
        attempt_proof: MerkleMapLookupProof,
        observation_proof: MerkleMapLookupProof,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot_body,
            observation,
            measurement_set,
            trace,
            total_bytes,
            offset: request.offset(),
            chunk,
            attempt_proof,
            observation_proof,
        };
        response.validate_for(request)?;
        ensure_message_size(&response, "get-campaign-trace-chunk-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the exact authenticated trace leaf identity.
    #[must_use]
    pub const fn trace(&self) -> ContentId {
        self.trace
    }

    /// Returns the complete logical trace length.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns the zero-based offset of this chunk.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the bounded trace bytes.
    #[must_use]
    pub fn chunk(&self) -> &[u8] {
        &self.chunk
    }

    /// Returns the authenticated observation owning the trace.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Validates request binding, attempt and observation proofs, trace
    /// ownership, and exact range shape.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a mismatched or unauthenticated response.
    pub fn validate_for(
        &self,
        request: &GetCampaignTraceChunkRequest,
    ) -> Result<(), CampaignCodecError> {
        let invalid = || CampaignCodecError::InvalidValue {
            reason: "campaign trace chunk response basis is invalid",
        };
        if self.request_digest != request.request_digest()
            || self.snapshot_body.id()? != request.snapshot()
            || self.observation.attempt() != request.attempt()
            || self.trace.kind() != ObjectKind::Trace
            || self.total_bytes > MAX_CAMPAIGN_TRACE_BYTES
            || self.offset != request.offset()
            || self.offset > self.total_bytes
            || self.chunk.len() as u64
                != u64::from(request.limit()).min(self.total_bytes - self.offset)
        {
            return Err(invalid());
        }
        let attempt = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().accounting,
            crate::repository::attempt_index_key(request.attempt()),
            &self.attempt_proof,
        )
        .map_err(|_| invalid())?;
        let observation = MerkleMap::verify_lookup_proof(
            self.snapshot_body.roots().observations,
            crate::repository::attempt_observation_key(request.attempt()),
            &self.observation_proof,
        )
        .map_err(|_| invalid())?;
        if attempt != Some(request.attempt().content_id())
            || observation != Some(self.observation.id()?.content_id())
        {
            return Err(invalid());
        }
        match request.kind() {
            CampaignTraceKind::ResolvedEffect => {
                if self.measurement_set.is_some()
                    || self.trace.schema_version() != 1
                    || self.observation.resolved_effect_trace() != Some(self.trace)
                {
                    return Err(invalid());
                }
            }
            CampaignTraceKind::MeasurementEventLog => {
                let measurement_set = self.measurement_set.as_ref().ok_or_else(invalid)?;
                if measurement_set.id()? != self.observation.measurements()
                    || self.trace.schema_version() != 2
                    || measurement_set.evaluation().evidence().len() != 1
                    || !measurement_set
                        .evaluation()
                        .evidence()
                        .contains(&self.trace)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded response; callers validate it against a request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid, unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-trace-chunk-response-encoded-bytes")
    }
}

impl Canonical for GetCampaignTraceChunkResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot_body.encode(encoder);
        self.observation.encode(encoder);
        self.measurement_set.encode(encoder);
        Canonical::encode(&self.trace, encoder);
        self.total_bytes.encode(encoder);
        self.offset.encode(encoder);
        encoder.bytes(&self.chunk);
        self.attempt_proof.encode(encoder);
        self.observation_proof.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let mut charged = 0;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot_body: CampaignSnapshot::decode(decoder)?,
            observation: Observation::decode(decoder)?,
            measurement_set: Option::decode(decoder)?,
            trace: ContentId::decode(decoder)?,
            total_bytes: u64::decode(decoder)?,
            offset: u64::decode(decoder)?,
            chunk: decoder.byte_sequence_bounded_charged(
                MAX_CAMPAIGN_TRACE_CHUNK_BYTES as usize,
                "campaign-trace-chunk-bytes",
                &mut charged,
                MAX_CAMPAIGN_TRACE_CHUNK_BYTES as usize,
                "campaign-trace-chunk-bytes",
            )?,
            attempt_proof: MerkleMapLookupProof::decode(decoder)?,
            observation_proof: MerkleMapLookupProof::decode(decoder)?,
        };
        ensure_message_size(&response, "get-campaign-trace-chunk-response-encoded-bytes")?;
        Ok(response)
    }
}
