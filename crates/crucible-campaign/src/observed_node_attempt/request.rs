//! Planned execution identity and authenticated realization admission.

use super::*;
use crate::executor_node_capabilities::NodeMaterializationStrategy;
use crate::{ConfigurationArtifact, ScenarioArtifact};

/// Authenticates a request against the host-sealed graph and stored inputs.
///
/// The implementation verifies semantic scenario/configuration payloads, the
/// complete owner closure, provider compatibility and operating modes, and the
/// input closure's faults, clock policy, ordering and external context. A roster
/// whose labels match caller-provided names is insufficient. Every reservation,
/// including an idempotent retry, performs this check before returning state.
/// Verification runs inside repository publication/mutation exclusion. It must
/// be local authentication of previously sealed inputs: it cannot start native
/// execution, perform repository mutations or acquire a later subsystem fence.
pub trait ObservedAttemptAdmission {
    /// Verifies the realized graph's correspondence to authenticated artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error if the graph, payloads, input closure, implementation
    /// identities, qualification or requested operating mode cannot be verified.
    fn authenticate(
        &self,
        request: &ObservedAttemptRequest,
        scenario: &ScenarioArtifact,
        configuration: &ConfigurationArtifact,
    ) -> Result<(), CampaignCodecError>;
}

/// Binds one fresh execution nonce to an admitted planned world and input closure.
///
/// Version one starts fresh executions only. Exact restore and transcript replay
/// require separate source-closure qualification and are not implicitly enabled
/// by a materialization capability advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAttemptRequest {
    execution: ExecutionId,
    capabilities: ExecutorNodeCapabilities,
    inputs: ContentId,
}

impl ObservedAttemptRequest {
    /// Builds an independent fresh-execution request.
    ///
    /// # Errors
    ///
    /// Returns an error if the realization does not advertise fresh execution.
    pub fn new(
        execution: ExecutionId,
        capabilities: ExecutorNodeCapabilities,
        inputs: ContentId,
    ) -> Result<Self, CampaignCodecError> {
        if !capabilities
            .materialization()
            .contains(&NodeMaterializationStrategy::FreshExecution)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed request requires admitted fresh execution",
            });
        }
        let request = Self {
            execution,
            capabilities,
            inputs,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_OBSERVED_RECORD_BYTES - 1024,
            "observed request bytes",
        )?;
        Ok(request)
    }

    /// Returns the independent execution nonce.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the complete realized-owner capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &ExecutorNodeCapabilities {
        &self.capabilities
    }

    /// Returns the authenticated complete planned input closure.
    #[must_use]
    pub const fn inputs(&self) -> ContentId {
        self.inputs
    }

    /// Returns the planned identity without the independent execution nonce.
    #[must_use]
    pub fn plan_digest(&self) -> CampaignHash {
        let mut encoder = Encoder::new();
        self.capabilities.digest().encode(&mut encoder);
        Canonical::encode(&self.inputs, &mut encoder);
        CampaignHash::derive("crucible.observed-node-plan.v1", &encoder.finish())
    }

    /// Returns the complete request identity, including the execution nonce.
    #[must_use]
    pub fn digest(&self) -> CampaignHash {
        CampaignHash::derive("crucible.observed-node-request.v1", &self.canonical_bytes())
    }

    /// Returns strict version-one canonical request bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes bounded canonical version-one request bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, invalid capabilities,
    /// malformed, oversized, noncanonical or trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(bytes, MAX_OBSERVED_RECORD_BYTES, "observed request bytes")
    }

    pub(crate) fn envelope(&self) -> Result<ContentEnvelope, CampaignCodecError> {
        let roster = self.capabilities.roster();
        envelope(
            "crucible.observed-node-request",
            [
                ("scenario", roster.scenario().content_id()),
                ("configuration", roster.configuration().content_id()),
                ("inputs", self.inputs),
            ],
            self.canonical_bytes(),
        )
    }

    pub(crate) fn content_id(&self) -> Result<ContentId, CampaignCodecError> {
        Ok(self.envelope()?.content_id(ObjectKind::CampaignFact))
    }
}

impl Canonical for ObservedAttemptRequest {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(VERSION);
        self.execution.encode(encoder);
        self.capabilities.encode(encoder);
        Canonical::encode(&self.inputs, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(decoder)?;
        Self::new(
            ExecutionId::decode(decoder)?,
            ExecutorNodeCapabilities::decode(decoder)?,
            ContentId::decode(decoder)?,
        )
    }
}
