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
    conditional: Option<ConditionalReplayScope>,
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
            conditional: None,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_OBSERVED_RECORD_BYTES - 1024,
            "observed request bytes",
        )?;
        Ok(request)
    }

    /// Builds an explicitly selected unchanged-context conditional replay request.
    ///
    /// Version two retains the complete original source scope as child-bearing
    /// evidence. Construction authenticates no source and grants no deterministic
    /// work; the installed admission must verify the complete sealed recipe.
    ///
    /// # Errors
    /// Refuses a capability set other than conditional transcript replay alone
    /// or an oversized request. Fresh physical execution is never substituted.
    pub fn conditional_replay(
        execution: ExecutionId,
        capabilities: ExecutorNodeCapabilities,
        inputs: ContentId,
        scope: ConditionalReplayScope,
    ) -> Result<Self, CampaignCodecError> {
        if capabilities.materialization()
            != &std::collections::BTreeSet::from([
                NodeMaterializationStrategy::ConditionalTranscriptReplay,
            ])
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "conditional replay requires its distinct admitted materialization",
            });
        }
        let request = Self {
            execution,
            capabilities,
            inputs,
            conditional: Some(scope),
        };
        codec::ensure_encoded_size(
            &request,
            MAX_OBSERVED_RECORD_BYTES - 1024,
            "conditional replay request bytes",
        )?;
        Ok(request)
    }

    /// Returns the original-source scope only for explicit conditional replay.
    #[must_use]
    pub const fn conditional_scope(&self) -> Option<&ConditionalReplayScope> {
        self.conditional.as_ref()
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
        if let Some(scope) = &self.conditional {
            scope.encode(&mut encoder);
            CampaignHash::derive("crucible.conditional-node-plan.v2", &encoder.finish())
        } else {
            CampaignHash::derive("crucible.observed-node-plan.v1", &encoder.finish())
        }
    }

    /// Returns the complete request identity, including the execution nonce.
    #[must_use]
    pub fn digest(&self) -> CampaignHash {
        CampaignHash::derive("crucible.observed-node-request.v1", &self.canonical_bytes())
    }

    /// Returns strict canonical request bytes in its selected edition.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes bounded canonical fresh or conditional request bytes.
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
        let Some(scope) = &self.conditional else {
            return envelope(
                "crucible.observed-node-request",
                [
                    ("scenario", roster.scenario().content_id()),
                    ("configuration", roster.configuration().content_id()),
                    ("inputs", self.inputs),
                ],
                self.canonical_bytes(),
            );
        };
        let mut children = vec![
            ContentChild::new("scenario", roster.scenario().content_id())?,
            ContentChild::new("configuration", roster.configuration().content_id())?,
            ContentChild::new("inputs", self.inputs)?,
        ];
        children
            .try_reserve_exact(scope.sources().len())
            .map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "conditional replay source child allocation",
            })?;
        for (index, source) in scope.sources().values().enumerate() {
            children.push(ContentChild::new(
                format!("recorded-source-{index:04}"),
                *source,
            )?);
        }
        Ok(ContentEnvelope::new(
            "crucible.observed-node-request",
            2,
            children.into_iter().collect(),
            self.canonical_bytes(),
        )?)
    }

    pub(crate) fn content_id(&self) -> Result<ContentId, CampaignCodecError> {
        Ok(self.envelope()?.content_id(ObjectKind::CampaignFact))
    }
}

impl Canonical for ObservedAttemptRequest {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(if self.conditional.is_some() {
            2
        } else {
            VERSION
        });
        self.execution.encode(encoder);
        self.capabilities.encode(encoder);
        Canonical::encode(&self.inputs, encoder);
        if let Some(scope) = &self.conditional {
            scope.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let edition = decoder.u32()?;
        if !matches!(edition, 1 | 2) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported observed request edition",
            });
        }
        let execution = ExecutionId::decode(decoder)?;
        let capabilities = ExecutorNodeCapabilities::decode(decoder)?;
        let inputs = ContentId::decode(decoder)?;
        if edition == 1 {
            Self::new(execution, capabilities, inputs)
        } else {
            Self::conditional_replay(
                execution,
                capabilities,
                inputs,
                ConditionalReplayScope::decode(decoder)?,
            )
        }
    }
}
