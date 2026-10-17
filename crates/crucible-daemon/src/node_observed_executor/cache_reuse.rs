//! Explicit deterministic reuse of an authenticated original node observation.
//!
//! Reuse reads the original result and preserves its execution nonce. It neither
//! dispatches a new world nor converts an observed result into a snapshot. The
//! complete implementation roster and input context form the cache key; ordinary
//! nondeterministic and conditional-transcript observations remain ineligible.
//!
//! ```json
//! {"format":"crucible.node-cache-reuse","version":1,
//!  "source_execution":"00112233445566778899aabbccddeeff",
//!  "expected_cache_key":"<64 lowercase hexadecimal digits>",
//!  "selections":[],"scenario":"<base64url>","configuration":"<base64url>"}
//! ```

use super::{InstalledNodeCatalog, InstalledNodeSelection, NodeObservationServiceError};
use crate::node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeRunConfiguration, NodeScenario};
use crucible_campaign::{
    CampaignHash, CampaignRepository, ExecutionId,
    executor_node_capabilities::{
        ConditionalTranscriptEvidence, DeterministicExecutionContext,
        DeterministicExecutionOperation, ExecutorNodeRoster, TranscriptQualificationVerifier,
    },
    observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptResult, ObservedAttemptState},
};
use crucible_node_contract::{Bytes, canonical};
use serde::{Deserialize, Serialize};

/// Selects an original deterministic result under exact installed world policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCacheReuseRequest {
    /// Names the independent, closed cache-reuse request format.
    pub format: String,
    /// Selects edition one without changing original observation codecs.
    pub version: u16,
    /// Identifies the original execution; no new execution nonce is allocated.
    pub source_execution: String,
    /// Optionally pins the complete original backend/model/configuration/input key.
    ///
    /// Absence requests exact original selection by nonce; installation and full
    /// request authentication still precede reuse, and the receipt returns its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_cache_key: Option<String>,
    /// Selects only independently installed implementations and immutable inputs.
    pub selections: Vec<InstalledNodeSelection>,
    /// Retains the exact scenario compiled by the owning installed controller.
    pub scenario: Bytes,
    /// Retains the original complete run configuration.
    pub configuration: Bytes,
}

/// Returns original observed bytes together with their verified reuse scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCacheReuseReceipt {
    /// Names the cache receipt format without claiming a fresh execution.
    pub format: String,
    /// Selects the first independent receipt edition.
    pub version: u16,
    /// Identifies the complete authenticated original reuse scope.
    pub cache_key: String,
    /// Retains the original independently named execution.
    pub source_execution: String,
    /// Identifies the authenticated observed-result closure.
    pub original_result: String,
    /// Contains unchanged canonical original result bytes, including its nonce.
    pub result: Bytes,
}

impl NodeCacheReuseRequest {
    /// Parses bounded closed canonical JSON without authenticating native evidence.
    ///
    /// # Errors
    /// Refuses duplicate or unknown fields, unsupported editions, invalid
    /// identities, oversized input, or malformed scenario/configuration records.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let value = canonical::parse_json(bytes, MAX_NODE_SCENARIO_BYTES).map_err(refused)?;
        let request: Self = serde_json::from_value(value).map_err(refused)?;
        request.validate()?;
        Ok(request)
    }

    /// Checks portable shape and allocation bounds without authorizing reuse.
    ///
    /// # Errors
    /// Refuses unsupported editions, malformed identities, excessive bytes,
    /// invalid scenario/configuration records, or an empty/oversized selection.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        if self.format != "crucible.node-cache-reuse"
            || self.version != 1
            || self.selections.is_empty()
            || self.selections.len() > 64
            || self.scenario.as_slice().len() > MAX_NODE_SCENARIO_BYTES
            || self.configuration.as_slice().len() > 4096
        {
            return Err(refused("unsupported or oversized cache reuse request"));
        }
        self.execution()?;
        if let Some(expected) = &self.expected_cache_key {
            let key = CampaignHash::parse(expected).map_err(refused)?;
            if key.to_hex() != *expected {
                return Err(refused("cache identity is not canonical"));
            }
        }
        let scenario = NodeScenario::from_json(self.scenario.as_slice()).map_err(refused)?;
        NodeRunConfiguration::from_json(self.configuration.as_slice())
            .map_err(refused)?
            .artifact(&scenario)
            .map_err(refused)?;
        Ok(())
    }

    fn execution(&self) -> Result<ExecutionId, NodeObservationServiceError> {
        if self.source_execution.len() != 32
            || self
                .source_execution
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(refused("original execution identity is not canonical"));
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.source_execution[index * 2..index * 2 + 2], 16)
                .map_err(refused)?;
        }
        ExecutionId::from_bytes(bytes).map_err(refused)
    }
}

/// Derives a complete deterministic reuse key without authenticating its source.
///
/// The key includes every coupled owner, implementation/model binding, scenario,
/// configuration, guarantee and actual input-context identity. Equal keys alone
/// never admit reuse: the owning service checks installation and result closure.
#[must_use]
pub fn node_cache_key(result: &ObservedAttemptResult) -> CampaignHash {
    let mut bytes = result.request().capabilities().canonical_bytes();
    bytes.extend_from_slice(result.request().inputs().encode().as_bytes());
    CampaignHash::derive("crucible.node-result-cache.v1", &bytes)
}

pub(super) fn reuse(
    catalog: &InstalledNodeCatalog,
    repository: &CampaignRepository,
    request: &NodeCacheReuseRequest,
) -> Result<NodeCacheReuseReceipt, NodeObservationServiceError> {
    request.validate()?;
    let _guard = repository.acquire_gc_exclusion_guard().map_err(refused)?;
    let state = repository
        .observed_execution_state(request.execution()?)
        .map_err(refused)?
        .ok_or_else(|| refused("original cache execution is unavailable"))?;
    let ObservedAttemptState::Completed(original) = state else {
        return Err(refused("original execution has no completed cache result"));
    };
    if original.outcome() != ObservedAttemptOutcome::Completed {
        return Err(refused("cache reuse requires a successful original result"));
    }
    // The repository authenticates all original request, trace and evidence
    // children before installing the result as reusable evidence.
    let original = repository
        .load_observed_result(original.id().map_err(refused)?)
        .map_err(refused)?;
    let key = node_cache_key(&original);
    if request
        .expected_cache_key
        .as_ref()
        .is_some_and(|expected| *expected != key.to_hex())
    {
        return Err(refused(
            "selected cache key differs from original complete world",
        ));
    }
    let context = DeterministicExecutionContext {
        request: CampaignHash::derive(
            "crucible.node-cache-request.v1",
            &canonical::canonical_json(&serde_json::to_value(request).map_err(refused)?)
                .map_err(refused)?,
        ),
        inputs: CampaignHash::derive(
            "crucible.node-cache-inputs.v1",
            original.request().inputs().encode().as_bytes(),
        ),
    };
    original
        .request()
        .capabilities()
        .roster()
        .admit_deterministic_operation(
            DeterministicExecutionOperation::CacheReuse,
            &context,
            &NoConditionalCache,
        )
        .map_err(refused)?;

    let scenario = NodeScenario::from_json(request.scenario.as_slice()).map_err(refused)?;
    let configuration =
        NodeRunConfiguration::from_json(request.configuration.as_slice()).map_err(refused)?;
    catalog
        .authenticate_cache_selection(&request.selections, &scenario)
        .map_err(refused)?;
    catalog
        .authenticate_recorded(&scenario, &configuration, original.request())
        .map_err(refused)?;
    Ok(NodeCacheReuseReceipt {
        format: "crucible.node-cache-receipt".into(),
        version: 1,
        cache_key: key.to_hex(),
        source_execution: request.source_execution.clone(),
        original_result: original.id().map_err(refused)?.content_id().encode(),
        result: Bytes::new(original.canonical_bytes()),
    })
}

struct NoConditionalCache;

impl TranscriptQualificationVerifier for NoConditionalCache {
    fn verify(
        &self,
        _: &ExecutorNodeRoster,
        _: &str,
        _: ConditionalTranscriptEvidence,
        _: DeterministicExecutionOperation,
        _: &DeterministicExecutionContext,
    ) -> Result<(), crucible_campaign::CampaignCodecError> {
        Err(crucible_campaign::CampaignCodecError::InvalidValue {
            reason: "conditional boundary replay does not qualify deterministic cache reuse",
        })
    }
}

fn refused(error: impl std::fmt::Display) -> NodeObservationServiceError {
    NodeObservationServiceError::Refused(error.to_string().chars().take(4096).collect())
}
